# Jelly2FA

> **Unofficial, personal project (version 0.0.2.0).** Not affiliated with Jellyfin. Not audited. Use at your own risk and keep a recovery path (see below).

Jelly2FA is a Jellyfin **12.x** plugin that adds a second factor to sign-ins that come in through your reverse proxy (nginx + DDNS), **without changing any client app**.

| Where the sign-in comes from | What the user types into the normal password field |
|---|---|
| Through nginx / DDNS (internet) | password, then **password + 8-digit code** from the email (no space) |
| Direct LAN connection (Jellyfin "LAN networks") | password only |
| Direct Tailscale connection (100.64.0.0/10, fd7a:115c:a1e0::/48)¹ | password only |
| Anything unclear (unknown proxy, forwarding headers, missing data) | 2FA (fail closed) |

¹ 100.64.0.0/10 is also the carrier-grade NAT range. If Jellyfin can be reached *directly* (not through nginx) from such an address, for example an ISP's CGNAT network or a VPS provider's internal network, remove it from *Trusted direct networks* and list your exact Tailscale addresses instead.

Administrators are treated exactly like everyone else. **API keys keep working as normal** (they are not sign-ins).

## How it works

1. A client sends the password through nginx. Jelly2FA (a Jellyfin *authentication provider*) runs **before Jellyfin creates any token**. It refuses with HTTP 403, so **no token or device is created**, and emails the user an 8-digit code.
2. The user signs in again in the same app and types `password` + `code`, for example `MyPassword12345678`.
3. Jelly2FA checks the password and the code, and Jellyfin issues its normal token. That token behaves exactly like any other Jellyfin session (sign-out, device removal and password changes all work as usual).

**How "LAN or proxy" is decided.** A tiny middleware records the real TCP peer address *before* Jellyfin applies `X-Forwarded-For`.
- **2FA** if the peer is your proxy, or if the request carries **any** forwarding header (`X-Forwarded-*`, `X-Real-IP`, `Forwarded`, …).
- **Password only** if it is a plain direct connection from a LAN or Tailscale address.
- Forwarded headers are therefore never trusted to *skip* 2FA, so spoofing them only ever leads to 2FA.
- If no proxy address is configured at all, everyone needs 2FA.

**The code:**
- Each code is random, single use, valid for 10 minutes, and allows 5 wrong tries.
- It only works for the user, device id and app that requested it, and only while the password is unchanged.
- It is stored only as an HMAC in memory, so restarting Jellyfin discards pending codes.
- The email has a plain-text part and an HTML part that shows the code in large bold type. The language is English or German (setting *Language of user emails*). Administrator alerts are always in English.

**Optional: code-only second step** (setting *Allow the code alone as the second step*, **off by default**). When it is on, the second sign-in can be the user name plus **only the code** in the password field. Password + code keeps working too.
- The code is still only emailed after a correct password.
- It is additionally bound to the **client IP** that requested it. Entering it from another IP counts as a wrong try.
- Trade-off: the password is not checked again on the second step. Someone who can read the mailbox while the code is valid could use it, but only with the same device id, app name and IP as the original sign-in. Leave this off if you want the password re-checked.
- The IP binding needs Jellyfin's **Known proxies** to be set (otherwise every remote client has nginx's IP). With the option on and Known proxies empty, the status page reports a problem.

**Abuse limits:**
- Emails are sent only after a correct password, with a 60 s resend cooldown, at most 5 per user per hour and 50 per hour for the server.
- Failed sign-ins are throttled per IP (10 / 5 min; IPv6 per /64) and, for sign-ins through the proxy, per user (10 / 15 min). Direct LAN/Tailscale sign-ins are throttled per IP only, so failures from the internet cannot lock a user out of the LAN.
- If a code email cannot be queued, no code is kept, so the next attempt sends a new one instead of waiting for the resend cooldown.
- Jellyfin's own lockout is switched off for enrolled users. A lockout disables the account, which would also kill existing sessions, and anyone who knows a username could trigger it.

**Quick Connect** stays available. A code can only be approved from a session that is already signed in. Enrolling a user revokes all of that user's older sessions, so every approving session has passed 2FA or come from LAN/Tailscale. The user is emailed about every Quick Connect sign-in; you can turn that off, or disable Quick Connect for enrolled users altogether.

**Other token paths.** Any token for an enrolled user that did not pass Jelly2FA and is not Quick Connect is revoked immediately, and the admin is alerted. This covers, for example, an SSO plugin that signs users in directly.

## Requirements

- Jellyfin **12.x** (built against 12.2, .NET 10, `targetAbi 12.0.0.0`).
- An SMTP account that supports **STARTTLS** (port 587). Implicit TLS on port 465 is not supported. The server certificate is validated.
- Users with a password.

## Installation

1. Install the plugin, either:
   - **From the plugin repository (recommended):** in **Dashboard → Plugins → Repositories**, add
     `https://raw.githubusercontent.com/TIGamingTV/Jelly2FA/main/manifest.json`.
     Then install **Jelly2FA** from the **Catalog** (category *Authentication*) and restart Jellyfin.
   - **Manually:** build it (or download the zip from a GitHub release):
     ```sh
     dotnet publish src/Jellyfin.Plugin.Jelly2FA -c Release -o out/Jelly2FA_0.0.2.0
     ```
     Copy the folder `Jelly2FA_0.0.2.0` (it contains `Jellyfin.Plugin.Jelly2FA.dll` and `meta.json`) into Jellyfin's `plugins` directory, for example `/var/lib/jellyfin/plugins/` or `/config/plugins/` in Docker. Then restart Jellyfin.
2. Configure the Jellyfin networking settings below.
3. Open **Dashboard → Plugins → Jelly2FA** and configure SMTP. Save the SMTP password with its own button; it is stored in `plugins/Jellyfin.Plugin.Jelly2FA/secrets.json` with mode 0600, or comes from the environment variable `JELLY2FA_SMTP_PASSWORD`. Then send a test email.
4. **While connected over LAN or Tailscale**, enroll each user, including admins, with their email address. Enrolling signs out all existing sessions of that user except the one you are using.
5. Check that the status box on the plugin page says *Healthy*.

### Jellyfin networking settings (Dashboard → Networking)

- **Known proxies**: the IP address nginx connects to Jellyfin from. This is required for correct client IPs and for the LAN exemption. You can also list it in the plugin's *Reverse proxy addresses*.
- **LAN networks**: list your LAN explicitly, for example `192.168.1.0/24`. Tailscale is handled by the plugin's *Trusted direct networks* (default: the Tailscale ranges).
- Keep **legacy authorization** disabled (the 12.x default).
- Router: forward only nginx (443). **Never forward port 8096.**

### nginx

See [`docs/nginx-jellyfin.conf.example`](docs/nginx-jellyfin.conf.example). The two important points:
- nginx must always send `X-Forwarded-For` (the official Jellyfin config does).
- nginx must connect from an address listed as a proxy.

The example also rate-limits the sign-in routes (not Quick Connect polling), blocks the obsolete `?pw=` route, hides the anonymous `/Jelly2FA/Health` endpoint from the internet (the watchdog talks to Jellyfin directly) and strips query strings from logs.

**Topology caveats:**
- If nginx runs **on the Jellyfin host**, it connects from `127.0.0.1`. Loopback is not trusted by default; leave *Trust loopback* off.
- If Jellyfin runs in **Docker bridge mode**, LAN clients may appear as the Docker gateway (for example `172.17.0.1`). If nginx also arrives from that address, everyone gets 2FA (safe, but no LAN exemption). Use host networking, or make sure nginx and LAN clients arrive from different addresses.
- If LAN users connect via the DDNS name (hairpin NAT), they go through nginx and get 2FA. That is intended.

## What users see

Apps don't know about 2FA. After the first attempt the app shows its usual error. The message differs per app:

| Client | Message after the first (password-only) attempt |
|---|---|
| Web, Jellyfin Desktop, Android app, Samsung/LG TV | "You are not authorized to access the server at this time…" |
| Android TV / Google TV | "Unable to connect to server" (misleading; just retry with password+code) |
| Swiftfin | an HTTP 403 error |
| Findroid / Streamyfin / Finamp / Kodi / Roku | an error/"login failed" message |

The email explains the next step. Notes:
- Don't put a space between the password and the code (Swiftfin trims spaces).
- Roku's on-screen keyboard is limited in length (unverified).
- **Jellyseerr / Seerr**: the user can sign in with **Quick Connect** (Seerr 3.4+). Seerr's library sync uses an API key and is unaffected.
- **Scripts**: use API keys. They bypass 2FA by design, so treat them like root passwords.
- **Infuse** (closed source) is untested.

Verified from the clients' source code, not by testing on devices: all listed apps sign in through the standard `/Users/AuthenticateByName` call, and none retries automatically.

## Recovery

- **Already signed-in sessions keep working if the plugin breaks.** Tokens are checked by Jellyfin, not by the plugin, and lockout is off for enrolled users. This was verified on Jellyfin 12.2.
- **New sign-ins of enrolled users fail if the plugin cannot load** (crash, incompatible Jellyfin version, folder deleted by hand), even on LAN. Jellyfin then uses its "invalid provider", which refuses everyone. This is different from *disabling* the plugin, see below.
- **Plugin loaded but SMTP broken** → LAN/Tailscale sign-in still works (password only). Fix SMTP from there.
- **Plugin not loaded** → nobody enrolled can sign in. Recover from any session that is still signed in, or use shell access to the host (for example SSH over LAN/Tailscale):
  ```sh
  sudo systemctl stop jellyfin            # or: docker stop jellyfin
  sudo tools/jelly2fa-recover.sh /var/lib/jellyfin/data/jellyfin.db <username>   # or --all
  sudo systemctl start jellyfin
  ```
  The script backs up the database first, restores Jellyfin's default lockout and resets the failed-login counter. The user then signs in with the password only until you re-enroll them. It exits non-zero if no matching Jelly2FA user was found (user names are matched case-insensitively).
- Optional: keep one extra admin account that is **not enrolled**, with "Allow remote connections" turned off. Jellyfin blocks it remotely, but only if Known proxies is set correctly.

### Disabling, enabling and uninstalling

The plugin behaves like any other plugin in **Dashboard → Plugins**:

- **Disable**: sign-in returns to normal immediately, without a restart. Every user on Jelly2FA is switched to Jellyfin's default provider with Jellyfin's default lockout, and the failed-login counter is reset. The plugin remembers who was enrolled, and the admin gets an alert email. The status page says *disabled* until you restart; after the restart the plugin is not loaded.
- **Enable**: the remembered users are switched back to two-factor sign-in and **all their sessions are revoked**, because those may have been created with the password only. This happens immediately if the plugin is still loaded (your own session is kept), otherwise during the next start, before Jellyfin accepts sign-ins. Users whose provider you changed in the meantime are left alone.
- While the plugin is disabled you cannot enroll users. Unenrolling still works.
- **Uninstall** (of an active plugin): users are switched back to the default provider (default lockout, counter reset), the enrollment list is cleared and the SMTP password file is deleted. Jellyfin leaves the plugin's settings file (`plugins/configurations/Jellyfin.Plugin.Jelly2FA.xml`) behind, as for every plugin.
- **Uninstalling a disabled plugin** cannot run any plugin code. Users are already on normal sign-in, but `plugins/Jellyfin.Plugin.Jelly2FA/secrets.json` (the SMTP password) and the settings file with the email addresses stay behind; delete them by hand. A later reinstall does **not** re-activate anybody; the status page then lists those users as "enrolled but uses another authentication provider".

### Watchdog (email when the plugin is down)

A plugin that failed to load cannot send email itself. Use the watchdog on the host instead:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin jelly2fa-watchdog
sudo install -m 0755 tools/jelly2fa-watchdog.sh /usr/local/bin/
echo 'ALERT_TO=you@example.com' | sudo tee /etc/default/jelly2fa-watchdog
sudo cp tools/systemd/jelly2fa-watchdog.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now jelly2fa-watchdog.timer
```

The watchdog runs as the unprivileged user `jelly2fa-watchdog` (the unit was checked with `systemd-analyze verify`, mail delivery as that user was not tested). postfix's `sendmail` is normally usable by any local user. For msmtp, give that user a readable config, for example `SENDMAIL="msmtp -C /etc/jelly2fa-watchdog/msmtprc -t"` in `/etc/default/jelly2fa-watchdog`, with the file owned by `jelly2fa-watchdog` and mode 0600. `/etc/default/jelly2fa-watchdog` is executed as a shell script by the watchdog, so keep it owned by root and not writable by others.

It checks `GET /health` (Jellyfin) and `GET /Jelly2FA/Health` every 5 minutes:
- 200: OK
- 404: plugin not loaded (also after disabling it and restarting)
- 503: degraded (SMTP, proxy settings or user enrollment problems)

It mails you on every state change, via `sendmail -t` (for example msmtp or postfix). While the plugin is loaded, it also emails the administrator alert address about problems itself, at most once per hour.

## Security notes and limits

- Protects against a remote attacker who knows a password. It does **not** protect against someone who controls the user's mailbox *and* knows the password, a compromised server or admin, or a stolen session token. Tokens don't expire in Jellyfin, so sign out devices you no longer use.
- Codes travel by email, so the security of the second factor equals the security of the mailbox.
- A correct password from the internet results in a code email ("Someone entered the correct password…"). Treat that email as an alarm.
- There is no "remember this device": device ids are chosen by the client and are not secret. One code gives one Jellyfin session, which lasts until sign-out.
- Pending codes and throttle counters are in memory only.
- The plugin uses an undocumented-but-standard ASP.NET Core hook (`IStartupFilter`) for origin capture. If that ever stops running, every sign-in requires 2FA (fail closed) and the status page warns.
- **Never rename** `TwoFactorAuthenticationProvider`: its full type name is stored as the provider id of every enrolled user.

## Development

```sh
dotnet test                       # unit tests
tests/e2e/run_e2e.sh              # end-to-end against a throwaway Jellyfin 12.2 (see header of the script)
```

The end-to-end suite runs against the real Jellyfin 12.2 server, with 127.0.0.1 playing nginx and a local STARTTLS SMTP sink. It checks:
- no token or device on 403; the code flow; code replay, device binding and races;
- LAN, Tailscale-style and untrusted direct connections; spoofed forwarding headers;
- admins via the proxy; the legacy and lowercase routes;
- API keys (header and `?ApiKey=`); Quick Connect (allowed, notified, disabled);
- fail closed without a proxy; password change; throttling without account lockout; remote failures not blocking LAN sign-in;
- the code-only option (IP binding); unenroll after failed sign-ins (no surprise lockout); a posted configuration without users;
- Disable (immediate and after restart), Enable (immediate and at startup, sessions revoked), Uninstall of an active and of a disabled plugin, reinstall;
- the plugin failing to load (fail closed) and `tools/jelly2fa-recover.sh` with a user name containing a quote.

It needs the Jellyfin 12.2 tarball, the .NET SDK, python3, sqlite3, openssl and curl.

### Releasing

1. Update `version` and `changelog` in `src/Jellyfin.Plugin.Jelly2FA/meta.json`.
2. Tag and push: `git tag v0.0.3.0 && git push origin v0.0.3.0`.

The `release` workflow runs the tests, builds `jelly2fa_<version>.zip`, attaches it to a GitHub release, and adds the version (with its MD5 checksum) to `manifest.json` on `main`. Jellyfin reads that file as the plugin repository. If `main` is branch-protected, allow `github-actions[bot]` to push to it.

## License

GPL-3.0 (see `LICENSE`).
