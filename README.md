<p align="center">
  <img src="Jelly2FA.PNG" alt="Jelly2FA" width="400">
</p>

# Jelly2FA

> **Unofficial personal project.** Not affiliated with Jellyfin and not security-audited. Use it at your own risk and keep a [recovery path](docs/troubleshooting.md#recovery).

Jelly2FA is a Jellyfin plugin that adds an emailed one-time code as a second factor for sign-ins that arrive **through your reverse proxy** (for example nginx with a DDNS name). Users type the code directly after their password in the normal password field, so **no client app needs to change**. Direct sign-ins from your LAN or Tailscale keep working with the password only.

It is for people who expose Jellyfin to the internet through a reverse proxy and want protection against someone who knows (or guesses) a user's password.

## Features

- **Email code for remote sign-ins:** after a correct password from the internet, Jellyfin issues no token. The user gets an 8-digit code by email and signs in again with `password` + `code` (for example `MyPassword12345678`).
- **Password only on the LAN/Tailscale:** direct connections from Jellyfin's LAN networks or the *Trusted direct networks* (Tailscale ranges by default) skip the code.
- **Fail closed:** anything unclear (an unknown proxy, forwarding headers, missing data) requires the code. Forged forwarding headers can only ever *add* the code requirement.
- **Applies to everyone, including administrators.** API keys are not affected.
- **Quick Connect** keeps working (optionally with an email notice per sign-in, or disabled for enrolled users).
- **Abuse limits:** per-IP and per-user failure throttling, email budgets, resend cooldown, limited wrong code entries.
- **Optional:** code alone as the second step, and code reuse for apps such as Seerr that sign in with credentials another app (Neptune) just used.
- **Admin tooling:** status page with health checks, admin alert emails, anonymous health endpoint, an external watchdog script and an offline recovery script.
- User emails in English or German, with times in the server's (or a configured) time zone.

## Requirements

- Jellyfin **12.x** (the plugin is built against Jellyfin 12.2 / .NET 10, `targetAbi` 12.0.0.0).
- A reverse proxy (an nginx example is included) that connects to Jellyfin from a known address and sends `X-Forwarded-For`.
- An SMTP account with **STARTTLS** (usually port 587). Implicit TLS on port 465 is not supported. The server certificate is validated.
- Every user you enroll needs a password and an email address.

## Installation

1. In Jellyfin, open **Dashboard → Plugins → Repositories** and add a repository with any name (for example `Jelly2FA`) and this **repository manifest URL**:

   ```text
   https://raw.githubusercontent.com/TIGamingTV/Jelly2FA/main/manifest.json
   ```

2. Open the plugin **Catalog**, find **Jelly2FA** (category *Authentication*) and install it.
3. Restart Jellyfin.
4. Verify: **Dashboard → Plugins** lists Jelly2FA and its settings page opens with a **Status** box. From the Jellyfin host, `curl -i http://127.0.0.1:8096/Jelly2FA/Health` (adjust the address to your Jellyfin) returns `503` (not configured yet) or `200`; `404` means the plugin is not loaded.

Manual installation (without the repository) and Docker notes are in [docs/configuration.md](docs/configuration.md#manual-installation).

## Initial configuration

Do these steps **while connected over the LAN or Tailscale**, not through the proxy.

1. **Jellyfin networking** (**Dashboard → Networking**):
   - **Known proxies:** the IP address nginx connects to Jellyfin from. Without a known proxy address, *everyone* (also on the LAN) needs a code.
   - **LAN networks:** list your LAN explicitly, for example `192.168.1.0/24`.
2. **Reverse proxy:** make sure nginx always sends `X-Forwarded-For` and connects from the address listed above. See [`docs/nginx-jellyfin.conf.example`](docs/nginx-jellyfin.conf.example). Forward only the proxy port (443) on your router, **never port 8096**.
3. **Plugin page** (**Dashboard → Plugins → Jelly2FA**):
   1. Fill in **SMTP host**, **SMTP port**, **SMTP user name**, **From address** and **Administrator alert email**, then click **Save settings**.
   2. Enter the SMTP password under **SMTP password** and click **Save SMTP password** (it has its own button and is never shown again).
   3. Under **Test email**, enter your address and click **Send test email**.
4. **Enroll users:** in the **Users** table, type each user's email address and click **Enroll**. Enroll admins too. Enrolling signs out all existing sessions of that user (except the session you are using).
5. Click **Refresh status**. The status box should say **Healthy**.

## Quick start: the first remote sign-in

1. From outside your network (for example a phone on mobile data), open Jellyfin through your DDNS name and sign in with the **password only**.
2. The app shows its normal sign-in error. That is expected: Jellyfin does not know how to show "code required". The user receives an email *"&lt;server&gt;: sign-in code"*.
3. Sign in again **in the same app** with the password immediately followed by the 8-digit code, no space: `MyPassword12345678`.
4. You are signed in. The session behaves like any other Jellyfin session.

The code is valid for 10 minutes (default), works once, and only for the same user, device and app. If the user signs in with the password only again, a new code is sent, and the codes from the last 3 emails keep working.

## Usage

- [docs/usage.md](docs/usage.md): the sign-in flow, what each client shows, Quick Connect, code-only sign-in, code reuse for Seerr/Neptune, managing users, API keys and scripts.
- [docs/configuration.md](docs/configuration.md): every setting on the plugin page, Jellyfin and nginx requirements, the `JELLY2FA_SMTP_PASSWORD` and `TZ` environment variables, Jellyfin in Docker.
- [docs/troubleshooting.md](docs/troubleshooting.md): status page and log messages, fail2ban/CrowdSec, recovery when nobody can sign in, disabling/uninstalling, the watchdog, updating.
- [docs/development.md](docs/development.md): building, tests and releases.

## Essential settings

| Setting | Default | Notes |
|---|---|---|
| SMTP host / port / user name / From address | empty / `587` / empty / empty | Required for codes to be sent. |
| SMTP password | none | Saved separately; or set the environment variable `JELLY2FA_SMTP_PASSWORD`. |
| Administrator alert email | empty | Recommended: receives alerts about problems. |
| Reverse proxy addresses | empty | Extra proxy IPs/CIDRs. Jellyfin's *Known proxies* are always included. |
| Trusted direct networks | `100.64.0.0/10,fd7a:115c:a1e0::/48` | Tailscale ranges. Direct connections from here use the password only. |
| Trust Jellyfin's LAN networks for direct connections | on | |

All settings: [docs/configuration.md](docs/configuration.md).

## Security notes and limits

- Protects against a remote attacker who knows a password. It does **not** protect against someone who controls the user's mailbox *and* knows the password, a compromised server or admin account, or a stolen session token. Jellyfin tokens don't expire, so sign out devices you no longer use.
- The second factor is only as strong as the mailbox. A code email means someone entered the correct password; users should treat an unexpected one as an alarm.
- There is no "remember this device": one code gives one Jellyfin session, which lasts until sign-out.
- API keys bypass 2FA by design. Treat them like root passwords.
- Pending codes and throttle counters are kept in memory only; restarting Jellyfin discards pending codes.
- If the plugin fails to load, enrolled users **cannot sign in at all** (existing sessions keep working). See [Recovery](docs/troubleshooting.md#recovery).

## License

GPL-3.0, see [LICENSE](LICENSE).
