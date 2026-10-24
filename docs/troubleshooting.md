# Troubleshooting and operations

- [Status page and health endpoint](#status-page-and-health-endpoint)
- [Logs](#logs)
- [Common problems](#common-problems)
- [fail2ban / CrowdSec](#fail2ban--crowdsec)
- [Recovery](#recovery)
- [Disabling, enabling and uninstalling](#disabling-enabling-and-uninstalling)
- [Watchdog](#watchdog)
- [Updating](#updating)

## Status page and health endpoint

**Dashboard → Plugins → Jelly2FA → Status** shows **Healthy** or **PROBLEMS FOUND**, the number of enrolled users, whether a proxy is known, whether SMTP is configured and whether Quick Connect is on. Problems (red) and warnings (orange) are listed below it. Click **Refresh status** after changes.

Problems (status not healthy):

- no reverse proxy address configured (everyone needs a code, also on the LAN);
- *Allow the code alone as the second step* is on but Jellyfin *Known proxies* is empty;
- SMTP is not configured, or sending email failed recently;
- a user is enrolled but uses another authentication provider (no 2FA), uses the Jelly2FA provider but is not enrolled, or has an invalid email address.

Warnings include: Jellyfin *Known proxies* empty, code reuse on, invalid code-reuse addresses, unknown email time zone, legacy authorization enabled, no administrator alert email, users not enrolled, the plugin is disabled, and "origin capture middleware has not seen a request yet" (if this persists, every sign-in requires a code).

While loaded, the plugin checks itself every hour (starting 2 minutes after startup), logs the warnings and emails the problems to the administrator alert address (at most once per hour).

**Health endpoint** (no authentication, intended for monitoring from the Jellyfin host; the nginx example hides it from the internet):

```sh
curl -i http://127.0.0.1:8096/Jelly2FA/Health
```

| Status | Meaning |
|---|---|
| `200` `{"Status":"ok"}` | Plugin loaded, no problems. |
| `503` `{"Status":"degraded"}` | Plugin loaded, problems found (see the status page). |
| `404` | Plugin not loaded. |

## Logs

All plugin messages in Jellyfin's log start with `Jelly2FA`. Useful entries:

| Message (excerpt) | Meaning |
|---|---|
| `two-factor required for user … (reason, peer …, client ip …)` | A sign-in was treated as remote. The reason and peer show why. |
| `password-only sign-in for user … (direct connection from a Jellyfin LAN network …)` | A sign-in was treated as LAN/Tailscale. |
| `sign-in code emailed to user …` | A code was queued for sending. |
| `two-factor sign-in (…) completed for user …` | A code was accepted. |
| `sending email failed: …` | SMTP error. Check the SMTP settings and send a test email. |
| `throttled sign-in for user … from …` | A failure limit was reached. |
| `Jelly2FA alert: …` | An administrator alert (also emailed if an alert address is set). |

To find out why a LAN sign-in needs a code, look at the `peer` and the reason in the `two-factor required` line.

## Common problems

| Symptom | Cause and fix |
|---|---|
| Everyone needs a code, also on the LAN | No proxy address known: set Jellyfin **Known proxies** (or *Reverse proxy addresses*). Or LAN clients arrive from the proxy's address (Docker bridge, nginx on the same host as clients' gateway); see [Topology caveats](configuration.md#topology-caveats). Or the LAN is missing from Jellyfin's **LAN networks**. |
| Remote sign-in never asks for a code | The user is not enrolled, or the request does not pass through nginx. Check the user's state on the plugin page. |
| No code email arrives | Check the status page for SMTP problems, send a test email, check the spam folder. The resend cooldown (60 s) and the per-user limit (5 per hour) may suppress new emails; the earlier code stays valid. |
| "Unable to connect" / "not authorized" after the first attempt | Expected: the app cannot show "code required". Sign in again with password + code (on Android TV, the password is still in the field: add the code at the end). |
| Several code emails, user keeps getting new codes | The app was signed in with the password only again (for example the TV's *Sign in* pressed again without the code). Each attempt after the 60 s cooldown sends a new code; the codes from the last 3 emails for that app all work. |
| Code is rejected (`stale code` in the log) | It must be entered in the same app on the same device that requested it (the email subject names the app), within its lifetime, with no space after the password. Codes from more than 3 emails ago, used codes, and codes after a password change, email change or Jellyfin restart no longer work. Sign in with the password only to get a new code. |
| Enroll fails with "The user has no password" | Set a password for the user first. |
| Enroll fails with "Jelly2FA is disabled" | Enable the plugin and restart Jellyfin first. |
| Test email fails | The error from the SMTP server is shown. Only STARTTLS (usually port 587) is supported; port 465 does not work. |

## fail2ban / CrowdSec

- **Jellyfin's log** (CrowdSec `LePresidente/jellyfin-bf`, the usual fail2ban jellyfin filter) matches "Authentication request for … has been denied". Jellyfin writes that line only for a 401: with Jelly2FA a wrong password or an unknown code alone. The two-factor step after a correct password is not logged as denied (see [401 or 403](usage.md#401-or-403)).
- **nginx's access log:** CrowdSec's `crowdsecurity/base-http-scenarios` collection contains `LePresidente/http-generic-403-bf`, which bans after about 5 **POST requests with status 403** within a short time, on any route. Every Jelly2FA sign-in produces at least one such 403 (Seerr two, because it retries), plus one per mistyped code, so frequent sign-ins can get a user banned.

To keep that scenario for everything else, whitelist 403 on the sign-in routes only. For example, create `/etc/crowdsec/parsers/s02-enrich/jelly2fa-whitelist.yaml` (field names of the hub's `crowdsecurity/nginx-logs` parser; adapt them for other proxies):

```yaml
name: jelly2fa/signin-403-whitelist
description: "Jelly2FA: 403 on the Jellyfin sign-in routes follows a correct password"
whitelist:
  reason: "Jelly2FA two-factor step"
  expression:
    - "evt.Meta.http_verb == 'POST' && evt.Meta.http_status == '403' && evt.Meta.http_path matches '(?i)^(/[^?]*)?/users/(authenticatebyname|[0-9a-f-]{32,36}/authenticate)/?([?].*)?$'"
```

Then run `sudo systemctl reload crowdsec`.

Why this is acceptable: wrong passwords stay 401 and are still counted by every scenario. Guessing codes needs the correct password and is limited by Jelly2FA itself (5 wrong entries per code, codes only emailed after a correct password, 5 emails per user per hour, 10 failures per IP per 5 minutes). Jelly2FA's throttle also answers with 403, but only after repeated failures; wrong passwords among them are still visible to CrowdSec as 401. Jellyfin's own 403s on these routes (disabled account, remote access not allowed, parental schedule) are hidden as well; they never sign anybody in.

## Recovery

- **Already signed-in sessions keep working if the plugin breaks.** Tokens are checked by Jellyfin, not by the plugin, and lockout is off for enrolled users.
- **Plugin loaded but SMTP broken:** LAN/Tailscale sign-in still works with the password only. Fix SMTP from there.
- **Plugin not loaded** (crash, incompatible Jellyfin version, folder deleted by hand): new sign-ins of enrolled users fail, **even on the LAN**, because Jellyfin refuses users whose authentication provider is missing. This is different from *disabling* the plugin (see below).

To recover when the plugin is not loaded, either use a session that is still signed in (for example to reinstall the plugin), or use shell access to the host (for example SSH over LAN/Tailscale) and the recovery script from this repository. It needs `sqlite3` 3.27 or newer.

```sh
sudo systemctl stop jellyfin            # or: docker stop jellyfin
sudo tools/jelly2fa-recover.sh /var/lib/jellyfin/data/jellyfin.db <username>   # or --all instead of <username>
sudo systemctl start jellyfin
```

Use the path of `data/jellyfin.db` inside your Jellyfin data directory (in Docker, the corresponding file in the mounted config volume on the host). The script:

- refuses to run while it detects a running Jellyfin process;
- backs up the database first (`jellyfin.db.jelly2fa-recover.<timestamp>.<pid>.bak`);
- switches the user(s) back to Jellyfin's default provider, restores the default lockout and resets the failed-login counter;
- matches user names case-insensitively, and exits non-zero if no matching Jelly2FA user was found.

The user then signs in with the password only (also remotely) until you re-enroll them.

Optional safety net: keep one extra admin account that is **not enrolled**, with "Allow remote connections" turned off. Jellyfin blocks it remotely, but only if Known proxies is set correctly.

## Disabling, enabling and uninstalling

The plugin behaves like any other plugin in **Dashboard → Plugins**:

- **Disable:** sign-in returns to normal immediately, without a restart. Every user on Jelly2FA is switched to Jellyfin's default provider with Jellyfin's default lockout, and the failed-login counter is reset. The plugin remembers who was enrolled, and the administrator gets an alert email. The status page says the plugin is disabled until you restart; after the restart the plugin is not loaded.
- **Enable:** the remembered users are switched back to two-factor sign-in and **all their sessions are revoked**, because those may have been created with the password only. This happens immediately if the plugin is still loaded (your own session is kept), otherwise during the next start. Users whose provider you changed in the meantime are left alone.
- While the plugin is disabled you cannot enroll users. Unenrolling still works.
- **Uninstall (of an active plugin):** users are switched back to the default provider (default lockout, counter reset), the enrollment list is cleared and the SMTP password file is deleted. Jellyfin leaves the settings file `plugins/configurations/Jellyfin.Plugin.Jelly2FA.xml` behind, as for every plugin.
- **Uninstall of a disabled plugin** cannot run any plugin code. Users are already on normal sign-in, but `plugins/Jellyfin.Plugin.Jelly2FA/secrets.json` (SMTP password) and the settings file (with the email addresses) stay behind; delete them by hand. A later reinstall does **not** re-activate anybody; the status page then lists those users as "enrolled but uses another authentication provider". Re-enroll them.

## Watchdog

A plugin that failed to load cannot send email. The watchdog script runs on the host, checks `GET /health` (Jellyfin) and `GET /Jelly2FA/Health` every 5 minutes through a systemd timer, and emails you on every state change via a sendmail-compatible command (for example postfix or msmtp).

Install it from a checkout of this repository:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin jelly2fa-watchdog
sudo install -m 0755 tools/jelly2fa-watchdog.sh /usr/local/bin/
echo 'ALERT_TO=you@example.com' | sudo tee /etc/default/jelly2fa-watchdog
sudo cp tools/systemd/jelly2fa-watchdog.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now jelly2fa-watchdog.timer
```

Check it with `sudo systemctl start jelly2fa-watchdog.service` and `journalctl -u jelly2fa-watchdog.service`.

Settings, in `/etc/default/jelly2fa-watchdog` (or the environment):

| Variable | Required | Default | Description |
|---|---|---|---|
| `ALERT_TO` | Yes | none | Recipient of the alerts. |
| `JELLYFIN_URL` | No | `http://127.0.0.1:8096` | Jellyfin URL reachable directly from this host (not through nginx). |
| `MAIL_FROM` | No | `jelly2fa-watchdog@<hostname>` | Sender address. |
| `STATE_FILE` | No | `/var/lib/jelly2fa-watchdog/state` | Last known state (the systemd unit creates this directory). |
| `SENDMAIL` | No | `sendmail -t` | Sendmail-compatible command, for example `msmtp -C /etc/jelly2fa-watchdog/msmtprc -t`. |

States: `OK`, `JELLYFIN_DOWN`, `PLUGIN_NOT_LOADED` (404), `PLUGIN_DEGRADED` (503), `PLUGIN_UNKNOWN`.

Notes:

- The service runs as the unprivileged user `jelly2fa-watchdog`. postfix's `sendmail` is normally usable by any local user. For msmtp, give that user a readable config file owned by `jelly2fa-watchdog` with mode 0600.
- `/etc/default/jelly2fa-watchdog` is executed as a shell script by the watchdog, so keep it owned by root and not writable by others.
- The unit file was checked with `systemd-analyze verify`; mail delivery as the watchdog user was not tested by the author.

## Updating

1. Read the changelog in the Catalog or on the [releases page](https://github.com/TIGamingTV/Jelly2FA/releases).
2. Install the new version from **Dashboard → Plugins → Catalog** (or replace the files of a manual installation).
3. Restart Jellyfin, then check that the status box says **Healthy**.

Settings, enrolled users and the saved SMTP password are stored outside the version folder (see [Files on disk](configuration.md#files-on-disk)), so the new version uses them. The author's end-to-end tests cover reinstalling but not upgrading between versions, so check the status page and the user states after the restart. Pending codes are discarded by the restart; users in the middle of signing in need to request a new code. Back up `plugins/configurations/Jellyfin.Plugin.Jelly2FA.xml` and `plugins/Jellyfin.Plugin.Jelly2FA/secrets.json` before upgrading if you want to be able to roll back.
