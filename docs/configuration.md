# Configuration

This page covers installation options, the Jellyfin and reverse-proxy settings Jelly2FA depends on, and every setting on the plugin page.

- [Manual installation](#manual-installation)
- [How Jelly2FA decides "LAN or proxy"](#how-jelly2fa-decides-lan-or-proxy)
- [Jellyfin networking settings](#jellyfin-networking-settings)
- [Reverse proxy (nginx)](#reverse-proxy-nginx)
- [Plugin settings reference](#plugin-settings-reference)
- [Environment variables](#environment-variables)
- [Jellyfin in Docker](#jellyfin-in-docker)
- [Files on disk](#files-on-disk)

## Manual installation

The recommended way is the plugin repository (see the [README](../README.md#installation)). To install without it:

1. Download `jelly2fa_<version>.zip` from the [GitHub releases](https://github.com/TIGamingTV/Jelly2FA/releases), or build it yourself with the .NET 10 SDK:

   ```sh
   dotnet publish src/Jellyfin.Plugin.Jelly2FA -c Release -o out/Jelly2FA_0.0.5.0
   ```

2. Create a folder such as `Jelly2FA_0.0.5.0` in Jellyfin's `plugins` directory (for example `/var/lib/jellyfin/plugins/`, or `/config/plugins/` in the official Docker image) and put the contents of the zip (or of the publish output) in it. It must contain `Jellyfin.Plugin.Jelly2FA.dll` and `meta.json`.
3. Make sure the Jellyfin user can read the folder, then restart Jellyfin.

A manually installed plugin is not updated through the Catalog.

## How Jelly2FA decides "LAN or proxy"

A small middleware records the real TCP peer address **before** Jellyfin applies `X-Forwarded-For`. Then:

| Where the sign-in comes from | What the user types into the password field |
|---|---|
| Through the reverse proxy (internet) | password, then **password + 8-digit code** |
| Direct connection from Jellyfin's *LAN networks* | password only |
| Direct connection from *Trusted direct networks* (default: Tailscale `100.64.0.0/10`, `fd7a:115c:a1e0::/48`) | password only |
| Anything unclear | password + code (fail closed) |

The code is required if any of these is true:

- the TCP peer is a proxy address (Jellyfin's *Known proxies* or the plugin's *Reverse proxy addresses*);
- the request carries **any** forwarding header: `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Protocol`, `X-Forwarded-Port`, `X-Real-IP`, `Forwarded`, `X-Original-For`, `X-Client-IP`, `True-Client-IP`, `CF-Connecting-IP`;
- **no proxy address is configured at all** (then everybody needs a code, also on the LAN);
- the peer is loopback (`127.0.0.1`, `::1`) and *Trust loopback* is off;
- the peer is in neither the LAN networks nor the trusted networks.

Forwarding headers are never trusted to *skip* the code, so spoofing them only ever leads to 2FA.

> **CGNAT warning:** `100.64.0.0/10` is also the carrier-grade NAT range. If Jellyfin can be reached *directly* (not through nginx) from such addresses, for example an ISP's CGNAT network or a VPS provider's internal network, remove the range from *Trusted direct networks* and list your exact Tailscale addresses instead.

## Jellyfin networking settings

In **Dashboard → Networking**:

- **Known proxies:** the IP address nginx connects to Jellyfin from. Required for correct client IPs and for the LAN exemption. You can list it in the plugin's *Reverse proxy addresses* instead, but Jellyfin then sees every remote client as the proxy IP (the status page warns about this; with *Allow the code alone* on it is reported as a problem).
- **LAN networks:** list your LAN explicitly, for example `192.168.1.0/24`. Tailscale is covered by the plugin's *Trusted direct networks*.
- **Legacy authorization:** keep it disabled. The status page warns if it is enabled.

On your router, forward only the proxy (443). **Never forward port 8096**: a direct internet connection still needs a code, but it bypasses nginx (TLS, rate limiting, logging).

### Topology caveats

- **nginx on the Jellyfin host:** nginx connects from `127.0.0.1`. Leave *Trust loopback* off (the default).
- **Jellyfin in Docker bridge mode:** LAN clients may appear as the Docker gateway (for example `172.17.0.1`). If nginx also arrives from that address, everyone needs a code (safe, but no LAN exemption). Use host networking, or make sure nginx and LAN clients arrive from different addresses.
- **Hairpin NAT:** LAN users who connect via the DDNS name go through nginx and need a code. That is intended.

## Reverse proxy (nginx)

See [`nginx-jellyfin.conf.example`](nginx-jellyfin.conf.example), based on the official Jellyfin nginx example. Two points are essential:

1. nginx must always send `X-Forwarded-For` (the example overwrites any client-supplied value).
2. nginx must connect to Jellyfin from an address listed as a proxy.

The example additionally rate-limits the sign-in routes (not Quick Connect polling), blocks the obsolete `/Users/{id}/Authenticate` route (it takes the password in the URL), hides the anonymous `/Jelly2FA/Health` endpoint from the internet, and strips query strings from the access log. Replace the server name, certificate paths and upstream address before use.

## Plugin settings reference

Open **Dashboard → Plugins → Jelly2FA**. Click **Save settings** after changing anything in the form. Settings take effect immediately; no restart is needed. The SMTP password and the user list have their own buttons.

### Email (SMTP)

| Setting | Default | Description |
|---|---|---|
| SMTP host | empty | SMTP server name. STARTTLS is always required; the certificate is validated. |
| SMTP port | `587` | Submission port with STARTTLS. Implicit TLS (465) is not supported. |
| SMTP user name | empty | Empty = no SMTP authentication. If set, a password is required. |
| From address | empty | Sender address. Must be a valid address. |
| From name | `Jellyfin Jelly2FA` | Sender display name. |
| Administrator alert email | empty | Receives alerts (SMTP missing, self-check problems, unexpected tokens revoked, plugin disabled/enabled, email budget exhausted). At most one email per alert type per hour. Alerts are always in English. |
| Server name in emails | `Jellyfin` | Shown in email subjects and text. |
| Language of user emails | English | `English` or `Deutsch`. Applies to code and Quick Connect emails. |
| Time zone of user emails | empty | Empty = the server's time zone. Otherwise an IANA id such as `Europe/Berlin`. Unknown ids fall back to the server's time zone and show a warning on the status page. |

SMTP counts as configured when the host, a valid port, a valid From address and (if a user name is set) a password are present.

**SMTP password:** enter it under **SMTP password** and click **Save SMTP password**. It is stored in `plugins/Jellyfin.Plugin.Jelly2FA/secrets.json` (mode 0600), not in the regular settings file, and is never shown again. Saving an empty value clears it. The environment variable [`JELLY2FA_SMTP_PASSWORD`](#environment-variables) overrides the stored value.

**Test email:** enter a recipient and click **Send test email**. It is sent immediately; an SMTP error is shown in a dialog.

### Network

| Setting | Default | Description |
|---|---|---|
| Reverse proxy addresses | empty | IPs/CIDRs of nginx as seen by Jellyfin, separated by commas. Jellyfin's *Known proxies* are always included. |
| Trusted direct networks | `100.64.0.0/10,fd7a:115c:a1e0::/48` | CIDRs whose **direct** connections sign in with the password only. Invalid entries are ignored. |
| Trust Jellyfin's LAN networks for direct connections | on | Direct connections from Jellyfin's *LAN networks* use the password only. |
| Trust loopback | off | Trust direct connections from `127.0.0.1`/`::1`. Only enable it if nginx is **not** on the Jellyfin host. |

### Quick Connect

| Setting | Default | Description |
|---|---|---|
| Allow Quick Connect for enrolled users | on | If off, a Quick Connect sign-in of an enrolled user is revoked right after approval. |
| Email the user on every Quick Connect sign-in | on | Sends a notice with device, app, approving IP and time. |

Quick Connect must also be enabled in Jellyfin itself; the status box shows whether it is.

### Second step

| Setting | Default | Description |
|---|---|---|
| Allow the code alone as the second step | off | The second sign-in may be user name + **only the code**. See [Code-only sign-in](usage.md#code-only-sign-in). Requires Jellyfin *Known proxies* to be set. |

### Code reuse

Off by default. See [Code reuse (Seerr, Neptune)](usage.md#code-reuse-seerr-neptune) before enabling it.

| Setting | Default | Accepted values | Description |
|---|---|---|---|
| Additional sign-ins per code | `0` | 0–10 | `0` = off. How many more sign-ins a successfully used code allows. |
| Reuse window after the first use | `5` | 1–60 minutes | How long after the first use the code can be reused. |
| Apps allowed to reuse a code | `Seerr,Jellyseerr` | comma separated | App (client) names as sent by the client, case-insensitive. If empty, reuse is off. |
| Only from these addresses | empty | IPs/CIDRs, comma separated | Recommended. Reuse is only accepted when the real TCP connection to Jellyfin comes from one of these addresses (for example the Seerr host). Empty = any address. Invalid entries are ignored and reported on the status page. |

### Limits

| Setting | Default | Description |
|---|---|---|
| Code lifetime | `10` minutes | 1–60. |
| Wrong code entries per code | `5` | After this many wrong entries the code is invalidated. |
| Pending codes per user | `3` | Oldest pending code is dropped when exceeded (one pending code per device and app). |
| Resend cooldown | `60` seconds | No new email for the same device and app within this time; the earlier code stays valid. |
| Code emails per user per hour | `5` | |
| Code emails per hour (server) | `50` | When exhausted, the administrator is alerted. |
| Failed sign-ins per IP / IP window | `10` / `5` minutes | IPv6 clients are counted per /64. |
| Failed sign-ins per user / User window | `10` / `15` minutes | Applies to sign-ins through the proxy only, so remote failures cannot lock a user out of the LAN. |

What counts as a failed sign-in is described in [Abuse limits](usage.md#abuse-limits). Current counters can be seen and cleared on the plugin page under **Failed sign-in throttles**.

### CrowdSec

Off by default. See [Let CrowdSec make the IP bans](troubleshooting.md#let-crowdsec-make-the-ip-bans).

| Setting | Default | Description |
|---|---|---|
| Let CrowdSec make the IP bans | off | *Failed sign-ins per IP* is no longer applied; only the backstop below is. Wrong codes after a correct password (403) and IPs blocked by the backstop are logged as `Jelly2FA: Authentication request for "<user>" has been denied (IP: "<ip>"). Reason: …`, the line CrowdSec's Jellyfin parser reads, so CrowdSec counts them like wrong passwords. The per-user limit stays. Requires Jellyfin *Known proxies* (otherwise the status page shows a problem). |
| Backstop: failed sign-ins per IP that Jelly2FA still blocks | `100` | Within the *IP window*. A safety net if CrowdSec is not running; keep it well above CrowdSec's threshold. Empty or `0` = `100`. |

## Environment variables

These are read by the plugin from the Jellyfin process environment. Jellyfin must be restarted for changes to take effect.

| Variable | Required | Default | Description |
|---|---|---|---|
| `JELLY2FA_SMTP_PASSWORD` | No | none | SMTP password. When set and non-empty, it takes precedence over the password saved on the plugin page. **Sensitive.** Example: `JELLY2FA_SMTP_PASSWORD=app-password-here` |
| `TZ` | No | system time zone | Standard variable used by .NET for the server's local time zone. Times in user emails use it unless *Time zone of user emails* is set. Example: `TZ=Europe/Berlin` |

The [watchdog](troubleshooting.md#watchdog) has its own variables; they are not read by the plugin.

## Jellyfin in Docker

Jelly2FA has no Docker image of its own; it runs inside your Jellyfin container. Install it through the plugin repository as usual. Relevant points:

- Plugin and settings files live in Jellyfin's config volume (for example `/config/plugins/` in the official image), so they persist across container recreation.
- To use the environment variables, add them to your existing Jellyfin service. Excerpt for a Compose file (keep the rest of your service definition):

  ```yaml
  services:
    jellyfin:
      # ... your existing image, volumes, ports ...
      environment:
        TZ: "Europe/Berlin"
        JELLY2FA_SMTP_PASSWORD: "${JELLY2FA_SMTP_PASSWORD}"   # put the value in an .env file next to compose.yaml
  ```

  Then recreate the container: `docker compose up -d jellyfin`.
- Bridge networking can make LAN clients and nginx appear from the same gateway address; see [Topology caveats](#topology-caveats). Host networking avoids this.
- The watchdog must reach Jellyfin directly; set `JELLYFIN_URL` if Jellyfin is not on `http://127.0.0.1:8096`.

## Files on disk

Paths are relative to Jellyfin's data directory (for example `/var/lib/jellyfin/` or `/config/` in Docker).

| File | Contents |
|---|---|
| `plugins/configurations/Jellyfin.Plugin.Jelly2FA.xml` | Settings and the enrolled users with their email addresses. Manage users on the plugin page, not by editing this file. |
| `plugins/Jellyfin.Plugin.Jelly2FA/secrets.json` | The saved SMTP password (mode 0600). |
| `jelly2fa-suspended.json` in the plugin's installation folder (for example `plugins/Jelly2FA_<version>/`) | Only while the plugin is disabled: the users to switch back to 2FA when it is enabled again. |

Pending codes, recently issued codes and throttle counters are kept in memory only.
