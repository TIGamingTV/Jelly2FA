# Usage

- [Managing users](#managing-users)
- [Signing in through the proxy](#signing-in-through-the-proxy)
- [What users see in their apps](#what-users-see-in-their-apps)
- [Signing in on the LAN or Tailscale](#signing-in-on-the-lan-or-tailscale)
- [Code-only sign-in](#code-only-sign-in)
- [Quick Connect](#quick-connect)
- [Code reuse (Seerr, Neptune)](#code-reuse-seerr-neptune)
- [API keys, scripts and other sign-in paths](#api-keys-scripts-and-other-sign-in-paths)
- [Abuse limits](#abuse-limits)

## Managing users

Manage users in the **Users** table on **Dashboard → Plugins → Jelly2FA**. Each row shows the user, whether they are an admin or have no password, their state and their email address.

| Action | How | Effect |
|---|---|---|
| Enroll | Type the email address, click **Enroll**, confirm. | The user needs a code for sign-ins through the proxy. **All existing sessions of the user are signed out** (except the session you are using). Jellyfin's own lockout is turned off for the user (Jelly2FA throttles instead) and the failed-login counter is reset. |
| Change email | Edit the address, click **Save email**. | Pending codes of the user are discarded. |
| Unenroll | Click **Unenroll**, confirm. | The user signs in with the password only, also remotely. Jellyfin's default lockout is restored and the failed-login counter is reset. |

Notes:

- Enroll users **while you are connected over the LAN or Tailscale**, so you are not locked out of your own session.
- A user without a password cannot be enrolled. Set a password first.
- You cannot enroll users while the plugin is disabled.
- Deleting a Jellyfin user also removes their enrollment.
- States in the table: `enrolled`, `not enrolled`, `ENROLLED BUT PROVIDER CHANGED` (someone switched the user's authentication provider, so 2FA is off; click **Enroll** again), `PROVIDER SET, NOT ENROLLED` (remote sign-in is refused; enroll or unenroll the user).

## Signing in through the proxy

1. The user signs in through nginx with the **password only**.
2. Jelly2FA runs as Jellyfin's authentication provider **before** Jellyfin creates a token. It refuses the sign-in with HTTP 403, so **no token or device is created**, and emails the user an 8-digit code.
3. The user signs in again **in the same app** with the password immediately followed by the code, no space, for example `MyPassword12345678`.
4. Jelly2FA checks the password and the code, and Jellyfin issues its normal token. Sign-out, device removal and password changes work as usual.

The code:

- is random, valid for 10 minutes and allows 5 wrong entries (both configurable);
- works once (unless [code reuse](#code-reuse-seerr-neptune) is on);
- works only for the user, device id and app that requested it, and only while the password is unchanged;
- stays valid when the user signs in with the password again: after the resend cooldown that sends a new code, but the codes from the last 3 emails for the same device and app all keep working until they expire. Using one of them signs the user in and ends the others;
- is stored only as an HMAC in memory. Restarting Jellyfin discards pending codes.

The code email has a plain-text part and an HTML part that shows the code in large type. Its subject names the app that requested it (for example *"MyServer: sign-in code for Jellyfin Android TV"*). It names the device, app, IP and time of the sign-in and warns that someone entered the correct password. Changing the password, the email address or unenrolling discards pending codes.

### 401 or 403

| Situation | HTTP status | Counted by Jellyfin as a failed sign-in? |
|---|---|---|
| Wrong password | 401 | Yes |
| Code alone that was not recently issued to this user | 401 | Yes |
| Correct password, code sent (or still pending during the resend cooldown) | 403 | No |
| Correct password + wrong code | 403 | No (but counts for Jelly2FA's own limits) |
| Correct password + used or expired code, a code from an older email beyond the last 3, or a code issued to another device or app | 403 | No |
| Correct password, but no code pending for this device and app | 403 | No |
| Too many failed sign-ins (Jelly2FA throttle) | 403 | No |

Jellyfin logs "Authentication request for … has been denied" and increments its failed-login counter only for 401. For 403, Jellyfin's log shows the reason, for example:

- `Jelly2FA: two-factor verification required: password correct, a sign-in code was sent by email. …`
- `Jelly2FA: this sign-in code is no longer valid (already used, expired, or requested by another device). …`
- `Jelly2FA: password correct, but the code is wrong. …`
- `Jelly2FA: password correct, but no code is pending for this device and app. …`

Codes issued in the last 30 days (the last 10 per user) are recognised when entered again, for example by an app that signs in again with stored credentials, and answered with 403 instead of counting as a failed sign-in.

## What users see in their apps

Apps don't know about 2FA. After the first (password-only) attempt they show their usual error, chosen from the HTTP status alone, so no app can say "password correct". The email explains the next step.

| Client | Message after the first attempt |
|---|---|
| Web, Jellyfin Desktop, Android app, Samsung/LG TV | "You are not authorized to access the server at this time…" |
| Android TV / Google TV (app name *Jellyfin Android TV*) | "Unable to connect to server" (misleading). The password stays in the field: add the code at the end and sign in again. |
| Swiftfin | an HTTP 403 error |
| Neptune | "Could not connect to server" (misleading) |
| Findroid / Streamyfin / Finamp / Kodi / Roku | an error / "login failed" message |

This table was derived from the clients' source code, not by testing on devices. All listed apps sign in through the standard `/Users/AuthenticateByName` call, and none retries automatically.

Tips:

- Don't put a space between the password and the code (Swiftfin trims spaces).
- Password + code always works, also when *Allow the code alone as the second step* is on. On TVs this is the easiest way: the password is still in the field after the first attempt, so just add the code. Pressing *Sign in* again without the code only sends another code email.
- A code works only in the app that requested it: a code requested on the TV cannot be used in the phone app, and the other way round.
- Roku's on-screen keyboard may limit the length of the password field (unverified).
- Infuse (closed source) is untested.
- **Jellyseerr / Seerr:** sign in with **Quick Connect** (Seerr 3.4+). Seerr's library sync uses an API key and is unaffected. For apps that sign in to Seerr with your Jellyfin credentials, see [Code reuse](#code-reuse-seerr-neptune).

## Signing in on the LAN or Tailscale

Direct connections from Jellyfin's LAN networks or the *Trusted direct networks* need the password only. Password + code is also accepted there (the code is not checked), so apps that stored password + code keep working on the LAN. Which connections count as direct is explained in [configuration.md](configuration.md#how-jelly2fa-decides-lan-or-proxy).

## Code-only sign-in

Setting: *Allow the code alone as the second step* (**off** by default).

When on, the second sign-in can be the user name plus **only the code** in the password field. Password + code keeps working, and the email tells the user to enter only the code.

- The code is still only emailed after a correct password.
- It is additionally bound to the **client IP** that requested it. Entering it from another IP counts as a wrong entry.
- The IP binding requires Jellyfin's **Known proxies** to be set (otherwise every remote client has nginx's IP). With the option on and Known proxies empty, the status page reports a problem.
- **Trade-off:** the password is not checked again on the second step. Someone who can read the mailbox while the code is valid could use it, but only with the same device id, app name and IP as the original sign-in. Leave the option off if you want the password re-checked.

## Quick Connect

Quick Connect stays available for enrolled users (setting *Allow Quick Connect for enrolled users*):

1. On the new device, choose Quick Connect; it shows a code.
2. On a device that is **already signed in** as that user, enter the code in Jellyfin's Quick Connect page and approve it.
3. The new device is signed in. If *Email the user on every Quick Connect sign-in* is on, the user receives an email with the device, app, approving IP and time.

Enrolling a user revokes all of that user's older sessions, so every session that can approve has passed 2FA or come from the LAN/Tailscale. If you turn *Allow Quick Connect for enrolled users* off, Quick Connect sign-ins of enrolled users are revoked immediately after approval.

## Code reuse (Seerr, Neptune)

Some apps pass the credentials you typed on to another service. [Neptune](https://docs.neptuneplayer.com/getting-started/setup/seerr#signing-in), for example, signs you in to Seerr with the user name and password field you used for Jellyfin, and Seerr then signs in to Jellyfin with them. Seerr uses its own device id, its own app name (`Seerr`) and its own IP, so without reuse that sign-in fails because Neptune already used the code (answered with 403, not counted as a failed sign-in).

To enable reuse, on the plugin page under **Code reuse**:

1. Set **Additional sign-ins per code** to `1` (or more; maximum 10).
2. Keep or adjust **Reuse window after the first use** (default 5 minutes).
3. Keep `Seerr,Jellyseerr` in **Apps allowed to reuse a code**, or list the app names your app sends.
4. Strongly recommended: enter the Seerr host's IP in **Only from these addresses**.
5. Click **Save settings**. The status page shows a warning while reuse is on, more strongly without an address list.

How it behaves:

- After a code was used successfully, it can be used that many more times within the window, **only by the same user** and only by apps whose name is listed (case-insensitive), from any of their devices.
- Password + code is always accepted for reuse; the code alone only if *Allow the code alone as the second step* is on (Neptune passes on exactly what you typed, so with code-only sign-in Seerr receives only the code).
- Reuse is not bound to an IP. *Only from these addresses* is checked against the real TCP connection to Jellyfin, not against forwarded headers. Seerr sends `X-Forwarded-For` with the user's IP first and retries without it, so a Seerr host on the LAN that connects directly is seen with its own address.
- Wrong codes from listed apps count like wrong codes (the grant ends after *Wrong code entries per code*) and for the failure throttle. A password change, unenrolling or deleting the user ends the grant.
- The code email mentions the reuse.

**Trade-off:** app names are chosen by the client. Without an address list, whoever knows a code that was just used (for example by reading the mailbox) can use it again within the window by calling their app "Seerr", without the password if code-only sign-in is on.

Notes:

- If Seerr reaches Jellyfin **directly from a LAN/Tailscale address**, its retry without `X-Forwarded-For` is a normal direct sign-in: password + code is accepted like the password alone, and a code alone only through reuse.
- If Neptune signs in to Seerr only later (after the reuse window), reuse does not help; those attempts are answered with 403. In that case sign in to Seerr with Quick Connect (Seerr 3.4+).

## API keys, scripts and other sign-in paths

- **API keys** keep working as normal; they are not sign-ins. Use them for scripts. They bypass 2FA by design, so treat them like root passwords.
- **Password changes** by a signed-in user (confirming the current password) need the password only, throttled per user.
- Only `POST /Users/AuthenticateByName` and the obsolete `POST /Users/{id}/Authenticate` can sign in an enrolled user with a password. Other callers that ask Jellyfin to check an enrolled user's password are refused.
- **Other token paths:** any new token for an enrolled user that did not pass Jelly2FA and is not Quick Connect (for example an SSO plugin that signs users in directly) is revoked immediately, and the administrator is alerted.

## Abuse limits

All limits are configurable, see [Limits](configuration.md#limits). Defaults:

- Code emails are sent only after a correct password, with a 60 s resend cooldown per device and app, at most 5 per user per hour and 50 per hour for the server.
- Failed sign-ins are throttled per IP (10 per 5 minutes; IPv6 per /64) and, for sign-ins through the proxy, per user (10 per 15 minutes). Throttled attempts get 403. Administrators can see and clear the counters on the plugin page (**Failed sign-in throttles**). With [Let CrowdSec make the IP bans](troubleshooting.md#let-crowdsec-make-the-ip-bans), CrowdSec bans IPs instead and Jelly2FA keeps only a high per-IP backstop.
- Counted as failures: wrong passwords, unknown codes, and wrong codes after a correct password. **Not** counted: a stale (recently issued) code, or a correct password without a pending code.
- Direct LAN/Tailscale sign-ins are throttled per IP only, so failures from the internet cannot lock a user out of the LAN.
- If a code email cannot be queued, that code is dropped (earlier codes stay valid).
- Jellyfin's own lockout is switched off for enrolled users: a lockout disables the account (which also kills existing sessions), and anyone who knows a user name could trigger it.
