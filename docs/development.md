# Development

## Layout

| Path | Contents |
|---|---|
| `src/Jellyfin.Plugin.Jelly2FA/` | The plugin (authentication provider, API controller, configuration page, services). |
| `tests/Jellyfin.Plugin.Jelly2FA.Tests/` | Unit tests. |
| `tests/e2e/` | End-to-end tests against a real, throwaway Jellyfin server. |
| `tools/` | Recovery script, watchdog script and its systemd units. |
| `docs/` | User documentation and the nginx example. |
| `manifest.json` | The Jellyfin plugin repository manifest (updated by the release workflow). |
| `build.yaml` | Plugin metadata in Jellyfin's build format (kept in sync by hand). |

## Build

Requires the .NET 10 SDK (see `global.json`).

```sh
dotnet build
dotnet publish src/Jellyfin.Plugin.Jelly2FA -c Release -o out/Jelly2FA_<version>
```

## Tests

```sh
dotnet test                 # unit tests
tests/e2e/run_e2e.sh        # end-to-end tests (see the header of the script)
```

On systems without ICU, run `dotnet` with `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`.

The end-to-end suite runs against a real Jellyfin 12.2 server, with `127.0.0.1` playing nginx and a local STARTTLS SMTP sink. It needs the extracted Jellyfin 12.2 tarball, the .NET SDK, python3, sqlite3, openssl and curl; the script header documents its environment variables (`J2FA_E2E_DIR`, `J2FA_E2E_LAN_URL`, `J2FA_E2E_LAN_NET`, `J2FA_E2E_BIND`). **Never run it against a production server.**

It covers, among others: no token or device on 403; the code flow; code replay, device binding and races; LAN, Tailscale-style and untrusted direct connections; spoofed forwarding headers; admins via the proxy; the legacy and lowercase routes; API keys; Quick Connect (allowed, notified, disabled); fail closed without a proxy; password change; throttling without account lockout; the code-only option; 403 instead of 401 after a correct password; code reuse; the email time zone; CrowdSec mode (denied lines, backstop) and clearing throttles; Disable/Enable/Uninstall/reinstall; the plugin failing to load; and `tools/jelly2fa-recover.sh`.

## Releasing

1. Bump the version (format `1.2.3.4`) and changelog in `src/Jellyfin.Plugin.Jelly2FA/meta.json`. Keep `build.yaml` and the version properties in `Jellyfin.Plugin.Jelly2FA.csproj` in sync.
2. Commit, then tag and push, for example:

   ```sh
   git tag v0.0.7.0 && git push origin v0.0.7.0
   ```

The `release` workflow (`.github/workflows/release.yml`) runs the tests, builds `jelly2fa_<version>.zip`, attaches it to a GitHub release, and adds the version (with its MD5 checksum) to `manifest.json` on `main`. Jellyfin reads that file as the plugin repository. If `main` is branch-protected, allow `github-actions[bot]` to push to it. The workflow can also re-release an existing tag via *workflow_dispatch*.

The `build` workflow runs the tests and uploads the package as an artifact on every push to `main` and every pull request.

## Constraints

- **Never rename** `TwoFactorAuthenticationProvider` or its namespace: its full type name is stored as the authentication provider id of every enrolled user (and is used by `tools/jelly2fa-recover.sh`).
- Origin capture relies on ASP.NET Core's `IStartupFilter` to run before Jellyfin's forwarded-headers middleware. If that ever stops running, every sign-in requires 2FA (fail closed) and the status page warns.
