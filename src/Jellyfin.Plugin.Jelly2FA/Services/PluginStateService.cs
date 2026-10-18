using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Makes "Disable" in Dashboard &gt; Plugins behave like for any other plugin: sign-in returns to normal
/// immediately (and stays normal after the restart), and "Enable" brings 2FA back.
/// Jellyfin has no disable callback for plugins, so the successful admin API call is observed by
/// <see cref="PluginStateMiddleware"/>.
/// </summary>
public sealed class PluginStateService
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly IConfigProvider _config;
    private readonly ChallengeStore _challenges;
    private readonly SuspensionStore _store;
    private readonly INotificationService _notifications;
    private readonly ILogger<PluginStateService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginStateService"/> class.
    /// </summary>
    /// <param name="userManager">User manager.</param>
    /// <param name="sessionManager">Session manager.</param>
    /// <param name="config">Config.</param>
    /// <param name="challenges">Code store.</param>
    /// <param name="store">Suspension store.</param>
    /// <param name="notifications">Notifications.</param>
    /// <param name="logger">Logger.</param>
    public PluginStateService(
        IUserManager userManager,
        ISessionManager sessionManager,
        IConfigProvider config,
        ChallengeStore challenges,
        SuspensionStore store,
        INotificationService notifications,
        ILogger<PluginStateService> logger)
    {
        _userManager = userManager;
        _sessionManager = sessionManager;
        _config = config;
        _challenges = challenges;
        _store = store;
        _notifications = notifications;
        _logger = logger;
    }

    /// <summary>
    /// The plugin was disabled: hand every user on the Jelly2FA provider back to Jellyfin's default provider
    /// and remember them for <see cref="ReactivateAsync"/>.
    /// </summary>
    /// <returns>The number of users handed back.</returns>
    public async Task<int> SuspendAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var onProvider = _userManager.GetUsers().Where(ProviderSwitch.IsOnJelly2Fa).ToList();

            // Remember first (merged with an earlier, not yet re-activated suspension), then switch: if switching
            // fails half-way, everybody already switched is still re-activated later.
            _store.Save(_store.Load().Concat(onProvider.Select(u => u.Id)));

            var switched = 0;
            foreach (var user in onProvider)
            {
                if (await ProviderSwitch.ToDefaultAsync(_userManager, user).ConfigureAwait(false))
                {
                    switched++;
                }

                _challenges.RemoveUser(user.Id);
            }

            _logger.LogWarning("Jelly2FA disabled: {Count} user(s) handed back to password-only sign-in", switched);
            _notifications.AlertAdmin(
                "plugin-disabled",
                "plugin disabled, 2FA is off",
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Jelly2FA was disabled. {switched} user(s) now sign in with the password only, also remotely. When the plugin is enabled again, they are switched back to two-factor sign-in and their sessions are revoked."));
            return switched;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// The plugin is enabled again (Enable call, or the first start after it): switch the remembered users back
    /// to Jelly2FA and revoke their sessions, because those may have been created with the password only.
    /// </summary>
    /// <param name="keepToken">Token of the administrator performing the action (kept), or null to revoke all.</param>
    /// <returns>The number of users re-activated.</returns>
    public async Task<int> ReactivateAsync(string? keepToken)
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!_store.IsSuspended)
            {
                return 0;
            }

            var config = _config.Current;
            var count = 0;
            var skipped = new List<string>();
            foreach (var id in _store.Load())
            {
                var user = _userManager.GetUserById(id);
                if (user is null || config.FindUser(id) is null)
                {
                    continue; // deleted or unenrolled meanwhile
                }

                if (ProviderSwitch.IsOnJelly2Fa(user))
                {
                    continue;
                }

                if (!ProviderSwitch.IsOnDefault(user))
                {
                    // An administrator chose another provider meanwhile: respect it (the status page reports it).
                    skipped.Add(user.Username);
                    continue;
                }

                await ProviderSwitch.ToJelly2FaAsync(_userManager, user).ConfigureAwait(false);
                await _sessionManager.RevokeUserTokens(id, keepToken!).ConfigureAwait(false);
                _challenges.RemoveUser(id);
                count++;
            }

            _store.Clear();
            _logger.LogWarning("Jelly2FA enabled: {Count} user(s) switched back to two-factor sign-in; their sessions were revoked", count);
            var body = string.Create(
                CultureInfo.InvariantCulture,
                $"Jelly2FA was enabled again. {count} user(s) were switched back to two-factor sign-in and their existing sessions were revoked (they may have been created while 2FA was off).");
            if (skipped.Count > 0)
            {
                body += " Not switched because another authentication provider was chosen meanwhile: " + string.Join(", ", skipped) + ".";
            }

            _notifications.AlertAdmin("plugin-enabled", "plugin enabled, 2FA is on again", body);
            return count;
        }
        finally
        {
            _gate.Release();
        }
    }
}

/// <summary>
/// Watches the admin API for Disable/Enable of this plugin (the running version) and reacts after Jellyfin
/// answered with success. Runs first in the pipeline, so the path still contains a configured base URL.
/// </summary>
public sealed partial class PluginStateMiddleware
{
    private const string TokenClaim = "Jellyfin-Token";

    private readonly RequestDelegate _next;
    private readonly ILogger<PluginStateMiddleware> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginStateMiddleware"/> class.
    /// </summary>
    /// <param name="next">Next middleware.</param>
    /// <param name="logger">Logger.</param>
    public PluginStateMiddleware(RequestDelegate next, ILogger<PluginStateMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    /// <summary>What a request does to this plugin.</summary>
    public enum PluginAction
    {
        /// <summary>Nothing relevant.</summary>
        None,

        /// <summary>Disables this plugin.</summary>
        Disable,

        /// <summary>Enables this plugin.</summary>
        Enable,
    }

    /// <summary>Middleware entry point.</summary>
    /// <param name="context">HTTP context.</param>
    /// <param name="state">Plugin state service.</param>
    /// <returns>A task.</returns>
    public async Task InvokeAsync(HttpContext context, PluginStateService state)
    {
        var action = Classify(context.Request.Method, context.Request.Path.Value, Plugin.Instance?.Version);
        await _next(context).ConfigureAwait(false);

        if (action == PluginAction.None || context.Response.StatusCode is < 200 or > 299)
        {
            return;
        }

        try
        {
            if (action == PluginAction.Disable)
            {
                await state.SuspendAsync().ConfigureAwait(false);
            }
            else
            {
                await state.ReactivateAsync(context.User.FindFirst(TokenClaim)?.Value).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Jelly2FA: reacting to plugin {Action} failed", action);
        }
    }

    /// <summary>Classifies a request (pure, for tests).</summary>
    /// <param name="method">HTTP method.</param>
    /// <param name="path">Request path (may include the base URL).</param>
    /// <param name="runningVersion">Version of the running plugin.</param>
    /// <returns>The action.</returns>
    internal static PluginAction Classify(string method, string? path, Version? runningVersion)
    {
        if (!HttpMethods.IsPost(method) || string.IsNullOrEmpty(path) || runningVersion is null)
        {
            return PluginAction.None;
        }

        var match = StateRegex().Match(path);
        if (!match.Success
            || !Guid.TryParse(match.Groups["id"].Value, out var id)
            || id != Guid.Parse(Plugin.PluginGuid, CultureInfo.InvariantCulture)
            || !Version.TryParse(Uri.UnescapeDataString(match.Groups["version"].Value), out var version)
            || version != runningVersion)
        {
            return PluginAction.None;
        }

        return string.Equals(match.Groups["action"].Value, "Disable", StringComparison.OrdinalIgnoreCase)
            ? PluginAction.Disable
            : PluginAction.Enable;
    }

    // POST [base url]/Plugins/{pluginId}/{version}/Disable|Enable
    [GeneratedRegex(@"(?:^|/)Plugins/(?<id>[^/]+)/(?<version>[^/]+)/(?<action>Disable|Enable)/?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex StateRegex();
}

/// <summary>
/// First start after the plugin was enabled again (the usual "Enable, then restart" flow): re-activates the
/// remembered users before Jellyfin finishes starting. Retries in the background if Jellyfin is not ready yet.
/// </summary>
public sealed class ReactivationStartupService : IHostedService
{
    private readonly PluginStateService _state;
    private readonly SuspensionStore _store;
    private readonly ILogger<ReactivationStartupService> _logger;
    private readonly CancellationTokenSource _stopping = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="ReactivationStartupService"/> class.
    /// </summary>
    /// <param name="state">Plugin state service.</param>
    /// <param name="store">Suspension store.</param>
    /// <param name="logger">Logger.</param>
    public ReactivationStartupService(PluginStateService state, SuspensionStore store, ILogger<ReactivationStartupService> logger)
    {
        _state = state;
        _store = store;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_store.IsSuspended)
        {
            return;
        }

        if (await TryReactivate().ConfigureAwait(false))
        {
            return;
        }

        _ = Task.Run(RetryLoop, CancellationToken.None);
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken)
    {
        _stopping.Cancel();
        return Task.CompletedTask;
    }

    private async Task RetryLoop()
    {
        foreach (var seconds in new[] { 5, 15, 30, 60, 120, 300 })
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(seconds), _stopping.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (await TryReactivate().ConfigureAwait(false))
            {
                return;
            }
        }

        _logger.LogError("Jelly2FA: giving up re-activating users after the plugin was enabled; re-enroll them on the plugin page");
    }

    private async Task<bool> TryReactivate()
    {
        try
        {
            await _state.ReactivateAsync(null).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Jelly2FA: re-activating users after the plugin was enabled failed (will retry)");
            return false;
        }
    }
}
