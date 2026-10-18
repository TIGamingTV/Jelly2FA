using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>Status of the plugin.</summary>
public sealed class StatusReport
{
    /// <summary>Gets or sets a value indicating whether no critical problem exists.</summary>
    public bool Healthy { get; set; }

    /// <summary>Gets or sets critical problems (2FA not enforced as intended, or remote sign-in broken).</summary>
    public List<string> Problems { get; set; } = new();

    /// <summary>Gets or sets warnings.</summary>
    public List<string> Warnings { get; set; } = new();

    /// <summary>Gets or sets a value indicating whether origin capture middleware runs.</summary>
    public bool OriginCaptureActive { get; set; }

    /// <summary>Gets or sets a value indicating whether a reverse proxy address is known.</summary>
    public bool ProxyConfigured { get; set; }

    /// <summary>Gets or sets Jellyfin's known proxies.</summary>
    public string[] JellyfinKnownProxies { get; set; } = Array.Empty<string>();

    /// <summary>Gets or sets a value indicating whether SMTP is configured.</summary>
    public bool SmtpConfigured { get; set; }

    /// <summary>Gets or sets the last SMTP error.</summary>
    public string? LastSmtpError { get; set; }

    /// <summary>Gets or sets the last SMTP failure time.</summary>
    public DateTimeOffset? LastSmtpFailure { get; set; }

    /// <summary>Gets or sets a value indicating whether Quick Connect is enabled server-wide.</summary>
    public bool QuickConnectEnabled { get; set; }

    /// <summary>Gets or sets the number of enrolled users.</summary>
    public int EnrolledUsers { get; set; }

    /// <summary>Gets or sets a value indicating whether the plugin was disabled and users were handed back (2FA off).</summary>
    public bool Disabled { get; set; }
}

/// <summary>Computes plugin health.</summary>
public sealed class HealthService
{
    private readonly IUserManager _userManager;
    private readonly IServerConfigurationManager _serverConfig;
    private readonly IOriginClassifier _origin;
    private readonly IEmailSender _email;
    private readonly HealthState _state;
    private readonly IConfigProvider _config;
    private readonly SuspensionStore _suspension;

    /// <summary>
    /// Initializes a new instance of the <see cref="HealthService"/> class.
    /// </summary>
    /// <param name="userManager">User manager.</param>
    /// <param name="serverConfig">Server config.</param>
    /// <param name="origin">Origin classifier.</param>
    /// <param name="email">Email sender.</param>
    /// <param name="state">Health state.</param>
    /// <param name="config">Config.</param>
    /// <param name="suspension">Suspension store (plugin disabled).</param>
    public HealthService(IUserManager userManager, IServerConfigurationManager serverConfig, IOriginClassifier origin, IEmailSender email, HealthState state, IConfigProvider config, SuspensionStore suspension)
    {
        _suspension = suspension;
        _userManager = userManager;
        _serverConfig = serverConfig;
        _origin = origin;
        _email = email;
        _state = state;
        _config = config;
    }

    /// <summary>Builds the status report.</summary>
    /// <returns>The report.</returns>
    public StatusReport GetStatus()
    {
        var config = _config.Current;
        var network = _serverConfig.GetNetworkConfiguration();
        var r = new StatusReport
        {
            OriginCaptureActive = OriginCaptureMiddleware.IsActive,
            ProxyConfigured = _origin.ProxyConfigured,
            JellyfinKnownProxies = network.KnownProxies ?? Array.Empty<string>(),
            SmtpConfigured = _email.IsConfigured,
            LastSmtpError = _state.LastSmtpError,
            LastSmtpFailure = _state.LastSmtpFailure,
            QuickConnectEnabled = _serverConfig.Configuration.QuickConnectAvailable,
            EnrolledUsers = config.Users.Length,
            Disabled = _suspension.IsSuspended,
        };

        var suspended = r.Disabled ? _suspension.Load().ToHashSet() : new HashSet<Guid>();
        if (r.Disabled)
        {
            r.Warnings.Add($"Jelly2FA is disabled: {suspended.Count} user(s) sign in with the password only, also remotely. Enable the plugin to switch them back to two-factor sign-in.");
        }

        if (!r.OriginCaptureActive)
        {
            r.Warnings.Add("Origin capture middleware has not seen a request yet (if this persists, every sign-in requires 2FA).");
        }

        if (!r.ProxyConfigured)
        {
            r.Problems.Add("No reverse proxy address configured (Jellyfin 'Known proxies' or plugin 'Proxy addresses'). Fail-closed: LAN/Tailscale sign-ins also require 2FA.");
        }

        if (r.JellyfinKnownProxies.Length == 0)
        {
            if (config.AllowCodeOnlySecondStep)
            {
                r.Problems.Add("'Allow the code alone as the second step' is on, but Jellyfin 'Known proxies' is empty: every remote client has the proxy's IP, so the IP binding of codes protects nothing. Set Known proxies or turn the option off.");
            }
            else
            {
                r.Warnings.Add("Jellyfin 'Known proxies' is empty: Jellyfin sees every proxied client as the proxy IP (remote-access restrictions, logs and per-IP throttling are inaccurate).");
            }
        }

        if (!r.SmtpConfigured)
        {
            r.Problems.Add("SMTP is not configured: remote sign-ins of enrolled users are impossible.");
        }
        else if (_state.SmtpRecentlyFailing)
        {
            r.Problems.Add("Sending email failed recently: " + (_state.LastSmtpError ?? "unknown error"));
        }

        if (_serverConfig.Configuration.EnableLegacyAuthorization)
        {
            r.Warnings.Add("Legacy authorization is enabled (tokens accepted in more places). Disable it unless a client needs it.");
        }

        if (!EmailAddress.IsValid(config.AdminAlertEmail))
        {
            r.Warnings.Add("No administrator alert email configured.");
        }

        var enrolled = config.Users.GroupBy(u => u.UserId).ToDictionary(g => g.Key, g => g.First());
        foreach (var user in _userManager.GetUsers())
        {
            var onProvider = string.Equals(user.AuthenticationProviderId, ProviderIds.Jelly2Fa, StringComparison.Ordinal);
            var isEnrolled = enrolled.TryGetValue(user.Id, out var entry);
            if (isEnrolled && !onProvider && suspended.Contains(user.Id))
            {
                continue; // reported once above
            }

            if (isEnrolled && !onProvider)
            {
                r.Problems.Add($"User '{user.Username}' is enrolled but uses another authentication provider (NO 2FA). Re-enroll the user.");
            }
            else if (!isEnrolled && onProvider)
            {
                r.Problems.Add($"User '{user.Username}' uses the Jelly2FA provider but is not enrolled (remote sign-in refused).");
            }
            else if (isEnrolled && !EmailAddress.IsValid(entry!.Email))
            {
                r.Problems.Add($"User '{user.Username}' has an invalid email address.");
            }
            else if (!isEnrolled)
            {
                r.Warnings.Add($"User '{user.Username}' is not enrolled (password-only sign-in everywhere).");
            }
        }

        r.Healthy = r.Problems.Count == 0;
        return r;
    }
}

/// <summary>
/// Periodic self-check: alerts the administrator (max once per hour per problem set) while loaded.
/// Detecting that the plugin did NOT load requires the external watchdog (tools/jelly2fa-watchdog.sh).
/// </summary>
public sealed class SelfCheckService : BackgroundService
{
    private readonly HealthService _health;
    private readonly INotificationService _notifications;
    private readonly ILogger<SelfCheckService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SelfCheckService"/> class.
    /// </summary>
    /// <param name="health">Health service.</param>
    /// <param name="notifications">Notifications.</param>
    /// <param name="logger">Logger.</param>
    public SelfCheckService(HealthService health, INotificationService notifications, ILogger<SelfCheckService> logger)
    {
        _health = health;
        _notifications = notifications;
        _logger = logger;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken).ConfigureAwait(false);
            using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
            do
            {
                try
                {
                    var status = _health.GetStatus();
                    foreach (var warning in status.Warnings)
                    {
                        _logger.LogWarning("Jelly2FA self-check: {Warning}", warning);
                    }

                    if (!status.Healthy)
                    {
                        _notifications.AlertAdmin("selfcheck", "self-check found problems", string.Join(Environment.NewLine, status.Problems));
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "Jelly2FA self-check failed");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // shutting down
        }
    }
}
