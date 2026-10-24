using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Jellyfin.Plugin.Jelly2FA.Configuration;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>A failed sign-in counter (per client IP or per user) as shown on the plugin page.</summary>
public sealed class ThrottleEntryDto
{
    /// <summary>Gets or sets the limiter key (pass it to the clear endpoint).</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Gets or sets the kind: "ip" or "user".</summary>
    public string Kind { get; set; } = string.Empty;

    /// <summary>Gets or sets the IP (IPv6: the /64) or the user name.</summary>
    public string Subject { get; set; } = string.Empty;

    /// <summary>Gets or sets the failures within the window.</summary>
    public int Failures { get; set; }

    /// <summary>Gets or sets the limit that applies.</summary>
    public int Limit { get; set; }

    /// <summary>Gets or sets a value indicating whether sign-ins are blocked now.</summary>
    public bool Blocked { get; set; }

    /// <summary>Gets or sets when the block ends (null when not blocked).</summary>
    public DateTimeOffset? BlockedUntil { get; set; }

    /// <summary>Gets or sets when the counter is empty again.</summary>
    public DateTimeOffset ExpiresAt { get; set; }
}

/// <summary>Lists and clears the failed sign-in throttles (per client IP and per user).</summary>
public sealed class ThrottleService
{
    /// <summary>Key prefix of the per-IP counters.</summary>
    public const string IpPrefix = "fail:ip:";

    /// <summary>Key prefix of the per-user counters (user id in "N" format).</summary>
    public const string UserPrefix = "fail:user:";

    private readonly RateLimiter _limiter;
    private readonly IConfigProvider _config;
    private readonly IUserManager _userManager;
    private readonly ILogger<ThrottleService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ThrottleService"/> class.
    /// </summary>
    /// <param name="limiter">Rate limiter.</param>
    /// <param name="config">Config.</param>
    /// <param name="userManager">User manager (names of throttled users).</param>
    /// <param name="logger">Logger.</param>
    public ThrottleService(RateLimiter limiter, IConfigProvider config, IUserManager userManager, ILogger<ThrottleService> logger)
    {
        _limiter = limiter;
        _config = config;
        _userManager = userManager;
        _logger = logger;
    }

    /// <summary>Backstop used when <see cref="PluginConfiguration.CrowdSecIpBackstop"/> is not set (0 or negative).</summary>
    public const int DefaultCrowdSecIpBackstop = 100;

    /// <summary>The failed sign-ins per client IP that Jelly2FA blocks at (the backstop when CrowdSec makes the bans).</summary>
    /// <param name="config">Config.</param>
    /// <returns>The limit (at least 1).</returns>
    public static int IpLimit(PluginConfiguration config)
    {
        if (config.DelegateIpBansToCrowdSec)
        {
            // An empty field must not turn the safety net into a ban after the first failure.
            return config.CrowdSecIpBackstop > 0 ? config.CrowdSecIpBackstop : DefaultCrowdSecIpBackstop;
        }

        return Math.Max(1, config.MaxFailuresPerIp);
    }

    /// <summary>The per-IP window.</summary>
    /// <param name="config">Config.</param>
    /// <returns>The window.</returns>
    public static TimeSpan IpWindow(PluginConfiguration config) => TimeSpan.FromMinutes(Math.Max(1, config.IpWindowMinutes));

    /// <summary>The per-user limit.</summary>
    /// <param name="config">Config.</param>
    /// <returns>The limit (at least 1).</returns>
    public static int UserLimit(PluginConfiguration config) => Math.Max(1, config.MaxFailuresPerUser);

    /// <summary>The per-user window.</summary>
    /// <param name="config">Config.</param>
    /// <returns>The window.</returns>
    public static TimeSpan UserWindow(PluginConfiguration config) => TimeSpan.FromMinutes(Math.Max(1, config.UserWindowMinutes));

    /// <summary>The key of a user's counter.</summary>
    /// <param name="userId">User id.</param>
    /// <returns>The key.</returns>
    public static string UserKey(Guid userId) => UserPrefix + userId.ToString("N", CultureInfo.InvariantCulture);

    /// <summary>Whether the key is one of the failed sign-in counters (and nothing else, e.g. email budgets).</summary>
    /// <param name="key">Key.</param>
    /// <returns>True if it may be cleared.</returns>
    public static bool IsThrottleKey(string? key) =>
        !string.IsNullOrEmpty(key)
        && ((key.StartsWith(IpPrefix, StringComparison.Ordinal) && key.Length > IpPrefix.Length)
            || (key.StartsWith(UserPrefix, StringComparison.Ordinal) && key.Length > UserPrefix.Length));

    /// <summary>Lists the active counters, blocked ones first.</summary>
    /// <returns>The entries.</returns>
    public IReadOnlyList<ThrottleEntryDto> List()
    {
        var config = _config.Current;
        var result = new List<ThrottleEntryDto>();

        var ipWindow = IpWindow(config);
        var ipLimit = IpLimit(config);
        foreach (var (key, events) in _limiter.Snapshot(IpPrefix, ipWindow))
        {
            result.Add(Entry(key, "ip", key[IpPrefix.Length..], events, ipLimit, ipWindow));
        }

        var userWindow = UserWindow(config);
        var userLimit = UserLimit(config);
        foreach (var (key, events) in _limiter.Snapshot(UserPrefix, userWindow))
        {
            result.Add(Entry(key, "user", UserName(key[UserPrefix.Length..]), events, userLimit, userWindow));
        }

        return result
            .OrderByDescending(e => e.Blocked)
            .ThenByDescending(e => e.Failures)
            .ThenBy(e => e.Subject, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>Clears a counter, which ends its block at once.</summary>
    /// <param name="key">Key from <see cref="List"/>.</param>
    /// <returns>False if the key is not a failed sign-in counter.</returns>
    public bool Clear(string? key)
    {
        if (!IsThrottleKey(key))
        {
            return false;
        }

        _limiter.Reset(key!);
        _logger.LogInformation("Jelly2FA: failed sign-in counter {Key} cleared by an administrator", EmailAddress.SingleLine(key));
        return true;
    }

    private static ThrottleEntryDto Entry(string key, string kind, string subject, DateTimeOffset[] events, int limit, TimeSpan window)
    {
        // Blocked while at least `limit` failures are in the window: it ends when the (count - limit + 1)th oldest leaves it.
        var blocked = events.Length >= limit;
        return new ThrottleEntryDto
        {
            Key = key,
            Kind = kind,
            Subject = subject,
            Failures = events.Length,
            Limit = limit,
            Blocked = blocked,
            BlockedUntil = blocked ? events[events.Length - limit] + window : null,
            ExpiresAt = events[^1] + window,
        };
    }

    private string UserName(string id)
    {
        if (Guid.TryParseExact(id, "N", out var userId))
        {
            var user = _userManager.GetUserById(userId);
            if (user is not null)
            {
                return user.Username;
            }
        }

        return "(unknown user " + id + ")";
    }
}
