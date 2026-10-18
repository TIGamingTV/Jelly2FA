using System;
using System.Collections.Generic;
using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.Jelly2FA.Configuration;

/// <summary>
/// Plugin settings. Stored by Jellyfin as XML in the plugin configuration folder.
/// Secrets (the SMTP password) are NOT stored here; see <see cref="Services.SecretStore"/>.
/// </summary>
public class PluginConfiguration : BasePluginConfiguration
{
    // ---- SMTP ----

    /// <summary>Gets or sets the SMTP host. STARTTLS is always required.</summary>
    public string SmtpHost { get; set; } = string.Empty;

    /// <summary>Gets or sets the SMTP port (submission with STARTTLS, normally 587).</summary>
    public int SmtpPort { get; set; } = 587;

    /// <summary>Gets or sets the SMTP user name (empty = no SMTP authentication).</summary>
    public string SmtpUsername { get; set; } = string.Empty;

    /// <summary>Gets or sets the sender address.</summary>
    public string FromAddress { get; set; } = string.Empty;

    /// <summary>Gets or sets the sender display name.</summary>
    public string FromName { get; set; } = "Jellyfin Jelly2FA";

    /// <summary>Gets or sets the address that receives administrator alerts.</summary>
    public string AdminAlertEmail { get; set; } = string.Empty;

    /// <summary>Gets or sets the server name shown in emails.</summary>
    public string ServerDisplayName { get; set; } = "Jellyfin";

    /// <summary>Gets or sets the language of user emails ("en" or "de"; anything else falls back to English).</summary>
    public string EmailLanguage { get; set; } = "en";

    // ---- Network / origin ----

    /// <summary>
    /// Gets or sets extra reverse-proxy addresses (comma separated IPs or CIDRs).
    /// Jellyfin's own "Known proxies" are always included. Any login whose TCP peer is a proxy requires 2FA.
    /// </summary>
    public string ProxyAddresses { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets networks (comma separated CIDRs) whose direct connections may sign in with the password only.
    /// Defaults to the Tailscale address ranges.
    /// </summary>
    public string TrustedDirectNetworks { get; set; } = "100.64.0.0/10,fd7a:115c:a1e0::/48";

    /// <summary>Gets or sets a value indicating whether Jellyfin's LAN networks count as trusted for direct connections.</summary>
    public bool TrustJellyfinLocalNetworks { get; set; } = true;

    /// <summary>Gets or sets a value indicating whether loopback (127.0.0.1/::1) direct connections are trusted. Off by default because a reverse proxy on the same host connects from loopback.</summary>
    public bool TrustLoopback { get; set; }

    // ---- Quick Connect ----

    /// <summary>Gets or sets a value indicating whether Quick Connect sign-ins of enrolled users are allowed.</summary>
    public bool AllowQuickConnect { get; set; } = true;

    /// <summary>Gets or sets a value indicating whether the user is emailed about each Quick Connect sign-in.</summary>
    public bool NotifyOnQuickConnect { get; set; } = true;

    // ---- Code / throttling policy ----

    /// <summary>
    /// Gets or sets a value indicating whether the second sign-in step may contain only the emailed code
    /// (instead of password + code). The code is only issued after a correct password, stays bound to
    /// user/device/client and is additionally bound to the client IP that requested it. Off by default.
    /// </summary>
    public bool AllowCodeOnlySecondStep { get; set; }

    /// <summary>Gets or sets the code lifetime in minutes.</summary>
    public int CodeLifetimeMinutes { get; set; } = 10;

    /// <summary>Gets or sets the number of wrong code entries before a code is invalidated.</summary>
    public int MaxCodeAttempts { get; set; } = 5;

    /// <summary>Gets or sets the maximum number of simultaneously pending codes per user.</summary>
    public int MaxPendingPerUser { get; set; } = 3;

    /// <summary>Gets or sets the minimum delay between two code emails for the same device.</summary>
    public int ResendCooldownSeconds { get; set; } = 60;

    /// <summary>Gets or sets the maximum code emails per user per hour.</summary>
    public int MaxEmailsPerUserPerHour { get; set; } = 5;

    /// <summary>Gets or sets the maximum code emails per hour for the whole server.</summary>
    public int MaxEmailsPerHourGlobal { get; set; } = 50;

    /// <summary>Gets or sets the failed sign-ins allowed per client IP within <see cref="IpWindowMinutes"/>.</summary>
    public int MaxFailuresPerIp { get; set; } = 10;

    /// <summary>Gets or sets the client IP failure window.</summary>
    public int IpWindowMinutes { get; set; } = 5;

    /// <summary>Gets or sets the failed sign-ins allowed per user within <see cref="UserWindowMinutes"/>.</summary>
    public int MaxFailuresPerUser { get; set; } = 10;

    /// <summary>Gets or sets the user failure window.</summary>
    public int UserWindowMinutes { get; set; } = 15;

    // ---- Enrollment ----

    /// <summary>
    /// Gets or sets the enrolled users. Managed through the plugin page / API, not by hand.
    /// Never null: null, null entries and duplicate user ids (e.g. from a hand-edited or API-posted
    /// configuration) are normalised away; the first entry per user wins.
    /// </summary>
    public EnrolledUser[] Users
    {
        get => _users;
        set => _users = Normalize(value);
    }

    private EnrolledUser[] _users = Array.Empty<EnrolledUser>();

    private static EnrolledUser[] Normalize(EnrolledUser[]? value)
    {
        if (value is null || value.Length == 0)
        {
            return Array.Empty<EnrolledUser>();
        }

        var seen = new HashSet<Guid>();
        var result = new List<EnrolledUser>(value.Length);
        foreach (var user in value)
        {
            if (user is not null && user.UserId != Guid.Empty && seen.Add(user.UserId))
            {
                result.Add(user);
            }
        }

        return result.ToArray();
    }
}
