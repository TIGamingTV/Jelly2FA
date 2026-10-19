using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Builds and queues user emails and administrator alerts.
/// </summary>
public interface INotificationService
{
    /// <summary>Queues a sign-in code email.</summary>
    /// <param name="email">Recipient.</param>
    /// <param name="userName">User name.</param>
    /// <param name="code">The code.</param>
    /// <param name="device">Device name.</param>
    /// <param name="client">Client name.</param>
    /// <param name="clientIp">Client IP as seen by Jellyfin.</param>
    /// <param name="lifetimeMinutes">Validity.</param>
    /// <returns>True if queued.</returns>
    bool SendCode(string email, string userName, string code, string? device, string? client, string? clientIp, int lifetimeMinutes);

    /// <summary>Queues a "new sign-in through Quick Connect" notice.</summary>
    /// <param name="email">Recipient.</param>
    /// <param name="userName">User name.</param>
    /// <param name="device">Device name.</param>
    /// <param name="client">Client name.</param>
    /// <param name="approverIp">IP of the approving session.</param>
    void NotifyQuickConnect(string email, string userName, string? device, string? client, string? approverIp);

    /// <summary>Queues an administrator alert (at most one per key per hour).</summary>
    /// <param name="key">Throttle key.</param>
    /// <param name="subject">Subject.</param>
    /// <param name="body">Body.</param>
    void AlertAdmin(string key, string subject, string body);
}

/// <summary>
/// Default notification service. User emails are localised (English/German, see
/// <see cref="Configuration.PluginConfiguration.EmailLanguage"/>); administrator alerts stay in English.
/// </summary>
public sealed class NotificationService : INotificationService
{
    /// <summary>Maximum length of client-supplied text (device/app name) in user emails.</summary>
    internal const int MaxClientTextLength = 64;

    private readonly EmailQueue _queue;
    private readonly IConfigProvider _config;
    private readonly RateLimiter _limiter;
    private readonly TimeProvider _time;
    private readonly ILogger<NotificationService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="NotificationService"/> class.
    /// </summary>
    /// <param name="queue">Queue.</param>
    /// <param name="config">Config.</param>
    /// <param name="limiter">Rate limiter.</param>
    /// <param name="time">Time provider (current time and the server's local time zone).</param>
    /// <param name="logger">Logger.</param>
    public NotificationService(EmailQueue queue, IConfigProvider config, RateLimiter limiter, TimeProvider time, ILogger<NotificationService> logger)
    {
        _queue = queue;
        _config = config;
        _limiter = limiter;
        _time = time;
        _logger = logger;
    }

    /// <summary>Gets the time zone used for user emails (configured override, else the server's zone).</summary>
    internal TimeZoneInfo EmailZone => ResolveTimeZone(_config.Current.EmailTimeZone, _time.LocalTimeZone, out _);

    /// <inheritdoc />
    public bool SendCode(string email, string userName, string code, string? device, string? client, string? clientIp, int lifetimeMinutes)
    {
        var c = _config.Current;
        var message = BuildCodeEmail(
            c.EmailLanguage,
            c.AllowCodeOnlySecondStep,
            c.ServerDisplayName,
            email,
            userName,
            code,
            device,
            client,
            clientIp,
            lifetimeMinutes,
            _time.GetUtcNow(),
            EmailZone,
            ReuseInfo.From(c));
        return _queue.Enqueue(message);
    }

    /// <inheritdoc />
    public void NotifyQuickConnect(string email, string userName, string? device, string? client, string? approverIp)
    {
        var c = _config.Current;
        _queue.Enqueue(BuildQuickConnectEmail(c.EmailLanguage, c.ServerDisplayName, email, userName, device, client, approverIp, _time.GetUtcNow(), EmailZone));
    }

    /// <inheritdoc />
    public void AlertAdmin(string key, string subject, string body)
    {
        _logger.LogWarning("Jelly2FA alert: {Subject}: {Body}", subject, body);
        var to = _config.Current.AdminAlertEmail;
        if (!EmailAddress.IsValid(to))
        {
            return;
        }

        if (!_limiter.TryAcquire("alert:" + key, 1, TimeSpan.FromHours(1)))
        {
            return;
        }

        var server = EmailAddress.SingleLine(_config.Current.ServerDisplayName);
        _queue.Enqueue(new EmailMessage(to, $"[Jelly2FA] {server}: {subject}", body + Environment.NewLine));
    }

    /// <summary>Resolves the time zone for user emails.</summary>
    /// <param name="id">Configured IANA time zone id (e.g. "Europe/Berlin"); empty = <paramref name="serverZone"/>.</param>
    /// <param name="serverZone">The server's local time zone.</param>
    /// <param name="invalid">True if <paramref name="id"/> is set but unknown (the server zone is used then).</param>
    /// <returns>The time zone.</returns>
    internal static TimeZoneInfo ResolveTimeZone(string? id, TimeZoneInfo serverZone, out bool invalid)
    {
        invalid = false;
        var trimmed = id?.Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            return serverZone;
        }

        if (TimeZoneInfo.TryFindSystemTimeZoneById(trimmed, out var zone))
        {
            return zone;
        }

        invalid = true;
        return serverZone;
    }

    /// <summary>Formats a time for emails, e.g. "2026-10-19 14:05 Europe/Berlin (UTC+02:00)" or "2026-10-19 12:05 UTC".</summary>
    /// <param name="now">The instant.</param>
    /// <param name="zone">Time zone (null = UTC).</param>
    /// <returns>The text.</returns>
    internal static string FormatTime(DateTimeOffset now, TimeZoneInfo? zone)
    {
        zone ??= TimeZoneInfo.Utc;
        var local = TimeZoneInfo.ConvertTime(now, zone);
        var stamp = local.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        if (IsUtc(zone))
        {
            return stamp + " UTC";
        }

        var offset = local.Offset;
        var utc = "UTC" + (offset < TimeSpan.Zero ? "-" : "+") + offset.Duration().ToString(@"hh\:mm", CultureInfo.InvariantCulture);
        var name = EmailAddress.SingleLine(zone.Id);
        return name.Length == 0 || string.Equals(name, "Local", StringComparison.OrdinalIgnoreCase)
            ? $"{stamp} ({utc})"
            : $"{stamp} {name} ({utc})";
    }

    private static bool IsUtc(TimeZoneInfo zone)
        => ReferenceEquals(zone, TimeZoneInfo.Utc)
           || (zone.BaseUtcOffset == TimeSpan.Zero
               && !zone.SupportsDaylightSavingTime
               && zone.Id is "UTC" or "Etc/UTC" or "Etc/UCT" or "UCT" or "Universal" or "Etc/Universal" or "Zulu" or "Etc/Zulu" or "GMT" or "Etc/GMT" or "Coordinated Universal Time");

    /// <summary>Builds the sign-in code email (plain text + HTML with the code highlighted).</summary>
    /// <param name="language">Language code ("en", "de"; others fall back to English).</param>
    /// <param name="codeOnly">Whether the second step takes the code alone.</param>
    /// <param name="serverName">Server display name.</param>
    /// <param name="email">Recipient.</param>
    /// <param name="userName">User name.</param>
    /// <param name="code">The code.</param>
    /// <param name="device">Device name.</param>
    /// <param name="client">Client name.</param>
    /// <param name="clientIp">Client IP.</param>
    /// <param name="lifetimeMinutes">Validity.</param>
    /// <param name="now">Current time.</param>
    /// <param name="zone">Time zone of the time shown (null = UTC).</param>
    /// <param name="reuse">Code reuse settings (null = off).</param>
    /// <returns>The message.</returns>
    internal static EmailMessage BuildCodeEmail(
        string? language,
        bool codeOnly,
        string? serverName,
        string email,
        string userName,
        string code,
        string? device,
        string? client,
        string? clientIp,
        int lifetimeMinutes,
        DateTimeOffset now,
        TimeZoneInfo? zone = null,
        ReuseInfo? reuse = null)
    {
        var t = Texts.For(language);
        var server = EmailAddress.SingleLine(serverName);
        var user = Clean(userName, t);
        var time = FormatTime(now, zone);
        var howTo = codeOnly ? t.HowToCodeOnly : t.HowToPasswordPlusCode;
        var example = codeOnly ? null : t.ExamplePassword + code;
        var validity = string.Format(CultureInfo.InvariantCulture, t.Validity, lifetimeMinutes);
        if (reuse is { Count: > 0 } r && r.Clients.Count > 0)
        {
            validity += " " + string.Format(
                CultureInfo.InvariantCulture,
                t.Reuse,
                r.Count,
                r.Minutes,
                string.Join(", ", r.Clients.Select(EmailAddress.SingleLine)));
        }
        var details = new (string Label, string Value)[]
        {
            (t.Device, Client(device, t)),
            (t.App, Client(client, t)),
            (t.Ip, Client(clientIp, t)),
            (t.Time, time),
        };

        var text = new StringBuilder()
            .AppendLine(string.Format(CultureInfo.InvariantCulture, t.Greeting, user))
            .AppendLine()
            .AppendLine(string.Format(CultureInfo.InvariantCulture, t.CodeIntro, server))
            .AppendLine()
            .AppendLine(CultureInfo.InvariantCulture, $"    {code}")
            .AppendLine()
            .AppendLine(howTo);
        if (example is not null)
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"{t.ExampleLabel} {example}");
        }

        text.AppendLine().AppendLine(validity).AppendLine();
        foreach (var (label, value) in details)
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"{(label + ":").PadRight(8)}{value}");
        }

        text.AppendLine().AppendLine(t.CodeWarning);

        var h = new StringBuilder()
            .Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head>")
            .Append("<body style=\"font-family:Arial,Helvetica,sans-serif;font-size:15px;color:#222;line-height:1.5;\">")
            .Append("<p>").Append(Html(string.Format(CultureInfo.InvariantCulture, t.Greeting, user))).Append("</p>")
            .Append("<p>").Append(Html(string.Format(CultureInfo.InvariantCulture, t.CodeIntro, server))).Append("</p>")
            .Append("<p style=\"margin:20px 0;\"><span style=\"display:inline-block;padding:12px 20px;background:#f1f3f5;border:1px solid #ced4da;border-radius:6px;")
            .Append("font-family:Consolas,'Courier New',monospace;font-size:30px;font-weight:bold;letter-spacing:4px;color:#000;\">")
            .Append(Html(code)).Append("</span></p>")
            .Append("<p>").Append(Html(howTo));
        if (example is not null)
        {
            h.Append("<br>").Append(Html(t.ExampleLabel)).Append(" <code>").Append(Html(t.ExamplePassword))
                .Append("<b>").Append(Html(code)).Append("</b></code>");
        }

        h.Append("</p><p>").Append(Html(validity)).Append("</p>")
            .Append("<table style=\"border-collapse:collapse;font-size:14px;\">");
        foreach (var (label, value) in details)
        {
            h.Append("<tr><td style=\"padding:2px 12px 2px 0;color:#666;\">").Append(Html(label))
                .Append("</td><td style=\"padding:2px 0;\">").Append(Html(value)).Append("</td></tr>");
        }

        h.Append("</table><p style=\"color:#b00020;\">").Append(Html(t.CodeWarning)).Append("</p></body></html>");

        return new EmailMessage(email, string.Format(CultureInfo.InvariantCulture, t.CodeSubject, server), text.ToString(), h.ToString());
    }

    /// <summary>Builds the Quick Connect notice.</summary>
    /// <param name="language">Language code.</param>
    /// <param name="serverName">Server display name.</param>
    /// <param name="email">Recipient.</param>
    /// <param name="userName">User name.</param>
    /// <param name="device">Device name.</param>
    /// <param name="client">Client name.</param>
    /// <param name="approverIp">Approver IP.</param>
    /// <param name="now">Current time.</param>
    /// <param name="zone">Time zone of the time shown (null = UTC).</param>
    /// <returns>The message.</returns>
    internal static EmailMessage BuildQuickConnectEmail(
        string? language,
        string? serverName,
        string email,
        string userName,
        string? device,
        string? client,
        string? approverIp,
        DateTimeOffset now,
        TimeZoneInfo? zone = null)
    {
        var t = Texts.For(language);
        var server = EmailAddress.SingleLine(serverName);
        var body = new StringBuilder()
            .AppendLine(string.Format(CultureInfo.InvariantCulture, t.Greeting, Clean(userName, t)))
            .AppendLine()
            .AppendLine(string.Format(CultureInfo.InvariantCulture, t.QcIntro, server))
            .AppendLine()
            .AppendLine(CultureInfo.InvariantCulture, $"{(t.Device + ":").PadRight(8)}{Client(device, t)}")
            .AppendLine(CultureInfo.InvariantCulture, $"{(t.App + ":").PadRight(8)}{Client(client, t)}")
            .AppendLine(CultureInfo.InvariantCulture, $"{t.ApprovedFromIp}: {Client(approverIp, t)}")
            .AppendLine(CultureInfo.InvariantCulture, $"{(t.Time + ":").PadRight(8)}{FormatTime(now, zone)}")
            .AppendLine()
            .AppendLine(t.QcWarning)
            .ToString();
        return new EmailMessage(email, string.Format(CultureInfo.InvariantCulture, t.QcSubject, server), body);
    }

    private static string Html(string value) => WebUtility.HtmlEncode(value);

    private static string Clean(string? value, Texts t)
    {
        var s = EmailAddress.SingleLine(value);
        return s.Length == 0 ? t.Unknown : s;
    }

    /// <summary>
    /// Client-supplied values (device/app name, IP text). Whoever triggers the email chooses them, so they are
    /// kept short to limit how much attacker-controlled text ends up in a trusted-looking email.
    /// </summary>
    private static string Client(string? value, Texts t)
    {
        var s = Clean(value, t);
        return s.Length > MaxClientTextLength ? s[..(MaxClientTextLength - 3)].TrimEnd() + "..." : s;
    }

    private sealed class Texts
    {
        private static readonly Texts English = new()
        {
            Greeting = "Hello {0},",
            CodeSubject = "{0}: sign-in code",
            CodeIntro = "Someone entered the correct password for your account on {0}. Your sign-in code is:",
            HowToPasswordPlusCode = "To finish signing in, enter your password immediately followed by this code in the password field (no space).",
            HowToCodeOnly = "To finish signing in, sign in again with your user name and enter only this code in the password field (without your password).",
            ExampleLabel = "For example:",
            ExamplePassword = "MyPassword",
            Validity = "The code is valid for {0} minutes, works once, and only on the device that requested it.",
            Reuse = "Exception: for {1} minutes after you signed in with it, these apps may use the code {0} more time(s), for example when your app signs you in to them: {2}.",
            Device = "Device",
            App = "App",
            Ip = "IP",
            Time = "Time",
            Unknown = "(unknown)",
            CodeWarning = "If this was NOT you, do not share the code: someone knows your password. Change it and tell the server administrator.",
            QcSubject = "{0}: new Quick Connect sign-in",
            QcIntro = "A new device was signed in to your account on {0} using Quick Connect.",
            ApprovedFromIp = "Approved from IP",
            QcWarning = "If this was not you, sign out that device (Dashboard > Devices) and change your password.",
        };

        private static readonly Texts German = new()
        {
            Greeting = "Hallo {0},",
            CodeSubject = "{0}: Anmeldecode",
            CodeIntro = "Jemand hat das richtige Passwort für dein Konto auf {0} eingegeben. Dein Anmeldecode lautet:",
            HowToPasswordPlusCode = "Um die Anmeldung abzuschließen, gib im Passwortfeld dein Passwort direkt gefolgt von diesem Code ein (ohne Leerzeichen).",
            HowToCodeOnly = "Um die Anmeldung abzuschließen, melde dich erneut mit deinem Benutzernamen an und gib im Passwortfeld nur diesen Code ein (ohne dein Passwort).",
            ExampleLabel = "Zum Beispiel:",
            ExamplePassword = "MeinPasswort",
            Validity = "Der Code ist {0} Minuten gültig, funktioniert nur einmal und nur auf dem Gerät, das ihn angefordert hat.",
            Reuse = "Ausnahme: {1} Minuten lang nach deiner Anmeldung damit dürfen diese Apps den Code noch {0}-mal verwenden, zum Beispiel wenn deine App dich dort anmeldet: {2}.",
            Device = "Gerät",
            App = "App",
            Ip = "IP",
            Time = "Zeit",
            Unknown = "(unbekannt)",
            CodeWarning = "Wenn du das NICHT warst, gib den Code nicht weiter: Jemand kennt dein Passwort. Ändere es und informiere den Server-Administrator.",
            QcSubject = "{0}: neue Anmeldung per Quick Connect",
            QcIntro = "Auf {0} wurde ein neues Gerät per Quick Connect bei deinem Konto angemeldet.",
            ApprovedFromIp = "Freigegeben von IP",
            QcWarning = "Wenn du das nicht warst, melde dieses Gerät ab (Dashboard > Geräte) und ändere dein Passwort.",
        };

        public required string Greeting { get; init; }

        public required string CodeSubject { get; init; }

        public required string CodeIntro { get; init; }

        public required string HowToPasswordPlusCode { get; init; }

        public required string HowToCodeOnly { get; init; }

        public required string ExampleLabel { get; init; }

        public required string ExamplePassword { get; init; }

        public required string Validity { get; init; }

        public required string Reuse { get; init; }

        public required string Device { get; init; }

        public required string App { get; init; }

        public required string Ip { get; init; }

        public required string Time { get; init; }

        public required string Unknown { get; init; }

        public required string CodeWarning { get; init; }

        public required string QcSubject { get; init; }

        public required string QcIntro { get; init; }

        public required string ApprovedFromIp { get; init; }

        public required string QcWarning { get; init; }

        public static Texts For(string? language)
            => string.Equals(language?.Trim(), "de", StringComparison.OrdinalIgnoreCase) ? German : English;
    }
}
