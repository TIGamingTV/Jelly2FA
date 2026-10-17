using System;
using System.Globalization;
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
/// Default notification service.
/// </summary>
public sealed class NotificationService : INotificationService
{
    private readonly EmailQueue _queue;
    private readonly IConfigProvider _config;
    private readonly RateLimiter _limiter;
    private readonly ILogger<NotificationService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="NotificationService"/> class.
    /// </summary>
    /// <param name="queue">Queue.</param>
    /// <param name="config">Config.</param>
    /// <param name="limiter">Rate limiter.</param>
    /// <param name="logger">Logger.</param>
    public NotificationService(EmailQueue queue, IConfigProvider config, RateLimiter limiter, ILogger<NotificationService> logger)
    {
        _queue = queue;
        _config = config;
        _limiter = limiter;
        _logger = logger;
    }

    /// <inheritdoc />
    public bool SendCode(string email, string userName, string code, string? device, string? client, string? clientIp, int lifetimeMinutes)
    {
        var server = EmailAddress.SingleLine(_config.Current.ServerDisplayName);
        var body = new StringBuilder()
            .AppendLine(CultureInfo.InvariantCulture, $"Hello {Clean(userName)},")
            .AppendLine()
            .AppendLine(CultureInfo.InvariantCulture, $"Someone entered the correct password for your account on {server}. Your sign-in code is:")
            .AppendLine()
            .AppendLine(CultureInfo.InvariantCulture, $"    {code}")
            .AppendLine()
            .AppendLine("To finish signing in, enter your password immediately followed by this code in the password field")
            .AppendLine("(no space), for example: MyPassword" + code)
            .AppendLine()
            .AppendLine(CultureInfo.InvariantCulture, $"The code is valid for {lifetimeMinutes} minutes, works once, and only on the device that requested it.")
            .AppendLine()
            .AppendLine(CultureInfo.InvariantCulture, $"Device: {Clean(device)}")
            .AppendLine(CultureInfo.InvariantCulture, $"App:    {Clean(client)}")
            .AppendLine(CultureInfo.InvariantCulture, $"IP:     {Clean(clientIp)}")
            .AppendLine(CultureInfo.InvariantCulture, $"Time:   {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm} UTC")
            .AppendLine()
            .AppendLine("If this was NOT you, do not share the code: someone knows your password. Change it and tell the server administrator.")
            .ToString();

        return _queue.Enqueue(new EmailMessage(email, $"{server}: sign-in code", body));
    }

    /// <inheritdoc />
    public void NotifyQuickConnect(string email, string userName, string? device, string? client, string? approverIp)
    {
        var server = EmailAddress.SingleLine(_config.Current.ServerDisplayName);
        var body = new StringBuilder()
            .AppendLine(CultureInfo.InvariantCulture, $"Hello {Clean(userName)},")
            .AppendLine()
            .AppendLine(CultureInfo.InvariantCulture, $"A new device was signed in to your account on {server} using Quick Connect.")
            .AppendLine()
            .AppendLine(CultureInfo.InvariantCulture, $"Device: {Clean(device)}")
            .AppendLine(CultureInfo.InvariantCulture, $"App:    {Clean(client)}")
            .AppendLine(CultureInfo.InvariantCulture, $"Approved from IP: {Clean(approverIp)}")
            .AppendLine(CultureInfo.InvariantCulture, $"Time:   {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm} UTC")
            .AppendLine()
            .AppendLine("If this was not you, sign out that device (Dashboard > Devices) and change your password.")
            .ToString();
        _queue.Enqueue(new EmailMessage(email, $"{server}: new Quick Connect sign-in", body));
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

    private static string Clean(string? value)
    {
        var s = EmailAddress.SingleLine(value);
        return s.Length == 0 ? "(unknown)" : s;
    }
}
