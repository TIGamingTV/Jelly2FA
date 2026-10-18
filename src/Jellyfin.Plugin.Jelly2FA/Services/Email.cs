using System;
using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>An email to send.</summary>
/// <param name="To">Recipient.</param>
/// <param name="Subject">Subject (must not contain secrets).</param>
/// <param name="Body">Plain text body.</param>
/// <param name="HtmlBody">Optional HTML alternative (all interpolated values must already be HTML-encoded).</param>
public sealed record EmailMessage(string To, string Subject, string Body, string? HtmlBody = null);

/// <summary>Sends email.</summary>
public interface IEmailSender
{
    /// <summary>Gets a value indicating whether sending is configured.</summary>
    bool IsConfigured { get; }

    /// <summary>Sends a message.</summary>
    /// <param name="message">Message.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task.</returns>
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken);
}

/// <summary>
/// SMTP sender. Always requires STARTTLS (no plaintext fallback) and validates the server certificate.
/// </summary>
public sealed class SmtpEmailSender : IEmailSender
{
    private readonly IConfigProvider _config;
    private readonly SecretStore _secrets;

    /// <summary>
    /// Initializes a new instance of the <see cref="SmtpEmailSender"/> class.
    /// </summary>
    /// <param name="config">Config.</param>
    /// <param name="secrets">Secrets.</param>
    public SmtpEmailSender(IConfigProvider config, SecretStore secrets)
    {
        _config = config;
        _secrets = secrets;
    }

    /// <inheritdoc />
    public bool IsConfigured
    {
        get
        {
            var c = _config.Current;
            return !string.IsNullOrWhiteSpace(c.SmtpHost)
                   && c.SmtpPort is > 0 and < 65536
                   && EmailAddress.IsValid(c.FromAddress)
                   && (string.IsNullOrEmpty(c.SmtpUsername) || _secrets.HasSmtpPassword);
        }
    }

    /// <inheritdoc />
    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        var c = _config.Current;
        if (!IsConfigured)
        {
            throw new InvalidOperationException("SMTP is not configured.");
        }

        using var mail = new MailMessage
        {
            From = new MailAddress(c.FromAddress, EmailAddress.SingleLine(c.FromName)),
            Subject = EmailAddress.SingleLine(message.Subject),
            SubjectEncoding = Encoding.UTF8,
            Body = message.Body,
            BodyEncoding = Encoding.UTF8,
            IsBodyHtml = false,
        };
        mail.To.Add(new MailAddress(message.To));
        if (!string.IsNullOrEmpty(message.HtmlBody))
        {
            // multipart/alternative: plain text first, HTML preferred by clients that support it.
            mail.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(message.HtmlBody, Encoding.UTF8, MediaTypeNames.Text.Html));
        }

#pragma warning disable SYSLIB0014 // SmtpClient is fine for simple STARTTLS submission and avoids extra dependencies.
        using var client = new SmtpClient(c.SmtpHost.Trim(), c.SmtpPort)
        {
            EnableSsl = true,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            Timeout = 30_000,
            UseDefaultCredentials = false,
        };
#pragma warning restore SYSLIB0014
        if (!string.IsNullOrEmpty(c.SmtpUsername))
        {
            client.Credentials = new NetworkCredential(c.SmtpUsername, _secrets.GetSmtpPassword());
        }

        await client.SendMailAsync(mail, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>Email address helpers.</summary>
public static class EmailAddress
{
    /// <summary>Validates an address (single mailbox, no display name, no control characters).</summary>
    /// <param name="value">Address.</param>
    /// <returns>True if valid.</returns>
    public static bool IsValid(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 254)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (char.IsControl(ch) || char.IsWhiteSpace(ch) || ch is ',' or ';' or '<' or '>')
            {
                return false;
            }
        }

        try
        {
            var parsed = new MailAddress(value);
            return string.Equals(parsed.Address, value, StringComparison.Ordinal) && value.IndexOf('@', StringComparison.Ordinal) > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Removes line breaks / control characters (header-injection safety).</summary>
    /// <param name="value">Value.</param>
    /// <returns>Sanitised value.</returns>
    public static string SingleLine(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var chars = value.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            if (char.IsControl(chars[i]))
            {
                chars[i] = ' ';
            }
        }

        var result = new string(chars).Trim();
        return result.Length > 200 ? result[..200] : result;
    }
}

/// <summary>
/// Background email queue: logins never wait for SMTP, and SMTP failures cannot break a login.
/// </summary>
public sealed class EmailQueue : BackgroundService
{
    private readonly Channel<EmailMessage> _channel = Channel.CreateBounded<EmailMessage>(
        new BoundedChannelOptions(200) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true });

    private readonly IEmailSender _sender;
    private readonly HealthState _health;
    private readonly ILogger<EmailQueue> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="EmailQueue"/> class.
    /// </summary>
    /// <param name="sender">Sender.</param>
    /// <param name="health">Health state.</param>
    /// <param name="logger">Logger.</param>
    public EmailQueue(IEmailSender sender, HealthState health, ILogger<EmailQueue> logger)
    {
        _sender = sender;
        _health = health;
        _logger = logger;
    }

    /// <summary>Queues a message.</summary>
    /// <param name="message">Message.</param>
    /// <returns>False if the queue is full or the address is invalid.</returns>
    public bool Enqueue(EmailMessage message)
    {
        if (!EmailAddress.IsValid(message.To))
        {
            _logger.LogWarning("Jelly2FA: refusing to queue email to an invalid address");
            return false;
        }

        if (!_channel.Writer.TryWrite(message))
        {
            _logger.LogError("Jelly2FA: email queue full, message dropped");
            return false;
        }

        return true;
    }

    /// <summary>Sends a message immediately (admin test email).</summary>
    /// <param name="message">Message.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task.</returns>
    public async Task SendNowAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        try
        {
            await _sender.SendAsync(message, cancellationToken).ConfigureAwait(false);
            _health.RecordSmtpSuccess();
        }
        catch (Exception ex)
        {
            _health.RecordSmtpFailure(ex.Message);
            throw;
        }
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var message in _channel.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await _sender.SendAsync(message, stoppingToken).ConfigureAwait(false);
                _health.RecordSmtpSuccess();
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                // Never log the body (it may contain a code).
                _health.RecordSmtpFailure(ex.Message);
                _logger.LogError("Jelly2FA: sending email failed: {Message}", ex.Message);
            }
        }
    }
}
