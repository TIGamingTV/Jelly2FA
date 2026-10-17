using System;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Runtime health facts shared between services.
/// </summary>
public sealed class HealthState
{
    private readonly object _lock = new();
    private readonly TimeProvider _time;

    /// <summary>
    /// Initializes a new instance of the <see cref="HealthState"/> class.
    /// </summary>
    /// <param name="time">Time provider.</param>
    public HealthState(TimeProvider time)
    {
        _time = time;
    }

    /// <summary>Gets the time of the last SMTP failure.</summary>
    public DateTimeOffset? LastSmtpFailure { get; private set; }

    /// <summary>Gets the last SMTP error message.</summary>
    public string? LastSmtpError { get; private set; }

    /// <summary>Gets the time of the last successful send.</summary>
    public DateTimeOffset? LastSmtpSuccess { get; private set; }

    /// <summary>Gets a value indicating whether the most recent SMTP attempt failed within the last hour.</summary>
    public bool SmtpRecentlyFailing
    {
        get
        {
            lock (_lock)
            {
                return LastSmtpFailure is { } f
                       && (LastSmtpSuccess is null || LastSmtpSuccess < f)
                       && _time.GetUtcNow() - f < TimeSpan.FromHours(1);
            }
        }
    }

    /// <summary>Records a failure.</summary>
    /// <param name="message">Error message.</param>
    public void RecordSmtpFailure(string message)
    {
        lock (_lock)
        {
            LastSmtpFailure = _time.GetUtcNow();
            LastSmtpError = EmailAddress.SingleLine(message);
        }
    }

    /// <summary>Records a success.</summary>
    public void RecordSmtpSuccess()
    {
        lock (_lock)
        {
            LastSmtpSuccess = _time.GetUtcNow();
        }
    }
}
