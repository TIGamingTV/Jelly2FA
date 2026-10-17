using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Short-lived record of sign-ins that Jelly2FA approved, so the token watcher can tell them apart from
/// tokens created by paths that bypass the auth provider (Quick Connect, other plugins).
/// </summary>
public sealed class LoginApprovalRegistry
{
    private static readonly TimeSpan _ttl = TimeSpan.FromMinutes(2);

    private readonly object _lock = new();
    private readonly Dictionary<string, DateTimeOffset> _approved = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;

    /// <summary>
    /// Initializes a new instance of the <see cref="LoginApprovalRegistry"/> class.
    /// </summary>
    /// <param name="time">Time provider.</param>
    public LoginApprovalRegistry(TimeProvider time)
    {
        _time = time;
    }

    /// <summary>Records an approval.</summary>
    /// <param name="userId">User id.</param>
    /// <param name="deviceId">Device id.</param>
    public void Approve(Guid userId, string? deviceId)
    {
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            foreach (var stale in _approved.Where(e => e.Value <= now).Select(e => e.Key).ToList())
            {
                _approved.Remove(stale);
            }

            _approved[Key(userId, deviceId)] = now + _ttl;
        }
    }

    /// <summary>Consumes an approval.</summary>
    /// <param name="userId">User id.</param>
    /// <param name="deviceId">Device id.</param>
    /// <returns>True if a fresh approval existed.</returns>
    public bool TryConsume(Guid userId, string? deviceId)
    {
        var key = Key(userId, deviceId);
        lock (_lock)
        {
            if (_approved.Remove(key, out var expires))
            {
                return expires > _time.GetUtcNow();
            }

            return false;
        }
    }

    private static string Key(Guid userId, string? deviceId)
        => string.Create(CultureInfo.InvariantCulture, $"{userId:N}\n{deviceId ?? string.Empty}");
}
