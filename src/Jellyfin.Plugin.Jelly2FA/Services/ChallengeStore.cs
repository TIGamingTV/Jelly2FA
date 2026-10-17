using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Identifies which sign-in a code belongs to. A code is only valid for the same user, device id and client.
/// (These values are client-chosen and NOT a security factor; they only stop one pending code from being
/// redeemed by a different login attempt of the same account. The secret is the emailed code.)
/// </summary>
/// <param name="UserId">User id.</param>
/// <param name="DeviceId">Device id from the Authorization header.</param>
/// <param name="Client">Client name from the Authorization header.</param>
public sealed record ChallengeBinding(Guid UserId, string DeviceId, string Client)
{
    internal string Key => string.Create(CultureInfo.InvariantCulture, $"{UserId:N}\n{DeviceId}\n{Client}");
}

/// <summary>Outcome of a code verification.</summary>
public enum VerifyResult
{
    /// <summary>No pending code for this sign-in.</summary>
    NoChallenge,

    /// <summary>Code matched; it has been consumed.</summary>
    Success,

    /// <summary>Wrong code.</summary>
    WrongCode,

    /// <summary>The code expired (removed).</summary>
    Expired,

    /// <summary>Too many wrong entries (removed).</summary>
    TooManyAttempts,

    /// <summary>The password changed after the code was issued (removed).</summary>
    PasswordChanged,
}

/// <summary>
/// In-memory store of pending one-time codes. Codes are kept only as HMACs keyed with a per-process
/// random key, are single use, expire, and allow a limited number of wrong entries. All operations are
/// serialised by a lock so concurrent redemptions of the same code cannot both succeed.
/// Restarting Jellyfin simply discards pending codes.
/// </summary>
public sealed class ChallengeStore
{
    /// <summary>Number of digits of a code.</summary>
    public const int CodeLength = 8;

    private readonly object _lock = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly TimeProvider _time;

    /// <summary>
    /// Initializes a new instance of the <see cref="ChallengeStore"/> class.
    /// </summary>
    /// <param name="time">Time provider.</param>
    public ChallengeStore(TimeProvider time)
    {
        _time = time;
    }

    /// <summary>Creates a new code for the binding, replacing any previous one for the same binding.</summary>
    /// <param name="binding">Binding.</param>
    /// <param name="passwordFingerprint">Fingerprint of the stored password hash at issue time.</param>
    /// <param name="lifetime">Lifetime.</param>
    /// <param name="maxPendingPerUser">Maximum pending codes per user (oldest evicted).</param>
    /// <returns>The plaintext code (to be emailed, never stored).</returns>
    public string Issue(ChallengeBinding binding, byte[] passwordFingerprint, TimeSpan lifetime, int maxPendingPerUser)
    {
        var code = RandomNumberGenerator.GetInt32(0, 100_000_000).ToString("D8", CultureInfo.InvariantCulture);
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            PruneExpired(now);
            _entries[binding.Key] = new Entry(binding.UserId, Mac(binding, code), passwordFingerprint, now, now + lifetime);

            var forUser = _entries.Where(e => e.Value.UserId == binding.UserId)
                .OrderBy(e => e.Value.CreatedUtc)
                .ToList();
            var excess = forUser.Count - Math.Max(1, maxPendingPerUser);
            for (var i = 0; i < excess; i++)
            {
                _entries.Remove(forUser[i].Key);
            }
        }

        return code;
    }

    /// <summary>Gets when the current code for the binding was issued, if one is pending.</summary>
    /// <param name="binding">Binding.</param>
    /// <returns>Issue time or null.</returns>
    public DateTimeOffset? GetIssuedAt(ChallengeBinding binding)
    {
        lock (_lock)
        {
            PruneExpired(_time.GetUtcNow());
            return _entries.TryGetValue(binding.Key, out var e) ? e.CreatedUtc : null;
        }
    }

    /// <summary>Checks a code. Success consumes it.</summary>
    /// <param name="binding">Binding.</param>
    /// <param name="code">Entered code.</param>
    /// <param name="passwordFingerprint">Current fingerprint of the stored password hash.</param>
    /// <param name="maxAttempts">Allowed wrong entries.</param>
    /// <returns>The result.</returns>
    public VerifyResult Verify(ChallengeBinding binding, string code, byte[] passwordFingerprint, int maxAttempts)
    {
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            if (!_entries.TryGetValue(binding.Key, out var entry))
            {
                return VerifyResult.NoChallenge;
            }

            if (entry.ExpiresUtc <= now)
            {
                _entries.Remove(binding.Key);
                return VerifyResult.Expired;
            }

            if (!CryptographicOperations.FixedTimeEquals(entry.PasswordFingerprint, passwordFingerprint))
            {
                _entries.Remove(binding.Key);
                return VerifyResult.PasswordChanged;
            }

            if (CryptographicOperations.FixedTimeEquals(entry.CodeMac, Mac(binding, code)))
            {
                _entries.Remove(binding.Key);
                return VerifyResult.Success;
            }

            entry.FailedAttempts++;
            if (entry.FailedAttempts >= Math.Max(1, maxAttempts))
            {
                _entries.Remove(binding.Key);
                return VerifyResult.TooManyAttempts;
            }

            return VerifyResult.WrongCode;
        }
    }

    /// <summary>Whether a non-expired code is pending for the binding.</summary>
    /// <param name="binding">Binding.</param>
    /// <returns>True if pending.</returns>
    public bool HasPending(ChallengeBinding binding) => GetIssuedAt(binding) is not null;

    /// <summary>Drops every pending code of a user (password change, unenroll, deletion).</summary>
    /// <param name="userId">User id.</param>
    public void RemoveUser(Guid userId)
    {
        lock (_lock)
        {
            foreach (var key in _entries.Where(e => e.Value.UserId == userId).Select(e => e.Key).ToList())
            {
                _entries.Remove(key);
            }
        }
    }

    /// <summary>Gets the number of pending codes (diagnostics/tests).</summary>
    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>Fingerprint of a stored password hash (so a password change invalidates pending codes).</summary>
    /// <param name="storedPasswordHash">The user's stored hash string.</param>
    /// <returns>SHA-256 of the string.</returns>
    public static byte[] Fingerprint(string? storedPasswordHash)
        => SHA256.HashData(Encoding.UTF8.GetBytes(storedPasswordHash ?? string.Empty));

    private byte[] Mac(ChallengeBinding binding, string code)
        => HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(binding.Key + "\n" + code));

    private void PruneExpired(DateTimeOffset now)
    {
        foreach (var key in _entries.Where(e => e.Value.ExpiresUtc <= now).Select(e => e.Key).ToList())
        {
            _entries.Remove(key);
        }
    }

    private sealed class Entry
    {
        public Entry(Guid userId, byte[] codeMac, byte[] passwordFingerprint, DateTimeOffset createdUtc, DateTimeOffset expiresUtc)
        {
            UserId = userId;
            CodeMac = codeMac;
            PasswordFingerprint = passwordFingerprint;
            CreatedUtc = createdUtc;
            ExpiresUtc = expiresUtc;
        }

        public Guid UserId { get; }

        public byte[] CodeMac { get; }

        public byte[] PasswordFingerprint { get; }

        public DateTimeOffset CreatedUtc { get; }

        public DateTimeOffset ExpiresUtc { get; }

        public int FailedAttempts { get; set; }
    }
}
