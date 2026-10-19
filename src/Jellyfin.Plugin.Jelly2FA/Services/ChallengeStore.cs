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

    /// <summary>The code was entered from a different client IP than the one that requested it (counts as a wrong entry).</summary>
    IpMismatch,

    /// <summary>
    /// Not valid here, but it is a code that was issued to this user recently (already used, expired, replaced, or
    /// requested by another device). Typical for apps that sign in again with stored credentials.
    /// Not counted as a wrong entry.
    /// </summary>
    Stale,
}

/// <summary>
/// In-memory store of pending one-time codes. Codes are kept only as HMACs keyed with a per-process
/// random key, are single use, expire, and allow a limited number of wrong entries. All operations are
/// serialised by a lock so concurrent redemptions of the same code cannot both succeed.
/// Restarting Jellyfin simply discards pending codes.
/// <para>
/// Two additions (also HMAC only, in memory):
/// <list type="bullet">
/// <item>Optional reuse grants: after a successful use, a code may be used a few more times by the same user
/// within a short window (see <see cref="CodeReusePolicy"/>).</item>
/// <item>Recently issued codes per user, so that a stale code (an app signing in again with stored
/// credentials) is recognised and answered without counting as a failed sign-in.</item>
/// </list>
/// </para>
/// </summary>
public sealed class ChallengeStore
{
    /// <summary>Number of digits of a code.</summary>
    public const int CodeLength = 8;

    /// <summary>How long an issued code is remembered as "recently issued".</summary>
    internal static readonly TimeSpan KnownCodeLifetime = TimeSpan.FromDays(30);

    /// <summary>How many issued codes are remembered per user.</summary>
    internal const int MaxKnownCodesPerUser = 10;

    private readonly object _lock = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, ReuseGrant> _grants = new();
    private readonly Dictionary<Guid, List<KnownCode>> _known = new();
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
    /// <param name="clientIp">Client IP that requested the code (used for code-only verification).</param>
    /// <returns>The plaintext code (to be emailed, never stored).</returns>
    public string Issue(ChallengeBinding binding, byte[] passwordFingerprint, TimeSpan lifetime, int maxPendingPerUser, string? clientIp = null)
    {
        var code = RandomNumberGenerator.GetInt32(0, 100_000_000).ToString("D8", CultureInfo.InvariantCulture);
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            PruneExpired(now);
            _entries[binding.Key] = new Entry(binding.UserId, Mac(binding, code), passwordFingerprint, now, now + lifetime, clientIp);
            RememberLocked(binding.UserId, UserMac(binding.UserId, code), now);

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
    /// <param name="requiredIp">If set, the code is only accepted from the client IP that requested it.</param>
    /// <returns>The result.</returns>
    public VerifyResult Verify(ChallengeBinding binding, string code, byte[] passwordFingerprint, int maxAttempts, string? requiredIp = null)
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

            var ipOk = requiredIp is null
                || (entry.ClientIp is not null && string.Equals(entry.ClientIp, requiredIp, StringComparison.Ordinal));
            var codeOk = CryptographicOperations.FixedTimeEquals(entry.CodeMac, Mac(binding, code));
            if (ipOk && codeOk)
            {
                _entries.Remove(binding.Key);
                return VerifyResult.Success;
            }

            if (!codeOk && IsKnownLocked(binding.UserId, UserMac(binding.UserId, code), now))
            {
                return VerifyResult.Stale;
            }

            entry.FailedAttempts++;
            if (entry.FailedAttempts >= Math.Max(1, maxAttempts))
            {
                _entries.Remove(binding.Key);
                return VerifyResult.TooManyAttempts;
            }

            return ipOk ? VerifyResult.WrongCode : VerifyResult.IpMismatch;
        }
    }

    /// <summary>Whether a non-expired code is pending for the binding.</summary>
    /// <param name="binding">Binding.</param>
    /// <returns>True if pending.</returns>
    public bool HasPending(ChallengeBinding binding) => GetIssuedAt(binding) is not null;

    /// <summary>Drops the pending code of one binding (e.g. the code email could not be queued).</summary>
    /// <param name="binding">Binding.</param>
    public void Remove(ChallengeBinding binding)
    {
        lock (_lock)
        {
            _entries.Remove(binding.Key);
        }
    }

    /// <summary>
    /// Allows a code that was just used successfully to be used <paramref name="uses"/> more times by the same
    /// user within <paramref name="lifetime"/>. Replaces an earlier grant of the user.
    /// </summary>
    /// <param name="userId">User id.</param>
    /// <param name="code">The code that was used.</param>
    /// <param name="passwordFingerprint">Fingerprint of the stored password hash.</param>
    /// <param name="uses">Additional uses (0 or less = no grant).</param>
    /// <param name="lifetime">Window.</param>
    public void GrantReuse(Guid userId, string code, byte[] passwordFingerprint, int uses, TimeSpan lifetime)
    {
        if (uses <= 0)
        {
            return;
        }

        var now = _time.GetUtcNow();
        lock (_lock)
        {
            _grants[userId] = new ReuseGrant(UserMac(userId, code), passwordFingerprint, now + lifetime, uses);
        }
    }

    /// <summary>Redeems a reuse grant. Success uses up one of the remaining uses.</summary>
    /// <param name="userId">User id.</param>
    /// <param name="code">Entered code.</param>
    /// <param name="passwordFingerprint">Current fingerprint of the stored password hash.</param>
    /// <param name="maxAttempts">Allowed wrong entries for the grant.</param>
    /// <returns>The result (<see cref="VerifyResult.NoChallenge"/> if no grant is active).</returns>
    public VerifyResult VerifyReuse(Guid userId, string code, byte[] passwordFingerprint, int maxAttempts)
    {
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            if (!_grants.TryGetValue(userId, out var grant))
            {
                return VerifyResult.NoChallenge;
            }

            if (grant.ExpiresUtc <= now)
            {
                _grants.Remove(userId);
                return VerifyResult.NoChallenge;
            }

            if (!CryptographicOperations.FixedTimeEquals(grant.PasswordFingerprint, passwordFingerprint))
            {
                _grants.Remove(userId);
                return VerifyResult.PasswordChanged;
            }

            var mac = UserMac(userId, code);
            if (CryptographicOperations.FixedTimeEquals(grant.CodeMac, mac))
            {
                if (--grant.RemainingUses <= 0)
                {
                    _grants.Remove(userId);
                }

                return VerifyResult.Success;
            }

            if (IsKnownLocked(userId, mac, now))
            {
                return VerifyResult.Stale;
            }

            if (++grant.FailedAttempts >= Math.Max(1, maxAttempts))
            {
                _grants.Remove(userId);
                return VerifyResult.TooManyAttempts;
            }

            return VerifyResult.WrongCode;
        }
    }

    /// <summary>Whether a reuse grant is active for the user (diagnostics/tests).</summary>
    /// <param name="userId">User id.</param>
    /// <returns>True if active.</returns>
    public bool HasReuseGrant(Guid userId)
    {
        lock (_lock)
        {
            return _grants.TryGetValue(userId, out var g) && g.ExpiresUtc > _time.GetUtcNow();
        }
    }

    /// <summary>Whether the code was issued to the user recently (see <see cref="KnownCodeLifetime"/>).</summary>
    /// <param name="userId">User id.</param>
    /// <param name="code">Entered code.</param>
    /// <returns>True if known.</returns>
    public bool IsKnownCode(Guid userId, string code)
    {
        lock (_lock)
        {
            return IsKnownLocked(userId, UserMac(userId, code), _time.GetUtcNow());
        }
    }

    /// <summary>Drops every pending code, reuse grant and remembered code of a user (password change, unenroll, deletion).</summary>
    /// <param name="userId">User id.</param>
    public void RemoveUser(Guid userId)
    {
        lock (_lock)
        {
            foreach (var key in _entries.Where(e => e.Value.UserId == userId).Select(e => e.Key).ToList())
            {
                _entries.Remove(key);
            }

            _grants.Remove(userId);
            _known.Remove(userId);
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

    // Not bound to a device: used for reuse grants and remembered codes.
    private byte[] UserMac(Guid userId, string code)
        => HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(string.Create(CultureInfo.InvariantCulture, $"user\n{userId:N}\n{code}")));

    private void RememberLocked(Guid userId, byte[] mac, DateTimeOffset now)
    {
        if (!_known.TryGetValue(userId, out var list))
        {
            list = new List<KnownCode>();
            _known[userId] = list;
        }

        list.RemoveAll(k => now - k.IssuedUtc >= KnownCodeLifetime);
        list.Add(new KnownCode(mac, now));
        if (list.Count > MaxKnownCodesPerUser)
        {
            list.RemoveRange(0, list.Count - MaxKnownCodesPerUser);
        }
    }

    private bool IsKnownLocked(Guid userId, byte[] mac, DateTimeOffset now)
    {
        if (!_known.TryGetValue(userId, out var list))
        {
            return false;
        }

        list.RemoveAll(k => now - k.IssuedUtc >= KnownCodeLifetime);
        if (list.Count == 0)
        {
            _known.Remove(userId);
            return false;
        }

        var found = false;
        foreach (var k in list)
        {
            found |= CryptographicOperations.FixedTimeEquals(k.Mac, mac);
        }

        return found;
    }

    private void PruneExpired(DateTimeOffset now)
    {
        foreach (var key in _entries.Where(e => e.Value.ExpiresUtc <= now).Select(e => e.Key).ToList())
        {
            _entries.Remove(key);
        }

        foreach (var user in _grants.Where(g => g.Value.ExpiresUtc <= now).Select(g => g.Key).ToList())
        {
            _grants.Remove(user);
        }
    }

    private sealed record KnownCode(byte[] Mac, DateTimeOffset IssuedUtc);

    private sealed class ReuseGrant
    {
        public ReuseGrant(byte[] codeMac, byte[] passwordFingerprint, DateTimeOffset expiresUtc, int remainingUses)
        {
            CodeMac = codeMac;
            PasswordFingerprint = passwordFingerprint;
            ExpiresUtc = expiresUtc;
            RemainingUses = remainingUses;
        }

        public byte[] CodeMac { get; }

        public byte[] PasswordFingerprint { get; }

        public DateTimeOffset ExpiresUtc { get; }

        public int RemainingUses { get; set; }

        public int FailedAttempts { get; set; }
    }

    private sealed class Entry
    {
        public Entry(Guid userId, byte[] codeMac, byte[] passwordFingerprint, DateTimeOffset createdUtc, DateTimeOffset expiresUtc, string? clientIp)
        {
            UserId = userId;
            CodeMac = codeMac;
            PasswordFingerprint = passwordFingerprint;
            CreatedUtc = createdUtc;
            ExpiresUtc = expiresUtc;
            ClientIp = clientIp;
        }

        public string? ClientIp { get; }

        public Guid UserId { get; }

        public byte[] CodeMac { get; }

        public byte[] PasswordFingerprint { get; }

        public DateTimeOffset CreatedUtc { get; }

        public DateTimeOffset ExpiresUtc { get; }

        public int FailedAttempts { get; set; }
    }
}
