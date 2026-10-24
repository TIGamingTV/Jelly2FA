using Jellyfin.Plugin.Jelly2FA.Services;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Jellyfin.Plugin.Jelly2FA.Tests;

public class ChallengeStoreTests
{
    private static readonly byte[] Fp = ChallengeStore.Fingerprint("hash-1");

    private readonly FakeTimeProvider _time = new(DateTimeOffset.Parse("2026-10-17T12:00:00Z"));

    private ChallengeStore Store() => new(_time);

    private static ChallengeBinding Bind(Guid? user = null, string device = "dev", string client = "app")
        => new(user ?? Guid.Parse("11111111-1111-1111-1111-111111111111"), device, client);

    [Fact]
    public void Code_IsEightDigits()
    {
        var code = Store().Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        Assert.Matches("^[0-9]{8}$", code);
    }

    [Fact]
    public void CorrectCode_SucceedsExactlyOnce()
    {
        var store = Store();
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), code, Fp, 5));
        Assert.Equal(VerifyResult.NoChallenge, store.Verify(Bind(), code, Fp, 5));
    }

    [Fact]
    public void Code_IsBoundToDeviceAndClient()
    {
        var store = Store();
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        Assert.Equal(VerifyResult.NoChallenge, store.Verify(Bind(device: "other"), code, Fp, 5));
        Assert.Equal(VerifyResult.NoChallenge, store.Verify(Bind(client: "other"), code, Fp, 5));
        Assert.Equal(VerifyResult.NoChallenge, store.Verify(Bind(user: Guid.NewGuid()), code, Fp, 5));
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), code, Fp, 5));
    }

    [Fact]
    public void WrongCodes_InvalidateAfterMaxAttempts()
    {
        var store = Store();
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        var wrong = code == "00000000" ? "00000001" : "00000000";
        for (var i = 0; i < 4; i++)
        {
            Assert.Equal(VerifyResult.WrongCode, store.Verify(Bind(), wrong, Fp, 5));
        }

        Assert.Equal(VerifyResult.TooManyAttempts, store.Verify(Bind(), wrong, Fp, 5));
        Assert.Equal(VerifyResult.NoChallenge, store.Verify(Bind(), code, Fp, 5));
    }

    [Fact]
    public void Code_Expires()
    {
        var store = Store();
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        _time.Advance(TimeSpan.FromMinutes(10));
        Assert.Equal(VerifyResult.Expired, store.Verify(Bind(), code, Fp, 5));
    }

    [Fact]
    public void PasswordChange_InvalidatesCode()
    {
        var store = Store();
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        Assert.Equal(VerifyResult.PasswordChanged, store.Verify(Bind(), code, ChallengeStore.Fingerprint("hash-2"), 5));
        Assert.Equal(VerifyResult.NoChallenge, store.Verify(Bind(), code, Fp, 5));
    }

    /// <summary>Issues <paramref name="count"/> distinct codes for the binding, one second apart.</summary>
    private List<string> IssueDistinct(ChallengeStore store, int count, ChallengeBinding? binding = null, string? ip = null)
    {
        var codes = new List<string>();
        while (codes.Count < count)
        {
            var code = store.Issue(binding ?? Bind(), Fp, TimeSpan.FromMinutes(10), 3, ip);
            if (!codes.Contains(code))
            {
                codes.Add(code);
            }

            _time.Advance(TimeSpan.FromSeconds(1));
        }

        return codes;
    }

    [Fact]
    public void Reissue_KeepsEarlierCodesValid()
    {
        var store = Store();
        var codes = IssueDistinct(store, 2);
        Assert.Equal(1, store.Count); // one binding
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), codes[0], Fp, 5)); // the code from the first email
    }

    [Fact]
    public void Reissue_UsingOneCode_ConsumesAllCodesOfTheBinding()
    {
        var store = Store();
        var codes = IssueDistinct(store, 3);
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), codes[1], Fp, 5));
        Assert.Equal(VerifyResult.NoChallenge, store.Verify(Bind(), codes[0], Fp, 5));
        Assert.Equal(VerifyResult.NoChallenge, store.Verify(Bind(), codes[2], Fp, 5));
        Assert.True(store.IsKnownCode(Bind().UserId, codes[2])); // still recognised as stale later
    }

    [Fact]
    public void Reissue_KeepsOnlyTheNewestCodes()
    {
        var store = Store();
        var codes = IssueDistinct(store, ChallengeStore.MaxCodesPerBinding + 1);
        Assert.Equal(VerifyResult.Stale, store.Verify(Bind(), codes[0], Fp, 5)); // dropped: known, not counted
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), codes[^1], Fp, 5));
    }

    [Fact]
    public void Reissue_EachCodeExpiresOnItsOwn()
    {
        var store = Store();
        var first = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        _time.Advance(TimeSpan.FromMinutes(6));
        string second;
        do
        {
            second = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        }
        while (second == first);

        _time.Advance(TimeSpan.FromMinutes(5)); // first expired, second still valid
        Assert.Equal(VerifyResult.Stale, store.Verify(Bind(), first, Fp, 5));
        Assert.Equal(_time.GetUtcNow() - TimeSpan.FromMinutes(5), store.GetIssuedAt(Bind())); // newest code
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), second, Fp, 5));
    }

    [Fact]
    public void Reissue_ResetsWrongEntries()
    {
        var store = Store();
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        var wrong = code == "00000000" ? "00000001" : "00000000";
        Assert.Equal(VerifyResult.WrongCode, store.Verify(Bind(), wrong, Fp, 2));
        var second = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        if (second != wrong)
        {
            Assert.Equal(VerifyResult.WrongCode, store.Verify(Bind(), wrong, Fp, 2));
            Assert.Equal(VerifyResult.Success, store.Verify(Bind(), code, Fp, 2));
        }
    }

    [Fact]
    public void Reissue_AfterPasswordChange_DropsEarlierCodes()
    {
        var store = Store();
        var first = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        var fp2 = ChallengeStore.Fingerprint("hash-2");
        string second;
        do
        {
            second = store.Issue(Bind(), fp2, TimeSpan.FromMinutes(10), 3);
        }
        while (second == first);

        Assert.Equal(VerifyResult.Stale, store.Verify(Bind(), first, fp2, 5));
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), second, fp2, 5));
    }

    [Fact]
    public void Reissue_RequiredIp_IsCheckedPerCode()
    {
        var store = Store();
        var first = IssueDistinct(store, 1, ip: "203.0.113.5")[0];
        string second;
        do
        {
            second = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3, "198.51.100.7");
        }
        while (second == first);

        Assert.Equal(VerifyResult.IpMismatch, store.Verify(Bind(), first, Fp, 5, "198.51.100.7"));
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), first, Fp, 5, "203.0.113.5"));
    }

    [Fact]
    public void Remove_DropsOnlyThatCode()
    {
        var store = Store();
        var codes = IssueDistinct(store, 2);
        store.Remove(Bind(), codes[1]);
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), codes[0], Fp, 5));

        var only = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        store.Remove(Bind(), only);
        Assert.False(store.HasPending(Bind()));
    }

    [Fact]
    public void StaleCodes_AreNotCountedAsWrongEntries()
    {
        var store = Store();
        var codes = IssueDistinct(store, ChallengeStore.MaxCodesPerBinding + 1);
        var first = codes[0]; // dropped from the pending codes, but known

        for (var i = 0; i < 10; i++)
        {
            Assert.Equal(VerifyResult.Stale, store.Verify(Bind(), first, Fp, 2));
        }

        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), codes[^1], Fp, 2));
    }

    [Fact]
    public void KnownCodes_ArePerUser_Bounded_AndForgotten()
    {
        var store = Store();
        var user = Bind().UserId;
        var codes = new List<string>();
        for (var i = 0; i < ChallengeStore.MaxKnownCodesPerUser + 1; i++)
        {
            codes.Add(store.Issue(Bind(device: "d" + i), Fp, TimeSpan.FromMinutes(10), 20));
        }

        Assert.True(store.IsKnownCode(user, codes[^1]));
        Assert.False(store.IsKnownCode(Guid.NewGuid(), codes[^1]));
        if (codes.Skip(1).All(c => c != codes[0]))
        {
            Assert.False(store.IsKnownCode(user, codes[0])); // oldest dropped
        }

        _time.Advance(ChallengeStore.KnownCodeLifetime);
        Assert.False(store.IsKnownCode(user, codes[^1]));
    }

    [Fact]
    public void RemoveUser_ForgetsKnownCodesAndGrants()
    {
        var store = Store();
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), code, Fp, 5));
        store.GrantReuse(Bind().UserId, code, Fp, 2, TimeSpan.FromMinutes(5));
        store.RemoveUser(Bind().UserId);
        Assert.False(store.IsKnownCode(Bind().UserId, code));
        Assert.False(store.HasReuseGrant(Bind().UserId));
        Assert.Equal(VerifyResult.NoChallenge, store.VerifyReuse(Bind().UserId, code, Fp, 5));
    }

    [Fact]
    public void Reuse_AnyDeviceOfTheUser_LimitedUses()
    {
        var store = Store();
        var user = Bind().UserId;
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), code, Fp, 5));
        Assert.Equal(VerifyResult.NoChallenge, store.VerifyReuse(user, code, Fp, 5)); // no grant yet

        store.GrantReuse(user, code, Fp, 2, TimeSpan.FromMinutes(5));
        Assert.Equal(VerifyResult.NoChallenge, store.VerifyReuse(Guid.NewGuid(), code, Fp, 5)); // other user
        Assert.Equal(VerifyResult.Success, store.VerifyReuse(user, code, Fp, 5));
        Assert.Equal(VerifyResult.Success, store.VerifyReuse(user, code, Fp, 5));
        Assert.Equal(VerifyResult.NoChallenge, store.VerifyReuse(user, code, Fp, 5)); // used up
        Assert.True(store.IsKnownCode(user, code));
    }

    [Fact]
    public void Reuse_Expires()
    {
        var store = Store();
        var user = Bind().UserId;
        store.GrantReuse(user, "12345678", Fp, 5, TimeSpan.FromMinutes(5));
        Assert.True(store.HasReuseGrant(user));
        _time.Advance(TimeSpan.FromMinutes(5));
        Assert.False(store.HasReuseGrant(user));
        Assert.Equal(VerifyResult.NoChallenge, store.VerifyReuse(user, "12345678", Fp, 5));
    }

    [Fact]
    public void Reuse_PasswordChange_RevokesGrant()
    {
        var store = Store();
        var user = Bind().UserId;
        store.GrantReuse(user, "12345678", Fp, 5, TimeSpan.FromMinutes(5));
        Assert.Equal(VerifyResult.PasswordChanged, store.VerifyReuse(user, "12345678", ChallengeStore.Fingerprint("hash-2"), 5));
        Assert.Equal(VerifyResult.NoChallenge, store.VerifyReuse(user, "12345678", Fp, 5));
    }

    [Fact]
    public void Reuse_WrongCodes_RevokeGrantAfterMaxAttempts()
    {
        var store = Store();
        var user = Bind().UserId;
        store.GrantReuse(user, "12345678", Fp, 5, TimeSpan.FromMinutes(5));
        Assert.Equal(VerifyResult.WrongCode, store.VerifyReuse(user, "00000000", Fp, 2));
        Assert.Equal(VerifyResult.TooManyAttempts, store.VerifyReuse(user, "00000001", Fp, 2));
        Assert.Equal(VerifyResult.NoChallenge, store.VerifyReuse(user, "12345678", Fp, 2));
    }

    [Fact]
    public void Reuse_ZeroUses_NoGrant()
    {
        var store = Store();
        store.GrantReuse(Bind().UserId, "12345678", Fp, 0, TimeSpan.FromMinutes(5));
        Assert.False(store.HasReuseGrant(Bind().UserId));
    }

    [Fact]
    public void MaxPendingPerUser_EvictsOldest()
    {
        var store = Store();
        var codes = new List<string>();
        for (var i = 0; i < 4; i++)
        {
            codes.Add(store.Issue(Bind(device: "d" + i), Fp, TimeSpan.FromMinutes(10), 3));
            _time.Advance(TimeSpan.FromSeconds(1));
        }

        Assert.Equal(3, store.Count);
        Assert.Equal(VerifyResult.NoChallenge, store.Verify(Bind(device: "d0"), codes[0], Fp, 5));
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(device: "d3"), codes[3], Fp, 5));
    }

    [Fact]
    public void RemoveUser_DropsAllCodesOfUser()
    {
        var store = Store();
        var other = Guid.NewGuid();
        store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        store.Issue(Bind(device: "x"), Fp, TimeSpan.FromMinutes(10), 3);
        store.Issue(Bind(user: other), Fp, TimeSpan.FromMinutes(10), 3);
        store.RemoveUser(Bind().UserId);
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void RequiredIp_MustMatchIssuingIp()
    {
        var store = Store();
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3, "203.0.113.5");
        Assert.Equal(VerifyResult.IpMismatch, store.Verify(Bind(), code, Fp, 5, "198.51.100.7"));
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), code, Fp, 5, "203.0.113.5"));
    }

    [Fact]
    public void RequiredIp_WithoutStoredIp_IsRejected()
    {
        var store = Store();
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        Assert.Equal(VerifyResult.IpMismatch, store.Verify(Bind(), code, Fp, 5, "203.0.113.5"));
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), code, Fp, 5)); // no IP requirement: password+code path
    }

    [Fact]
    public void IpMismatch_CountsAsAttempt()
    {
        var store = Store();
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3, "203.0.113.5");
        Assert.Equal(VerifyResult.IpMismatch, store.Verify(Bind(), code, Fp, 2, "198.51.100.7"));
        Assert.Equal(VerifyResult.TooManyAttempts, store.Verify(Bind(), code, Fp, 2, "198.51.100.7"));
        Assert.Equal(VerifyResult.NoChallenge, store.Verify(Bind(), code, Fp, 2, "203.0.113.5"));
    }

    [Fact]
    public void ParallelRedemption_OnlyOneSucceeds()
    {
        var store = Store();
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        var results = new System.Collections.Concurrent.ConcurrentBag<VerifyResult>();
        Parallel.For(0, 32, _ => results.Add(store.Verify(Bind(), code, Fp, 5)));
        Assert.Equal(1, results.Count(r => r == VerifyResult.Success));
    }
}
