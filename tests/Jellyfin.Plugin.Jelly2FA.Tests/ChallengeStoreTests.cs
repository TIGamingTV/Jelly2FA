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

    [Fact]
    public void Reissue_ReplacesPreviousCode()
    {
        var store = Store();
        var first = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        string second;
        do
        {
            second = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        }
        while (second == first);

        Assert.Equal(VerifyResult.WrongCode, store.Verify(Bind(), first, Fp, 5));
        Assert.Equal(VerifyResult.Success, store.Verify(Bind(), second, Fp, 5));
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
    public void ParallelRedemption_OnlyOneSucceeds()
    {
        var store = Store();
        var code = store.Issue(Bind(), Fp, TimeSpan.FromMinutes(10), 3);
        var results = new System.Collections.Concurrent.ConcurrentBag<VerifyResult>();
        Parallel.For(0, 32, _ => results.Add(store.Verify(Bind(), code, Fp, 5)));
        Assert.Equal(1, results.Count(r => r == VerifyResult.Success));
    }
}
