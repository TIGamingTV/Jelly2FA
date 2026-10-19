using System.Net;
using System.Security.Claims;
using System.Text;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.Jelly2FA.Configuration;
using Jellyfin.Plugin.Jelly2FA.Services;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Net;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.Jelly2FA.Tests;

public class ProviderTests
{
    private const string Password = "CorrectHorse1";

    private readonly FakeTimeProvider _time = new(DateTimeOffset.Parse("2026-10-17T12:00:00Z"));
    private readonly PluginConfiguration _config = new();
    private readonly FakeNotifications _notifications = new();
    private readonly IEmailSender _email = Substitute.For<IEmailSender>();
    private readonly IOriginClassifier _origin = Substitute.For<IOriginClassifier>();
    private readonly ChallengeStore _store;
    private readonly RateLimiter _limiter;
    private readonly LoginApprovalRegistry _approvals;
    private readonly HttpContextAccessor _accessor = new();
    private readonly User _user;
    private bool _trusted;

    public ProviderTests()
    {
        _store = new ChallengeStore(_time);
        _limiter = new RateLimiter(_time);
        _approvals = new LoginApprovalRegistry(_time);
        _email.IsConfigured.Returns(true);
        _origin.Classify(Arg.Any<RequestOrigin?>()).Returns(_ => new OriginDecision(_trusted, "test"));
        _user = new User("alice", ProviderIds.Jelly2Fa, "reset") { Password = FakeCrypto.Hash(Password) };
        _config.Users = new[] { new EnrolledUser { UserId = _user.Id, Email = "alice@example.com" } };
    }

    private TwoFactorAuthenticationProvider Provider() => new(
        _accessor,
        Substitute.For<IServiceProvider>(),
        new FakeCrypto(),
        _origin,
        _store,
        _limiter,
        _approvals,
        _notifications,
        _email,
        new TestConfigProvider(_config),
        NullLogger<TwoFactorAuthenticationProvider>.Instance,
        _time)
    {
        AuthorizationInfoOverride = ctx => Task.FromResult(new AuthorizationInfo
        {
            DeviceId = (string?)ctx.Items["dev"] ?? "dev-1",
            Client = (string?)ctx.Items["client"] ?? "Test Client",
            Device = "Test Device",
            Version = "1.0",
        }),
    };

    private void Request(string path = "/Users/AuthenticateByName", string ip = "203.0.113.5", string device = "dev-1", bool authenticated = false, string client = "Test Client", string peer = "192.168.1.10")
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "POST";
        ctx.Request.Path = path;
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(ip);
        ctx.Items["dev"] = device;
        ctx.Items["client"] = client;
        if (authenticated)
        {
            ctx.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("x", "y") }, "test"));
        }

        OriginCaptureMiddleware.Set(ctx, new RequestOrigin(IPAddress.Parse(peer), !_trusted));
        _accessor.HttpContext = ctx;
    }

    private Task<ProviderAuthenticationResult> Auth(string pw) => Provider().Authenticate("alice", pw, _user);

    [Fact]
    public async Task TrustedDirect_PasswordOnly()
    {
        _trusted = true;
        Request();
        var result = await Auth(Password);
        Assert.Equal("alice", result.Username);
        Assert.Empty(_notifications.Codes);
        Assert.True(_approvals.TryConsume(_user.Id, "dev-1"));
    }

    [Fact]
    public async Task TrustedDirect_WrongPassword_401()
    {
        _trusted = true;
        Request();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth("wrong"));
    }

    [Fact]
    public async Task Remote_FullFlow()
    {
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        var code = Assert.Single(_notifications.Codes);

        // Correct password + wrong code: 403 (not a failed sign-in for Jellyfin), message says the password was right.
        Request();
        var wrong = await Assert.ThrowsAsync<SecurityException>(() => Auth(Password + (code == "00000000" ? "00000001" : "00000000")));
        Assert.Contains("password correct", wrong.Message, StringComparison.Ordinal);

        Request();
        var ok = await Auth(Password + code);
        Assert.Equal("alice", ok.Username);
        Assert.True(_approvals.TryConsume(_user.Id, "dev-1"));

        Request();
        var replay = await Assert.ThrowsAsync<SecurityException>(() => Auth(Password + code)); // replay: stale, no token
        Assert.Contains("no longer valid", replay.Message, StringComparison.Ordinal);
        Assert.False(_approvals.TryConsume(_user.Id, "dev-1"));
    }

    [Fact]
    public async Task Remote_FirstStep_MessageSaysPasswordCorrect()
    {
        Request();
        var ex = await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Assert.Contains("password correct, a sign-in code was sent", ex.Message, StringComparison.Ordinal);
        Request();
        ex = await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Assert.Contains("already sent", ex.Message, StringComparison.Ordinal); // cooldown
    }

    [Fact]
    public async Task Remote_CodeFromOtherDevice_Rejected()
    {
        Request(device: "dev-1");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        var code = Assert.Single(_notifications.Codes);
        Request(device: "dev-2");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password + code)); // password correct: 403, no token
        Assert.False(_approvals.TryConsume(_user.Id, "dev-2"));
        Request(device: "dev-1");
        await Auth(Password + code); // still pending for the requesting device
    }

    [Fact]
    public async Task Remote_CorrectPasswordWithoutPendingCode_403_NotCounted()
    {
        for (var i = 0; i < 15; i++)
        {
            Request();
            var ex = await Assert.ThrowsAsync<SecurityException>(() => Auth(Password + "12345678"));
            Assert.Contains("no code is pending", ex.Message, StringComparison.Ordinal);
        }

        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Assert.Single(_notifications.Codes); // not throttled
    }

    [Fact]
    public async Task Remote_CorrectPasswordWrongCode_CountsForThrottle()
    {
        _config.MaxCodeAttempts = 100;
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        var code = _notifications.Codes.Single();
        var wrong = code == "00000000" ? "00000001" : "00000000";
        for (var i = 0; i < 10; i++)
        {
            Request();
            var ex = await Assert.ThrowsAsync<SecurityException>(() => Auth(Password + wrong));
            Assert.Contains("code is wrong", ex.Message, StringComparison.Ordinal);
        }

        Request();
        var throttled = await Assert.ThrowsAsync<SecurityException>(() => Auth(Password + code));
        Assert.Contains("Too many", throttled.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Remote_WrongPasswordWithCode_401()
    {
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Request();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth("wrongpw" + _notifications.Codes.Single()));
    }

    [Fact]
    public async Task Remote_WrongPassword_NoEmail()
    {
        Request();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth("wrong"));
        Assert.Empty(_notifications.Codes);
    }

    [Fact]
    public async Task Remote_CodeWithWrongPassword_Rejected()
    {
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        var code = _notifications.Codes.Single();
        Request();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth("wrongpw" + code));
    }

    [Fact]
    public async Task Remote_ResendCooldown_And_EmailBudget()
    {
        _config.MaxEmailsPerUserPerHour = 2;
        for (var i = 0; i < 5; i++)
        {
            Request();
            await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        }

        Assert.Single(_notifications.Codes); // cooldown
        _time.Advance(TimeSpan.FromSeconds(61));
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        _time.Advance(TimeSpan.FromSeconds(61));
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Assert.Equal(2, _notifications.Codes.Count); // budget of 2 per hour
    }

    [Fact]
    public async Task Remote_NewCodeInvalidatesOldOne()
    {
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        _time.Advance(TimeSpan.FromSeconds(61));
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Assert.Equal(2, _notifications.Codes.Count);
        if (_notifications.Codes[0] != _notifications.Codes[1])
        {
            Request();
            var ex = await Assert.ThrowsAsync<SecurityException>(() => Auth(Password + _notifications.Codes[0]));
            Assert.Contains("no longer valid", ex.Message, StringComparison.Ordinal);
        }

        Request();
        await Auth(Password + _notifications.Codes[1]);
    }

    [Fact]
    public async Task Remote_NotEnrolled_403AndAdminAlert()
    {
        _config.Users = Array.Empty<EnrolledUser>();
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Assert.Empty(_notifications.Codes);
        Assert.NotEmpty(_notifications.Alerts);
    }

    [Fact]
    public async Task Remote_SmtpNotConfigured_NoCodeButAlert()
    {
        _email.IsConfigured.Returns(false);
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Assert.Empty(_notifications.Codes);
        Assert.Contains(_notifications.Alerts, a => a.Contains("SMTP", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Remote_PasswordChangedWhilePending_CodeInvalid()
    {
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        var code = _notifications.Codes.Single();
        _user.Password = FakeCrypto.Hash("NewPassword9"); // hash changed by someone else
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Provider().Authenticate("alice", "NewPassword9" + code, _user));
        Assert.False(_approvals.TryConsume(_user.Id, "dev-1"));
        Request();
        await Assert.ThrowsAsync<AuthenticationException>(() => Provider().Authenticate("alice", Password + code, _user)); // old password
    }

    [Fact]
    public async Task Throttling_After10Failures_Returns403()
    {
        for (var i = 0; i < 10; i++)
        {
            Request();
            await Assert.ThrowsAsync<AuthenticationException>(() => Auth("wrong" + i));
        }

        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Assert.Empty(_notifications.Codes);

        _time.Advance(TimeSpan.FromMinutes(16));
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Assert.Single(_notifications.Codes); // window passed: code issued again
    }

    [Fact]
    public async Task UnknownCaller_Denied()
    {
        _trusted = true;
        Request(path: "/Some/Plugin/Login");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        _accessor.HttpContext = null;
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
    }

    [Fact]
    public async Task PasswordChangeCheck_PasswordOnlyEvenRemote()
    {
        Request(path: "/Users/Password", authenticated: true);
        await Auth(Password);
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth("wrong"));
        Assert.Empty(_notifications.Codes);
    }

    [Fact]
    public async Task Remote_UserWithoutPassword_Denied()
    {
        _user.Password = null;
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(string.Empty));
    }

    [Fact]
    public async Task NullUser_401()
    {
        Request();
        await Assert.ThrowsAsync<AuthenticationException>(() => Provider().Authenticate("ghost", Password, null));
    }

    [Fact]
    public async Task CodeOnly_DisabledByDefault_Rejected()
    {
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        var code = _notifications.Codes.Single();
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(code)); // known code: 403, but never accepted alone
        Assert.False(_approvals.TryConsume(_user.Id, "dev-1"));
        Request();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth("12345678" == code ? "87654321" : "12345678")); // unknown code: 401
        Request();
        await Auth(Password + code); // code was not consumed
    }

    [Fact]
    public async Task CodeOnly_Enabled_SameIp_Succeeds()
    {
        _config.AllowCodeOnlySecondStep = true;
        Request();
        var ex = await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Assert.Contains("code", ex.Message, StringComparison.Ordinal);
        var code = _notifications.Codes.Single();

        Request();
        var ok = await Auth(code);
        Assert.Equal("alice", ok.Username);
        Assert.True(_approvals.TryConsume(_user.Id, "dev-1"));

        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(code)); // replay: stale (403), no token
        Assert.False(_approvals.TryConsume(_user.Id, "dev-1"));
    }

    [Fact]
    public async Task CodeOnly_Enabled_OtherIp_Rejected()
    {
        _config.AllowCodeOnlySecondStep = true;
        Request(ip: "203.0.113.5");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        var code = _notifications.Codes.Single();
        Request(ip: "198.51.100.7");
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth(code));
    }

    [Fact]
    public async Task CodeOnly_Enabled_OtherDevice_Rejected()
    {
        _config.AllowCodeOnlySecondStep = true;
        Request(device: "dev-1");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        var code = _notifications.Codes.Single();
        Request(device: "dev-2");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(code)); // known code, but not for this device: 403, no token
        Assert.False(_approvals.TryConsume(_user.Id, "dev-2"));
    }

    [Fact]
    public async Task CodeOnly_Enabled_WrongCodes_InvalidateAndCountAsFailures()
    {
        _config.AllowCodeOnlySecondStep = true;
        _config.MaxCodeAttempts = 2;
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        var code = _notifications.Codes.Single();
        var wrong = code == "00000000" ? "00000001" : "00000000";
        for (var i = 0; i < 2; i++)
        {
            Request();
            await Assert.ThrowsAsync<AuthenticationException>(() => Auth(wrong));
        }

        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(code)); // invalidated after 2 wrong entries (stale now)
        Assert.False(_approvals.TryConsume(_user.Id, "dev-1"));
    }

    [Fact]
    public async Task CodeOnly_Enabled_WithoutPendingCode_Rejected()
    {
        _config.AllowCodeOnlySecondStep = true;
        Request();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth("12345678"));
        Assert.Empty(_notifications.Codes);
    }

    [Fact]
    public async Task CodeOnly_Enabled_PasswordPlusCodeStillWorks()
    {
        _config.AllowCodeOnlySecondStep = true;
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Request();
        await Auth(Password + _notifications.Codes.Single());
    }

    [Fact]
    public async Task CodeOnly_Enabled_EightDigitPassword_StillIssuesCode()
    {
        _config.AllowCodeOnlySecondStep = true;
        _user.Password = FakeCrypto.Hash("87654321");
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth("87654321"));
        var code = _notifications.Codes.Single();
        Request();
        await Auth(code);
    }

    [Fact]
    public async Task RemoteFailures_DoNotLockUserOutOfLan()
    {
        // 10 wrong passwords through the proxy exhaust the per-user bucket...
        for (var i = 0; i < 10; i++)
        {
            Request(ip: "203.0.113." + (10 + i));
            await Assert.ThrowsAsync<AuthenticationException>(() => Auth("wrong" + i));
        }

        Request(ip: "203.0.113.99");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password)); // remote: throttled

        // ...but a direct LAN sign-in still works (only the per-IP bucket applies there).
        _trusted = true;
        Request(ip: "192.168.1.50");
        Assert.Equal("alice", (await Auth(Password)).Username);
    }

    [Fact]
    public async Task LanFailures_ThrottledPerIp_NotPerUser()
    {
        _trusted = true;
        for (var i = 0; i < 10; i++)
        {
            Request(ip: "192.168.1.50");
            await Assert.ThrowsAsync<AuthenticationException>(() => Auth("wrong" + i));
        }

        Request(ip: "192.168.1.50");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password)); // that LAN IP is throttled

        Request(ip: "192.168.1.51");
        Assert.Equal("alice", (await Auth(Password)).Username); // the user is not
    }

    [Fact]
    public async Task Ipv6_ThrottledPer64()
    {
        for (var i = 0; i < 10; i++)
        {
            Request(ip: "2001:db8:1:2::" + (i + 1).ToString("x", System.Globalization.CultureInfo.InvariantCulture));
            await Assert.ThrowsAsync<AuthenticationException>(() => Auth("wrong" + i));
        }

        _config.MaxFailuresPerUser = 1000; // isolate the per-IP bucket
        Request(ip: "2001:db8:1:2:ffff::1");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password)); // same /64
        Request(ip: "2001:db8:1:3::1");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password)); // other /64: not throttled, code required
        Assert.Single(_notifications.Codes);
    }

    [Fact]
    public async Task ParallelWrongPasswords_CannotExceedTheLimit()
    {
        // Every attempt takes its slot before verifying, so concurrent attempts cannot all pass the check.
        var provider = Provider();
        var results = await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(async () =>
        {
            var ctx = new DefaultHttpContext();
            ctx.Request.Method = "POST";
            ctx.Request.Path = "/Users/AuthenticateByName";
            ctx.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.5");
            ctx.Items["dev"] = "dev-1";
            OriginCaptureMiddleware.Set(ctx, new RequestOrigin(IPAddress.Parse("192.168.1.10"), true));
            _accessor.HttpContext = ctx;
            try
            {
                await provider.Authenticate("alice", "wrong" + i, _user);
                return "ok";
            }
            catch (AuthenticationException)
            {
                return "401";
            }
            catch (SecurityException)
            {
                return "403";
            }
        })));

        Assert.Equal(10, results.Count(r => r == "401"));
        Assert.Equal(30, results.Count(r => r == "403"));
    }

    [Fact]
    public async Task SuccessfulSignIns_DoNotUseUpTheLimit()
    {
        _trusted = true;
        for (var i = 0; i < 25; i++)
        {
            Request(ip: "192.168.1.50");
            await Auth(Password);
        }

        Request(ip: "192.168.1.50");
        Assert.Equal("alice", (await Auth(Password)).Username);
    }

    [Fact]
    public async Task CodeEmailNotQueued_NoPendingCode_RetrySendsAgain()
    {
        _notifications.Accept = false;
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Assert.Equal(0, _store.Count); // no code that nobody received

        _notifications.Accept = true;
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password)); // no resend cooldown in the way
        Assert.Equal(2, _notifications.Codes.Count);
        Assert.Equal(1, _store.Count);
    }

    [Fact]
    public async Task PasswordChangeCheck_IsThrottledPerUser()
    {
        for (var i = 0; i < 10; i++)
        {
            Request(path: "/Users/Password", authenticated: true);
            await Assert.ThrowsAsync<AuthenticationException>(() => Auth("wrong" + i));
        }

        Request(path: "/Users/Password", authenticated: true);
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
    }

    // ---- code reuse (Neptune signs in, then passes the same credentials to Seerr) ----

    private async Task<string> NeptuneSignsIn(bool codeOnly = true)
    {
        Request(device: "neptune-1", client: "Neptune");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        var code = _notifications.Codes[^1];
        Request(device: "neptune-1", client: "Neptune");
        await Auth(codeOnly ? code : Password + code);
        Assert.True(_approvals.TryConsume(_user.Id, "neptune-1"));
        return code;
    }

    private void SeerrRequest(string device = "Qk9UX3NlZXJyX2FsaWNl", string client = "Seerr", string ip = "198.51.100.20", string peer = "192.168.1.10")
        => Request(device: device, client: client, ip: ip, peer: peer);

    private void EnableReuse(int count = 2)
    {
        _config.AllowCodeOnlySecondStep = true;
        _config.CodeReuseCount = count;
        _config.CodeReuseMinutes = 5;
    }

    [Fact]
    public async Task Reuse_OffByDefault_SeerrGetsStale403()
    {
        _config.AllowCodeOnlySecondStep = true;
        var code = await NeptuneSignsIn();
        SeerrRequest();
        var ex = await Assert.ThrowsAsync<SecurityException>(() => Auth(code));
        Assert.Contains("no longer valid", ex.Message, StringComparison.Ordinal);
        Assert.False(_approvals.TryConsume(_user.Id, "Qk9UX3NlZXJyX2FsaWNl"));
    }

    [Fact]
    public async Task Reuse_Seerr_CodeOnly_OtherDeviceAndIp_LimitedUses()
    {
        EnableReuse(count: 2);
        var code = await NeptuneSignsIn();

        SeerrRequest();
        Assert.Equal("alice", (await Auth(code)).Username);
        Assert.True(_approvals.TryConsume(_user.Id, "Qk9UX3NlZXJyX2FsaWNl"));

        SeerrRequest(client: "seerr", device: "other-seerr-device", ip: "198.51.100.21");
        await Auth(code); // second reuse, case-insensitive app name

        SeerrRequest();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(code)); // used up: stale 403
    }

    [Fact]
    public async Task Reuse_UnlistedApp_AndOriginalDevice_CannotReuse()
    {
        EnableReuse();
        var code = await NeptuneSignsIn();
        SeerrRequest(client: "Overseerr");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(code));
        Request(device: "neptune-1", client: "Neptune");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(code));
        Assert.False(_approvals.TryConsume(_user.Id, "neptune-1"));
        SeerrRequest();
        await Auth(code); // grant untouched by the refused attempts
    }

    [Fact]
    public async Task Reuse_WindowExpires()
    {
        EnableReuse();
        var code = await NeptuneSignsIn();
        _time.Advance(TimeSpan.FromMinutes(5));
        SeerrRequest();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(code));
    }

    [Fact]
    public async Task Reuse_CodeAlone_OnlyWithCodeOnlyOption()
    {
        _config.CodeReuseCount = 2;
        var code = await NeptuneSignsIn(codeOnly: false);
        SeerrRequest();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(code)); // code alone never accepted without the option
        SeerrRequest();
        await Auth(Password + code); // password + code is
    }

    [Fact]
    public async Task Reuse_PasswordPlusCode_WrongPassword_401()
    {
        _config.CodeReuseCount = 2;
        var code = await NeptuneSignsIn(codeOnly: false);
        SeerrRequest();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth("wrong" + code));
    }

    [Fact]
    public async Task Reuse_AddressFilter_UsesRealPeer()
    {
        EnableReuse();
        _config.CodeReuseAddresses = "10.0.0.5";
        var code = await NeptuneSignsIn();
        SeerrRequest(peer: "192.168.1.10", ip: "10.0.0.5"); // the forwarded client IP does not count
        await Assert.ThrowsAsync<SecurityException>(() => Auth(code));
        SeerrRequest(peer: "10.0.0.5");
        await Auth(code);
    }

    [Fact]
    public async Task Reuse_WrongCodesFromListedApp_Counted_AndRevokeGrant()
    {
        EnableReuse();
        _config.MaxCodeAttempts = 2;
        var code = await NeptuneSignsIn();
        var wrong = code == "00000000" ? "00000001" : "00000000";
        SeerrRequest();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth(wrong));
        SeerrRequest();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth(wrong));
        SeerrRequest();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(code)); // grant revoked, code only stale
        Assert.False(_store.HasReuseGrant(_user.Id));
    }

    [Fact]
    public async Task Reuse_PasswordChange_EndsGrant()
    {
        EnableReuse();
        var code = await NeptuneSignsIn();
        await Provider().ChangePassword(_user, "Another1");
        SeerrRequest();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth(code)); // grant and known codes dropped
    }

    [Fact]
    public async Task Reuse_DirectConnection_CodeOnly()
    {
        EnableReuse();
        var code = await NeptuneSignsIn();
        _trusted = true; // Seerr retries without X-Forwarded-For from a LAN address
        SeerrRequest(ip: "192.168.1.30", peer: "192.168.1.30");
        await Auth(code);
    }

    [Fact]
    public async Task StaleCodes_AreNotCountedAsFailures()
    {
        _config.AllowCodeOnlySecondStep = true;
        var code = await NeptuneSignsIn();
        for (var i = 0; i < 20; i++)
        {
            SeerrRequest();
            await Assert.ThrowsAsync<SecurityException>(() => Auth(code));
            Request(device: "neptune-1", client: "Neptune");
            await Assert.ThrowsAsync<SecurityException>(() => Auth(Password + code));
        }

        _time.Advance(TimeSpan.FromSeconds(61));
        await NeptuneSignsIn(); // neither the IP nor the user is throttled
    }

    [Fact]
    public async Task Direct_PasswordFollowedByCode_IsPasswordOnly()
    {
        _trusted = true;
        Request();
        await Auth(Password + "12345678");
        Assert.True(_approvals.TryConsume(_user.Id, "dev-1"));
        Request();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth("wrong" + "12345678"));
    }

    [Fact]
    public async Task Direct_StaleCodeOnly_403_UnknownCode_401()
    {
        var code = await NeptuneSignsIn(codeOnly: false);
        _trusted = true;
        Request(ip: "192.168.1.30", peer: "192.168.1.30");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(code));
        Request(ip: "192.168.1.30", peer: "192.168.1.30");
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth(code == "12345678" ? "87654321" : "12345678"));
    }

    [Fact]
    public async Task ChangePassword_HashesAndDropsCodes()
    {
        Request();
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        Assert.Equal(1, _store.Count);
        await Provider().ChangePassword(_user, "Another1");
        Assert.Equal(FakeCrypto.Hash("Another1"), _user.Password);
        Assert.Equal(0, _store.Count);
    }
}

internal sealed class FakeCrypto : ICryptoProvider
{
    public string DefaultHashMethod => "TEST";

    public static string Hash(string pw) => new PasswordHash("TEST", Encoding.UTF8.GetBytes(pw)).ToString();

    public PasswordHash CreatePasswordHash(ReadOnlySpan<char> password) => PasswordHash.Parse(Hash(password.ToString()));

    public bool Verify(PasswordHash hash, ReadOnlySpan<char> password) => hash.Hash.SequenceEqual(Encoding.UTF8.GetBytes(password.ToString()));

    public byte[] GenerateSalt() => new byte[16];

    public byte[] GenerateSalt(int length) => new byte[length];
}

internal sealed class FakeNotifications : INotificationService
{
    public List<string> Codes { get; } = new();

    public List<string> Alerts { get; } = new();

    public List<string> QuickConnect { get; } = new();

    /// <summary>Gets or sets a value indicating whether code emails are accepted (false = queue full).</summary>
    public bool Accept { get; set; } = true;

    public bool SendCode(string email, string userName, string code, string? device, string? client, string? clientIp, int lifetimeMinutes)
    {
        Codes.Add(code);
        return Accept;
    }

    public void NotifyQuickConnect(string email, string userName, string? device, string? client, string? approverIp) => QuickConnect.Add(email);

    public void AlertAdmin(string key, string subject, string body) => Alerts.Add(subject + ": " + body);
}
