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
            Client = "Test Client",
            Device = "Test Device",
            Version = "1.0",
        }),
    };

    private void Request(string path = "/Users/AuthenticateByName", string ip = "203.0.113.5", string device = "dev-1", bool authenticated = false)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "POST";
        ctx.Request.Path = path;
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(ip);
        ctx.Items["dev"] = device;
        if (authenticated)
        {
            ctx.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("x", "y") }, "test"));
        }

        OriginCaptureMiddleware.Set(ctx, new RequestOrigin(IPAddress.Parse("192.168.1.10"), !_trusted));
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

        Request();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth(Password + (code == "00000000" ? "00000001" : "00000000")));

        Request();
        var ok = await Auth(Password + code);
        Assert.Equal("alice", ok.Username);
        Assert.True(_approvals.TryConsume(_user.Id, "dev-1"));

        Request();
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth(Password + code)); // replay
    }

    [Fact]
    public async Task Remote_CodeFromOtherDevice_Rejected()
    {
        Request(device: "dev-1");
        await Assert.ThrowsAsync<SecurityException>(() => Auth(Password));
        var code = Assert.Single(_notifications.Codes);
        Request(device: "dev-2");
        await Assert.ThrowsAsync<AuthenticationException>(() => Auth(Password + code));
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
            await Assert.ThrowsAsync<AuthenticationException>(() => Auth(Password + _notifications.Codes[0]));
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
        await Assert.ThrowsAsync<AuthenticationException>(() => Provider().Authenticate("alice", "NewPassword9" + code, _user));
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

    public bool SendCode(string email, string userName, string code, string? device, string? client, string? clientIp, int lifetimeMinutes)
    {
        Codes.Add(code);
        return true;
    }

    public void NotifyQuickConnect(string email, string userName, string? device, string? client, string? approverIp) => QuickConnect.Add(email);

    public void AlertAdmin(string key, string subject, string body) => Alerts.Add(subject + ": " + body);
}
