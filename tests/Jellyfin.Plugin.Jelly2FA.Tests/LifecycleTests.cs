using System.Net;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.Jelly2FA.Configuration;
using Jellyfin.Plugin.Jelly2FA.Services;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Configuration;
using MediaBrowser.Model.Dto;
using MediaBrowser.Model.Users;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.Jelly2FA.Tests;

/// <summary>Plugin disable/enable/uninstall support and the shared provider switch.</summary>
public sealed class LifecycleTests : IDisposable
{
    private const string Pid = Plugin.PluginGuid;
    private static readonly Version Running = new(0, 0, 2, 0);

    private readonly string _folder = Path.Combine(Path.GetTempPath(), "j2fa-tests-" + Guid.NewGuid().ToString("N"));
    private readonly IUserManager _users = Substitute.For<IUserManager>();
    private readonly ISessionManager _sessions = Substitute.For<ISessionManager>();
    private readonly FakeNotifications _notifications = new();
    private readonly PluginConfiguration _config = new();
    private readonly ChallengeStore _challenges = new(new FakeTimeProvider());
    private readonly List<User> _all = new();
    private readonly SuspensionStore _store;

    public LifecycleTests()
    {
        Directory.CreateDirectory(_folder);
        _store = new SuspensionStore(NullLogger<SuspensionStore>.Instance, () => _folder);
        _users.GetUsers().Returns(_ => _all);
        _users.GetUserById(Arg.Any<Guid>()).Returns(ci => _all.FirstOrDefault(u => u.Id == ci.Arg<Guid>()));
        _users.GetUserDto(Arg.Any<User>(), Arg.Any<string?>()).Returns(ci =>
        {
            var u = ci.Arg<User>();
            return new UserDto
            {
                Id = u.Id,
                Policy = new UserPolicy
                {
                    AuthenticationProviderId = u.AuthenticationProviderId,
                    PasswordResetProviderId = u.PasswordResetProviderId,
                    LoginAttemptsBeforeLockout = u.LoginAttemptsBeforeLockout ?? -1,
                },
            };
        });

        // Emulates Jellyfin: the policy update sets the provider and the lockout.
        _users.UpdatePolicyAsync(Arg.Any<Guid>(), Arg.Any<UserPolicy>()).Returns(ci =>
        {
            var u = _all.Single(x => x.Id == ci.Arg<Guid>());
            var p = ci.Arg<UserPolicy>();
            u.AuthenticationProviderId = p.AuthenticationProviderId;
            u.LoginAttemptsBeforeLockout = p.LoginAttemptsBeforeLockout switch { -1 => null, 0 => 3, var n => n };
            return Task.CompletedTask;
        });
    }

    public void Dispose() => Directory.Delete(_folder, true);

    private User AddUser(string name, string provider, bool enrolled = true)
    {
        var user = new User(name, provider, "reset") { Password = "x", InvalidLoginAttemptCount = 11 };
        _all.Add(user);
        if (enrolled)
        {
            _config.Users = _config.Users.Append(new EnrolledUser { UserId = user.Id, Email = name + "@example.com" }).ToArray();
        }

        return user;
    }

    private PluginStateService State() => new(_users, _sessions, new TestConfigProvider(_config), _challenges, _store, _notifications, NullLogger<PluginStateService>.Instance);

    // ---- request matching ----

    [Theory]
    [InlineData("POST", "/Plugins/" + Pid + "/0.0.2.0/Disable", PluginStateMiddleware.PluginAction.Disable)]
    [InlineData("POST", "/plugins/" + Pid + "/0.0.2.0/disable/", PluginStateMiddleware.PluginAction.Disable)]
    [InlineData("POST", "/jellyfin/Plugins/" + Pid + "/0.0.2.0/Disable", PluginStateMiddleware.PluginAction.Disable)] // base URL
    [InlineData("POST", "/Plugins/aeb8e07d22274d18ad2f7f49c81db71b/0.0.2.0/Disable", PluginStateMiddleware.PluginAction.Disable)]
    [InlineData("POST", "/Plugins/" + Pid + "/0.0.2.0/Enable", PluginStateMiddleware.PluginAction.Enable)]
    [InlineData("GET", "/Plugins/" + Pid + "/0.0.2.0/Disable", PluginStateMiddleware.PluginAction.None)]
    [InlineData("POST", "/Plugins/" + Pid + "/0.0.1.0/Disable", PluginStateMiddleware.PluginAction.None)] // other installed version
    [InlineData("POST", "/Plugins/11111111-2222-3333-4444-555555555555/0.0.2.0/Disable", PluginStateMiddleware.PluginAction.None)]
    [InlineData("POST", "/Plugins/" + Pid + "/0.0.2.0/Disable/x", PluginStateMiddleware.PluginAction.None)]
    [InlineData("POST", "/Plugins/" + Pid + "/Disable", PluginStateMiddleware.PluginAction.None)]
    [InlineData("POST", "/Users/AuthenticateByName", PluginStateMiddleware.PluginAction.None)]
    public void Classify(string method, string path, PluginStateMiddleware.PluginAction expected)
        => Assert.Equal(expected, PluginStateMiddleware.Classify(method, path, Running));

    [Fact]
    public void Classify_WithoutRunningVersion_None()
        => Assert.Equal(PluginStateMiddleware.PluginAction.None, PluginStateMiddleware.Classify("POST", "/Plugins/" + Pid + "/0.0.2.0/Disable", null));

    // ---- provider switch ----

    [Fact]
    public async Task ToDefault_RestoresLockoutAndResetsCounter()
    {
        var user = AddUser("alice", ProviderIds.Jelly2Fa);
        user.LoginAttemptsBeforeLockout = null; // lockout off while enrolled
        Assert.True(await ProviderSwitch.ToDefaultAsync(_users, user));
        Assert.Equal(ProviderIds.Default, user.AuthenticationProviderId);
        Assert.Equal(3, user.LoginAttemptsBeforeLockout);
        Assert.Equal(0, user.InvalidLoginAttemptCount);
        await _users.Received().UpdateUserAsync(user);
    }

    [Fact]
    public async Task ToDefault_IgnoresUsersOnOtherProviders()
    {
        var user = AddUser("bob", "Some.Ldap.Provider");
        Assert.False(await ProviderSwitch.ToDefaultAsync(_users, user));
        Assert.Equal("Some.Ldap.Provider", user.AuthenticationProviderId);
    }

    [Fact]
    public async Task ToJelly2Fa_DisablesLockoutAndResetsCounter()
    {
        var user = AddUser("alice", ProviderIds.Default);
        await ProviderSwitch.ToJelly2FaAsync(_users, user);
        Assert.Equal(ProviderIds.Jelly2Fa, user.AuthenticationProviderId);
        Assert.Null(user.LoginAttemptsBeforeLockout);
        Assert.Equal(0, user.InvalidLoginAttemptCount);
    }

    // ---- disable / enable ----

    [Fact]
    public async Task Suspend_HandsBackEveryoneOnTheProvider_AndRemembersThem()
    {
        var alice = AddUser("alice", ProviderIds.Jelly2Fa);
        var admin = AddUser("admin", ProviderIds.Jelly2Fa);
        var other = AddUser("bob", ProviderIds.Default, enrolled: false);
        _challenges.Issue(new ChallengeBinding(alice.Id, "d", "c"), new byte[32], TimeSpan.FromMinutes(5), 3);

        Assert.Equal(2, await State().SuspendAsync());

        Assert.All(new[] { alice, admin, other }, u => Assert.Equal(ProviderIds.Default, u.AuthenticationProviderId));
        Assert.True(_store.IsSuspended);
        Assert.Equal(new[] { alice.Id, admin.Id }.OrderBy(x => x), _store.Load().OrderBy(x => x));
        Assert.Equal(0, _challenges.Count);
        Assert.Contains(_notifications.Alerts, a => a.Contains("disabled", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SuspendTwice_KeepsTheFirstList()
    {
        var alice = AddUser("alice", ProviderIds.Jelly2Fa);
        await State().SuspendAsync();
        await State().SuspendAsync(); // nobody is on the provider any more
        Assert.Equal(new[] { alice.Id }, _store.Load());
    }

    [Fact]
    public async Task Reactivate_SwitchesBack_RevokesSessions_KeepsCallerToken()
    {
        var alice = AddUser("alice", ProviderIds.Jelly2Fa);
        await State().SuspendAsync();

        Assert.Equal(1, await State().ReactivateAsync("admin-token"));

        Assert.Equal(ProviderIds.Jelly2Fa, alice.AuthenticationProviderId);
        Assert.Null(alice.LoginAttemptsBeforeLockout);
        await _sessions.Received().RevokeUserTokens(alice.Id, "admin-token");
        Assert.False(_store.IsSuspended);
    }

    [Fact]
    public async Task Reactivate_RespectsChangesMadeWhileDisabled()
    {
        var changed = AddUser("ldap", ProviderIds.Jelly2Fa);
        var unenrolled = AddUser("gone", ProviderIds.Jelly2Fa);
        var normal = AddUser("alice", ProviderIds.Jelly2Fa);
        await State().SuspendAsync();
        changed.AuthenticationProviderId = "Some.Ldap.Provider";
        _config.Users = _config.Users.Where(u => u.UserId != unenrolled.Id).ToArray();

        Assert.Equal(1, await State().ReactivateAsync(null));

        Assert.Equal("Some.Ldap.Provider", changed.AuthenticationProviderId);
        Assert.Equal(ProviderIds.Default, unenrolled.AuthenticationProviderId);
        Assert.Equal(ProviderIds.Jelly2Fa, normal.AuthenticationProviderId);
        Assert.Contains(_notifications.Alerts, a => a.Contains("ldap", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Reactivate_WithoutSuspension_DoesNothing()
    {
        var alice = AddUser("alice", ProviderIds.Default);
        Assert.Equal(0, await State().ReactivateAsync(null));
        Assert.Equal(ProviderIds.Default, alice.AuthenticationProviderId);
        await _sessions.DidNotReceiveWithAnyArgs().RevokeUserTokens(default, default!);
    }

    [Fact]
    public async Task StartupService_ReactivatesRememberedUsers()
    {
        var alice = AddUser("alice", ProviderIds.Jelly2Fa);
        await State().SuspendAsync();
        var service = new ReactivationStartupService(State(), _store, NullLogger<ReactivationStartupService>.Instance);
        await service.StartAsync(CancellationToken.None);
        Assert.Equal(ProviderIds.Jelly2Fa, alice.AuthenticationProviderId);
        await _sessions.Received().RevokeUserTokens(alice.Id, null!);
        await service.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Enroll_RefusedWhileDisabled()
    {
        var alice = AddUser("alice", ProviderIds.Default, enrolled: false);
        _store.Save(Array.Empty<Guid>());
        var enrollment = new EnrollmentService(_users, _sessions, new TestConfigProvider(_config), _challenges, _store, NullLogger<EnrollmentService>.Instance);
        await Assert.ThrowsAsync<InvalidOperationException>(() => enrollment.EnrollAsync(alice.Id, "alice@example.com", null));
        Assert.Equal(ProviderIds.Default, alice.AuthenticationProviderId);
    }

    [Fact]
    public async Task Unenroll_ResetsCounter_AndForgetsSuspension()
    {
        var alice = AddUser("alice", ProviderIds.Jelly2Fa);
        await State().SuspendAsync();
        alice.InvalidLoginAttemptCount = 7;
        var enrollment = new EnrollmentService(_users, _sessions, new TestConfigProvider(_config), _challenges, _store, NullLogger<EnrollmentService>.Instance);
        await enrollment.UnenrollAsync(alice.Id);
        Assert.Empty(_store.Load());
        Assert.Null(_config.FindUser(alice.Id));
    }

    [Fact]
    public void SuspensionStore_RoundTripAndClear()
    {
        Assert.False(_store.IsSuspended);
        Assert.Empty(_store.Load());
        var a = Guid.NewGuid();
        _store.Save(new[] { a, a });
        Assert.Equal(new[] { a }, _store.Load());
        _store.Remove(a);
        Assert.True(_store.IsSuspended);
        Assert.Empty(_store.Load());
        _store.Clear();
        Assert.False(_store.IsSuspended);
    }

    [Fact]
    public void SuspensionStore_CorruptFile_IsEmpty()
    {
        File.WriteAllText(Path.Combine(_folder, SuspensionStore.FileName), "{not json");
        Assert.Empty(_store.Load());
    }

    // ---- health ----

    private StatusReport Health(string[] knownProxies)
    {
        var server = Substitute.For<IServerConfigurationManager>();
        server.GetConfiguration("network").Returns(new NetworkConfiguration { KnownProxies = knownProxies });
        server.Configuration.Returns(new ServerConfiguration());
        var origin = Substitute.For<IOriginClassifier>();
        origin.ProxyConfigured.Returns(true);
        var email = Substitute.For<IEmailSender>();
        email.IsConfigured.Returns(true);
        _config.AdminAlertEmail = "admin@example.com";
        return new HealthService(_users, server, origin, email, new HealthState(new FakeTimeProvider()), new TestConfigProvider(_config), _store).GetStatus();
    }

    [Fact]
    public async Task Health_WhileDisabled_OneWarningNoProblems()
    {
        AddUser("alice", ProviderIds.Jelly2Fa);
        await State().SuspendAsync();
        var report = Health(new[] { "192.168.1.10" });
        Assert.True(report.Disabled);
        Assert.True(report.Healthy, string.Join("; ", report.Problems));
        Assert.Contains(report.Warnings, w => w.Contains("disabled", StringComparison.Ordinal));
    }

    [Fact]
    public void Health_CodeOnlyWithoutKnownProxies_IsAProblem()
    {
        AddUser("alice", ProviderIds.Jelly2Fa);
        Assert.True(Health(Array.Empty<string>()).Healthy);
        _config.AllowCodeOnlySecondStep = true;
        Assert.False(Health(Array.Empty<string>()).Healthy);
        Assert.True(Health(new[] { "192.168.1.10" }).Healthy);
    }

    [Fact]
    public void Health_CodeReuse_Warnings()
    {
        AddUser("alice", ProviderIds.Jelly2Fa);
        Assert.DoesNotContain(Health(new[] { "192.168.1.10" }).Warnings, w => w.Contains("reuse", StringComparison.OrdinalIgnoreCase));

        _config.CodeReuseCount = 2;
        var report = Health(new[] { "192.168.1.10" });
        Assert.True(report.Healthy);
        Assert.Contains(report.Warnings, w => w.Contains("from ANY address", StringComparison.Ordinal));

        _config.CodeReuseAddresses = "10.0.0.5, not-an-ip";
        report = Health(new[] { "192.168.1.10" });
        Assert.DoesNotContain(report.Warnings, w => w.Contains("from ANY address", StringComparison.Ordinal));
        Assert.Contains(report.Warnings, w => w.Contains("'not-an-ip' is not an IP address", StringComparison.Ordinal));

        _config.CodeReuseClients = " , ";
        Assert.Contains(Health(new[] { "192.168.1.10" }).Warnings, w => w.Contains("no apps are listed", StringComparison.Ordinal));
    }

    [Fact]
    public void Health_InvalidEmailTimeZone_Warning()
    {
        AddUser("alice", ProviderIds.Jelly2Fa);
        _config.EmailTimeZone = "Europe/Berlin";
        Assert.DoesNotContain(Health(new[] { "192.168.1.10" }).Warnings, w => w.Contains("time zone", StringComparison.Ordinal));
        _config.EmailTimeZone = "Mars/Olympus";
        Assert.Contains(Health(new[] { "192.168.1.10" }).Warnings, w => w.Contains("Unknown email time zone 'Mars/Olympus'", StringComparison.Ordinal));
    }
}

/// <summary>Small helpers added for the 0.0.2.0 fixes.</summary>
public class HelperTests
{
    [Theory]
    [InlineData("203.0.113.5", "203.0.113.5")]
    [InlineData("::ffff:203.0.113.5", "203.0.113.5")]
    [InlineData("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64")]
    [InlineData("2001:db8:1:2::1", "2001:db8:1:2::/64")]
    public void ThrottleKey(string ip, string expected) => Assert.Equal(expected, IpUtil.ThrottleKey(IPAddress.Parse(ip)));

    [Fact]
    public void Normalize_MapsIpv4AndHandlesNull()
    {
        Assert.Equal("10.0.0.1", IpUtil.Normalize(IPAddress.Parse("::ffff:10.0.0.1")));
        Assert.Equal(IpUtil.Unknown, IpUtil.Normalize(null));
    }

    [Fact]
    public void RateLimiter_RefundUndoesOneEvent()
    {
        var limiter = new RateLimiter(new FakeTimeProvider());
        var window = TimeSpan.FromMinutes(5);
        Assert.True(limiter.TryAcquire("k", 2, window, out var first));
        Assert.True(limiter.TryAcquire("k", 2, window, out _));
        Assert.False(limiter.TryAcquire("k", 2, window, out _));
        limiter.Refund("k", first);
        Assert.True(limiter.TryAcquire("k", 2, window, out _));
        limiter.Refund("missing", first); // no-op
    }

    [Fact]
    public void CodeEmail_ClientSuppliedTextIsShortened()
    {
        var longText = "Click https://evil.example/reset to keep your account " + new string('x', 150);
        var mail = NotificationService.BuildCodeEmail("en", false, "S", "a@example.com", "alice", "12345678", longText, longText, "203.0.113.5", 10, DateTimeOffset.UnixEpoch);
        Assert.DoesNotContain(longText, mail.Body, StringComparison.Ordinal);
        Assert.Contains(longText[..40], mail.Body, StringComparison.Ordinal);
        Assert.All(mail.Body.Split('\n').Where(l => l.StartsWith("Device:", StringComparison.Ordinal)), l => Assert.True(l.TrimEnd().Length <= 8 + NotificationService.MaxClientTextLength));
    }

    [Fact]
    public void Config_NullAndDuplicateUsers_AreNormalised()
    {
        var id = Guid.NewGuid();
        var config = new PluginConfiguration { Users = null! };
        Assert.Empty(config.Users);
        Assert.Null(config.FindUser(id));

        config.Users = new[]
        {
            new EnrolledUser { UserId = id, Email = "first@example.com" },
            null!,
            new EnrolledUser { UserId = id, Email = "second@example.com" },
            new EnrolledUser { UserId = Guid.Empty, Email = "x@example.com" },
        };
        Assert.Equal("first@example.com", Assert.Single(config.Users).Email);
    }

    [Fact]
    public void Config_XmlRoundTrip_KeepsUsers()
    {
        var id = Guid.NewGuid();
        var config = new PluginConfiguration { Users = new[] { new EnrolledUser { UserId = id, Email = "a@example.com" } } };
        var serializer = new System.Xml.Serialization.XmlSerializer(typeof(PluginConfiguration));
        using var writer = new StringWriter();
        serializer.Serialize(writer, config);
        using var reader = new StringReader(writer.ToString());
        var back = (PluginConfiguration)serializer.Deserialize(reader)!;
        Assert.Equal("a@example.com", back.FindUser(id)?.Email);
    }

    [Fact]
    public void SecretStore_DeleteFiles_RemovesPasswordAndTemp()
    {
        var folder = Path.Combine(Path.GetTempPath(), "j2fa-secret-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SecretStore(NullLogger<SecretStore>.Instance, () => folder);
            store.SetSmtpPassword("pw");
            File.WriteAllText(Path.Combine(folder, SecretStore.FileName + ".tmp"), "stale");
            Assert.True(SecretStore.DeleteFiles(folder));
            Assert.Empty(Directory.GetFiles(folder));
            Assert.True(SecretStore.DeleteFiles(null));
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    [Fact]
    public void SecretStore_StaleTempFileWithWideMode_IsReplaced()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var folder = Path.Combine(Path.GetTempPath(), "j2fa-secret-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var tmp = Path.Combine(folder, SecretStore.FileName + ".tmp");
            File.WriteAllText(tmp, "stale");
            File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            new SecretStore(NullLogger<SecretStore>.Instance, () => folder).SetSmtpPassword("pw");
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(folder, SecretStore.FileName)));
            Assert.False(File.Exists(tmp));
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }
}
