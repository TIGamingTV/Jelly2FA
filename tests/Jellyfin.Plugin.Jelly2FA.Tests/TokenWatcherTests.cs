using Jellyfin.Data.Queries;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Entities.Security;
using Jellyfin.Plugin.Jelly2FA.Configuration;
using Jellyfin.Plugin.Jelly2FA.Services;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Devices;
using MediaBrowser.Controller.Events.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Dto;
using MediaBrowser.Model.Querying;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.Jelly2FA.Tests;

public class TokenWatcherTests
{
    private readonly IUserManager _users = Substitute.For<IUserManager>();
    private readonly IDeviceManager _devices = Substitute.For<IDeviceManager>();
    private readonly ISessionManager _sessions = Substitute.For<ISessionManager>();
    private readonly HttpContextAccessor _accessor = new();
    private readonly LoginApprovalRegistry _approvals = new(new FakeTimeProvider());
    private readonly FakeNotifications _notifications = new();
    private readonly PluginConfiguration _config = new();
    private readonly User _user = new("alice", ProviderIds.Jelly2Fa, "reset");
    private readonly Device _device;

    public TokenWatcherTests()
    {
        _users.GetUserById(_user.Id).Returns(_user);
        _config.Users = new[] { new EnrolledUser { UserId = _user.Id, Email = "alice@example.com" } };
        _device = new Device(_user.Id, "TV", "1", "Living room", "tv-1");
        _devices.GetDevices(Arg.Any<DeviceQuery>()).Returns(new QueryResult<Device>(new[] { _device }));
    }

    private TokenWatcher Watcher() => new(_users, _devices, _sessions, _accessor, _approvals, _notifications, new TestConfigProvider(_config), NullLogger<TokenWatcher>.Instance);

    private AuthenticationResultEventArgs Event() => new(new AuthenticationResult
    {
        User = new UserDto { Id = _user.Id, Name = "alice" },
        SessionInfo = new SessionInfoDto { DeviceId = "tv-1", DeviceName = "Living room", Client = "TV" },
        AccessToken = "t",
        ServerId = "s",
    });

    private void Path(string path)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "POST";
        ctx.Request.Path = path;
        _accessor.HttpContext = ctx;
    }

    [Fact]
    public async Task ApprovedLogin_Untouched()
    {
        _approvals.Approve(_user.Id, "tv-1");
        Path("/Users/AuthenticateByName");
        await Watcher().OnEvent(Event());
        await _sessions.DidNotReceive().Logout(Arg.Any<Device>());
    }

    [Fact]
    public async Task QuickConnect_AllowedAndNotified()
    {
        Path("/QuickConnect/Authorize");
        await Watcher().OnEvent(Event());
        await _sessions.DidNotReceive().Logout(Arg.Any<Device>());
        Assert.Single(_notifications.QuickConnect);
    }

    [Fact]
    public async Task QuickConnect_DisabledRevokes()
    {
        _config.AllowQuickConnect = false;
        Path("/QuickConnect/Authorize");
        await Watcher().OnEvent(Event());
        await _sessions.Received(1).Logout(_device);
    }

    [Fact]
    public async Task UnexpectedPath_RevokesAndAlerts()
    {
        Path("/SSO/OID/Auth/provider");
        await Watcher().OnEvent(Event());
        await _sessions.Received(1).Logout(_device);
        Assert.NotEmpty(_notifications.Alerts);
    }

    [Fact]
    public async Task UsersNotOnJelly2Fa_Ignored()
    {
        var other = new User("bob", ProviderIds.Default, "reset");
        _users.GetUserById(other.Id).Returns(other);
        Path("/SSO/OID/Auth/provider");
        await Watcher().OnEvent(new AuthenticationResultEventArgs(new AuthenticationResult
        {
            User = new UserDto { Id = other.Id },
            SessionInfo = new SessionInfoDto { DeviceId = "x" },
            AccessToken = "t",
            ServerId = "s",
        }));
        await _sessions.DidNotReceive().Logout(Arg.Any<Device>());
    }
}
