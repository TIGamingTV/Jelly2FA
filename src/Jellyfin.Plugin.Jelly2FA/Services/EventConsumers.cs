using System;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Data.Events.Users;
using Jellyfin.Data.Queries;
using MediaBrowser.Controller.Devices;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Events.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Watches every newly issued user token. Tokens of enrolled users that were not approved by the
/// Jelly2FA provider came from a path that bypasses auth providers (Jellyfin's AuthenticateDirect):
/// Quick Connect is allowed by policy (and the user is notified); anything else is revoked immediately.
/// API keys are not user sessions and are never touched.
/// </summary>
public sealed class TokenWatcher : IEventConsumer<AuthenticationResultEventArgs>
{
    private readonly IUserManager _userManager;
    private readonly IDeviceManager _deviceManager;
    private readonly ISessionManager _sessionManager;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly LoginApprovalRegistry _approvals;
    private readonly INotificationService _notifications;
    private readonly IConfigProvider _config;
    private readonly ILogger<TokenWatcher> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenWatcher"/> class.
    /// </summary>
    /// <param name="userManager">User manager.</param>
    /// <param name="deviceManager">Device manager.</param>
    /// <param name="sessionManager">Session manager.</param>
    /// <param name="httpContextAccessor">HTTP context accessor.</param>
    /// <param name="approvals">Approval registry.</param>
    /// <param name="notifications">Notifications.</param>
    /// <param name="config">Config.</param>
    /// <param name="logger">Logger.</param>
    public TokenWatcher(
        IUserManager userManager,
        IDeviceManager deviceManager,
        ISessionManager sessionManager,
        IHttpContextAccessor httpContextAccessor,
        LoginApprovalRegistry approvals,
        INotificationService notifications,
        IConfigProvider config,
        ILogger<TokenWatcher> logger)
    {
        _userManager = userManager;
        _deviceManager = deviceManager;
        _sessionManager = sessionManager;
        _httpContextAccessor = httpContextAccessor;
        _approvals = approvals;
        _notifications = notifications;
        _config = config;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task OnEvent(AuthenticationResultEventArgs eventArgs)
    {
        var userId = eventArgs.User?.Id ?? Guid.Empty;
        if (userId == Guid.Empty)
        {
            return;
        }

        var user = _userManager.GetUserById(userId);
        if (user is null || !string.Equals(user.AuthenticationProviderId, ProviderIds.Jelly2Fa, StringComparison.Ordinal))
        {
            return;
        }

        var deviceId = eventArgs.SessionInfo?.DeviceId;
        if (_approvals.TryConsume(userId, deviceId))
        {
            return;
        }

        var http = _httpContextAccessor.HttpContext;
        var config = _config.Current;
        if (LoginEndpoints.IsQuickConnectAuthorize(http))
        {
            if (config.AllowQuickConnect)
            {
                _logger.LogInformation("Jelly2FA: Quick Connect sign-in for user {UserId} on device {Device}", userId, eventArgs.SessionInfo?.DeviceName);
                var email = config.FindUser(userId)?.Email;
                if (config.NotifyOnQuickConnect && EmailAddress.IsValid(email))
                {
                    _notifications.NotifyQuickConnect(
                        email!,
                        user.Username,
                        eventArgs.SessionInfo?.DeviceName,
                        eventArgs.SessionInfo?.Client,
                        IpUtil.Normalize(http?.Connection.RemoteIpAddress));
                }

                return;
            }

            _logger.LogWarning("Jelly2FA: Quick Connect is disabled for enrolled users; revoking the new token of user {UserId}", userId);
            await RevokeAsync(userId, deviceId).ConfigureAwait(false);
            return;
        }

        await RevokeAsync(userId, deviceId).ConfigureAwait(false);
        _notifications.AlertAdmin(
            "unexpected-token",
            "unexpected token revoked",
            $"A token for user '{user.Username}' was created without passing Jelly2FA (request: {EmailAddress.SingleLine(http?.Request.Path.Value ?? "none")}, device: {EmailAddress.SingleLine(eventArgs.SessionInfo?.DeviceName)}). It was revoked. Check for plugins that sign users in directly (e.g. SSO).");
    }

    private async Task RevokeAsync(Guid userId, string? deviceId)
    {
        if (string.IsNullOrEmpty(deviceId))
        {
            await _sessionManager.RevokeUserTokens(userId, null!).ConfigureAwait(false);
            return;
        }

        var devices = _deviceManager.GetDevices(new DeviceQuery { UserId = userId, DeviceId = deviceId }).Items;
        foreach (var device in devices.ToList())
        {
            await _sessionManager.Logout(device).ConfigureAwait(false);
        }
    }
}

/// <summary>Drops pending codes when a password changes.</summary>
public sealed class PasswordChangedConsumer : IEventConsumer<UserPasswordChangedEventArgs>
{
    private readonly ChallengeStore _challenges;

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordChangedConsumer"/> class.
    /// </summary>
    /// <param name="challenges">Code store.</param>
    public PasswordChangedConsumer(ChallengeStore challenges)
    {
        _challenges = challenges;
    }

    /// <inheritdoc />
    public Task OnEvent(UserPasswordChangedEventArgs eventArgs)
    {
        _challenges.RemoveUser(eventArgs.Argument.Id);
        return Task.CompletedTask;
    }
}

/// <summary>Removes the enrollment of a deleted user.</summary>
public sealed class UserDeletedConsumer : IEventConsumer<UserDeletedEventArgs>
{
    private readonly ChallengeStore _challenges;
    private readonly EnrollmentService _enrollment;

    /// <summary>
    /// Initializes a new instance of the <see cref="UserDeletedConsumer"/> class.
    /// </summary>
    /// <param name="challenges">Code store.</param>
    /// <param name="enrollment">Enrollment service.</param>
    public UserDeletedConsumer(ChallengeStore challenges, EnrollmentService enrollment)
    {
        _challenges = challenges;
        _enrollment = enrollment;
    }

    /// <inheritdoc />
    public Task OnEvent(UserDeletedEventArgs eventArgs)
    {
        _challenges.RemoveUser(eventArgs.Argument.Id);
        _enrollment.RemoveFromConfig(eventArgs.Argument.Id);
        return Task.CompletedTask;
    }
}
