using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.Jelly2FA.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Enrolls / unenrolls users. Only Jellyfin APIs are used to change users (never direct DB writes).
/// </summary>
public sealed class EnrollmentService
{
    private static readonly object _configLock = new();

    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly IConfigProvider _config;
    private readonly ChallengeStore _challenges;
    private readonly ILogger<EnrollmentService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="EnrollmentService"/> class.
    /// </summary>
    /// <param name="userManager">User manager.</param>
    /// <param name="sessionManager">Session manager.</param>
    /// <param name="config">Config.</param>
    /// <param name="challenges">Code store.</param>
    /// <param name="logger">Logger.</param>
    public EnrollmentService(IUserManager userManager, ISessionManager sessionManager, IConfigProvider config, ChallengeStore challenges, ILogger<EnrollmentService> logger)
    {
        _userManager = userManager;
        _sessionManager = sessionManager;
        _config = config;
        _challenges = challenges;
        _logger = logger;
    }

    /// <summary>
    /// Enrolls a user: stores the email, switches the user to the Jelly2FA provider, disables Jellyfin's
    /// lockout for the user (Jelly2FA throttles instead, so existing sessions can never be killed by a
    /// lockout) and revokes all existing tokens of the user (except <paramref name="callerToken"/>).
    /// </summary>
    /// <param name="userId">User id.</param>
    /// <param name="email">Email address.</param>
    /// <param name="callerToken">Token of the admin performing the action (kept if it belongs to the user).</param>
    /// <returns>A task.</returns>
    public async Task EnrollAsync(Guid userId, string email, string? callerToken)
    {
        email = (email ?? string.Empty).Trim();
        if (!EmailAddress.IsValid(email))
        {
            throw new ArgumentException("Invalid email address.", nameof(email));
        }

        var user = _userManager.GetUserById(userId) ?? throw new KeyNotFoundException("User not found.");
        if (string.IsNullOrEmpty(user.Password))
        {
            throw new InvalidOperationException("The user has no password. Set a password before enrolling.");
        }

        SetEmail(userId, email);

        var policy = _userManager.GetUserDto(user).Policy;
        policy.AuthenticationProviderId = ProviderIds.Jelly2Fa;
        policy.LoginAttemptsBeforeLockout = -1;
        policy.InvalidLoginAttemptCount = 0;
        await _userManager.UpdatePolicyAsync(userId, policy).ConfigureAwait(false);

        await _sessionManager.RevokeUserTokens(userId, callerToken ?? null!).ConfigureAwait(false);
        _challenges.RemoveUser(userId);
        _logger.LogInformation("Jelly2FA: enrolled user {UserId}; existing tokens revoked", userId);
    }

    /// <summary>Changes the email of an enrolled user.</summary>
    /// <param name="userId">User id.</param>
    /// <param name="email">Email.</param>
    public void UpdateEmail(Guid userId, string email)
    {
        email = (email ?? string.Empty).Trim();
        if (!EmailAddress.IsValid(email))
        {
            throw new ArgumentException("Invalid email address.", nameof(email));
        }

        if (_config.Current.FindUser(userId) is null)
        {
            throw new KeyNotFoundException("User is not enrolled.");
        }

        SetEmail(userId, email);
        _challenges.RemoveUser(userId);
    }

    /// <summary>
    /// Unenrolls a user: back to Jellyfin's default password provider (password only everywhere) with
    /// Jellyfin's default lockout.
    /// </summary>
    /// <param name="userId">User id.</param>
    /// <returns>A task.</returns>
    public async Task UnenrollAsync(Guid userId)
    {
        var user = _userManager.GetUserById(userId) ?? throw new KeyNotFoundException("User not found.");
        var policy = _userManager.GetUserDto(user).Policy;
        if (string.Equals(policy.AuthenticationProviderId, ProviderIds.Jelly2Fa, StringComparison.Ordinal))
        {
            policy.AuthenticationProviderId = ProviderIds.Default;
            policy.LoginAttemptsBeforeLockout = 0;
            await _userManager.UpdatePolicyAsync(userId, policy).ConfigureAwait(false);
        }

        RemoveFromConfig(userId);
        _challenges.RemoveUser(userId);
        _logger.LogWarning("Jelly2FA: user {UserId} unenrolled (password-only sign-in)", userId);
    }

    /// <summary>Removes a user from the plugin configuration only.</summary>
    /// <param name="userId">User id.</param>
    public void RemoveFromConfig(Guid userId)
    {
        lock (_configLock)
        {
            var config = _config.Current;
            if (config.FindUser(userId) is null)
            {
                return;
            }

            config.Users = config.Users.Where(u => u.UserId != userId).ToArray();
            _config.Save(config);
        }
    }

    private void SetEmail(Guid userId, string email)
    {
        lock (_configLock)
        {
            var config = _config.Current;
            var users = config.Users.Where(u => u.UserId != userId).ToList();
            users.Add(new EnrolledUser { UserId = userId, Email = email });
            config.Users = users.ToArray();
            _config.Save(config);
        }
    }
}
