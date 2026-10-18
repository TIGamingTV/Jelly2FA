using System;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Library;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Moves a user between the Jelly2FA provider and Jellyfin's default provider through Jellyfin's own APIs
/// (never direct DB writes). Shared by enrollment, unenrollment, plugin disable/enable and uninstall so every
/// path leaves the account in the same, consistent state.
/// </summary>
public static class ProviderSwitch
{
    /// <summary>Jellyfin's policy value for "use the default lockout" (3 failures, 5 for administrators).</summary>
    public const int DefaultLockout = 0;

    /// <summary>Jellyfin's policy value for "no lockout".</summary>
    public const int NoLockout = -1;

    /// <summary>Whether the user is on the Jelly2FA provider.</summary>
    /// <param name="user">User.</param>
    /// <returns>True if on the Jelly2FA provider.</returns>
    public static bool IsOnJelly2Fa(User user)
        => string.Equals(user.AuthenticationProviderId, ProviderIds.Jelly2Fa, StringComparison.Ordinal);

    /// <summary>Whether the user is on Jellyfin's default provider.</summary>
    /// <param name="user">User.</param>
    /// <returns>True if on the default provider.</returns>
    public static bool IsOnDefault(User user)
        => string.Equals(user.AuthenticationProviderId, ProviderIds.Default, StringComparison.Ordinal);

    /// <summary>
    /// Switches the user to the Jelly2FA provider. Jellyfin's lockout is turned off (Jelly2FA throttles instead;
    /// a lockout would disable the account and kill existing sessions) and the failed-login counter is reset.
    /// </summary>
    /// <param name="userManager">User manager.</param>
    /// <param name="user">User.</param>
    /// <returns>A task.</returns>
    public static async Task ToJelly2FaAsync(IUserManager userManager, User user)
    {
        var policy = userManager.GetUserDto(user).Policy;
        policy.AuthenticationProviderId = ProviderIds.Jelly2Fa;
        policy.LoginAttemptsBeforeLockout = NoLockout;
        policy.InvalidLoginAttemptCount = 0;
        await userManager.UpdatePolicyAsync(user.Id, policy).ConfigureAwait(false);
        await ResetFailedLoginsAsync(userManager, user.Id).ConfigureAwait(false);
    }

    /// <summary>
    /// Hands the user back to Jellyfin's default (password-only) provider with Jellyfin's default lockout.
    /// The failed-login counter is reset first: Jellyfin keeps counting failures while the lockout is off, so an
    /// old count would otherwise disable the account on the next wrong password.
    /// </summary>
    /// <param name="userManager">User manager.</param>
    /// <param name="user">User.</param>
    /// <returns>True if the user was on the Jelly2FA provider and was switched.</returns>
    public static async Task<bool> ToDefaultAsync(IUserManager userManager, User user)
    {
        if (!IsOnJelly2Fa(user))
        {
            return false;
        }

        await ResetFailedLoginsAsync(userManager, user.Id).ConfigureAwait(false);
        var fresh = userManager.GetUserById(user.Id) ?? user;
        var policy = userManager.GetUserDto(fresh).Policy;
        policy.AuthenticationProviderId = ProviderIds.Default;
        policy.LoginAttemptsBeforeLockout = DefaultLockout;
        policy.InvalidLoginAttemptCount = 0;
        await userManager.UpdatePolicyAsync(user.Id, policy).ConfigureAwait(false);
        return true;
    }

    private static async Task ResetFailedLoginsAsync(IUserManager userManager, Guid userId)
    {
        var user = userManager.GetUserById(userId);
        if (user is not null && user.InvalidLoginAttemptCount != 0)
        {
            user.InvalidLoginAttemptCount = 0;
            await userManager.UpdateUserAsync(user).ConfigureAwait(false);
        }
    }
}
