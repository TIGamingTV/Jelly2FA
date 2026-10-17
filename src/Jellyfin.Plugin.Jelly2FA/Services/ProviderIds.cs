namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Authentication provider ids as stored in <c>User.AuthenticationProviderId</c> (the provider's full type name).
/// NEVER rename <see cref="TwoFactorAuthenticationProvider"/>: its name is the id stored for every enrolled user.
/// </summary>
public static class ProviderIds
{
    /// <summary>Jelly2FA provider id.</summary>
    public const string Jelly2Fa = "Jellyfin.Plugin.Jelly2FA.Services.TwoFactorAuthenticationProvider";

    /// <summary>Jellyfin's built-in password provider id.</summary>
    public const string Default = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";
}
