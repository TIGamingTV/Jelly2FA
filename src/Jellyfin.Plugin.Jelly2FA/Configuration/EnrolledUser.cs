using System;

namespace Jellyfin.Plugin.Jelly2FA.Configuration;

/// <summary>
/// A user protected by Jelly2FA.
/// </summary>
public class EnrolledUser
{
    /// <summary>Gets or sets the Jellyfin user id.</summary>
    public Guid UserId { get; set; }

    /// <summary>Gets or sets the email address that receives sign-in codes. Only administrators can change it.</summary>
    public string Email { get; set; } = string.Empty;
}
