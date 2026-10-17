using System;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Which kind of request is asking the auth provider to check a password.
/// </summary>
public enum LoginKind
{
    /// <summary>Unknown caller: always denied (fail closed).</summary>
    Unknown,

    /// <summary>A sign-in that will create an access token.</summary>
    Login,

    /// <summary>An authenticated user confirming the current password (password change). Password only.</summary>
    PasswordCheck,
}

/// <summary>
/// Classifies the HTTP request that triggered a password check.
/// Paths are relative to Jellyfin's base URL (Jellyfin maps the base URL into PathBase).
/// </summary>
public static partial class LoginEndpoints
{
    /// <summary>Classifies the request.</summary>
    /// <param name="context">HTTP context (may be null for non-HTTP callers).</param>
    /// <returns>The login kind.</returns>
    public static LoginKind Classify(HttpContext? context)
    {
        if (context is null || !HttpMethods.IsPost(context.Request.Method))
        {
            return LoginKind.Unknown;
        }

        var path = context.Request.Path.Value ?? string.Empty;
        if (LoginRegex().IsMatch(path))
        {
            return LoginKind.Login;
        }

        if (PasswordRegex().IsMatch(path) && context.User?.Identity?.IsAuthenticated == true)
        {
            return LoginKind.PasswordCheck;
        }

        return LoginKind.Unknown;
    }

    /// <summary>Whether the request is a Quick Connect approval.</summary>
    /// <param name="context">HTTP context.</param>
    /// <returns>True for POST /QuickConnect/Authorize.</returns>
    public static bool IsQuickConnectAuthorize(HttpContext? context)
        => context is not null
           && HttpMethods.IsPost(context.Request.Method)
           && QuickConnectRegex().IsMatch(context.Request.Path.Value ?? string.Empty);

    // POST /Users/AuthenticateByName and the obsolete POST /Users/{guid}/Authenticate (forwards to the same code).
    [GeneratedRegex(@"^/Users/(AuthenticateByName|[0-9a-fA-F-]{32,36}/Authenticate)/?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LoginRegex();

    // POST /Users/Password and the legacy POST /Users/{guid}/Password.
    [GeneratedRegex(@"^/Users/([0-9a-fA-F-]{32,36}/)?Password/?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PasswordRegex();

    [GeneratedRegex(@"^/QuickConnect/Authorize/?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex QuickConnectRegex();
}
