using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Net;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// The enforcement point. Jellyfin calls this provider for every password check of an enrolled user,
/// BEFORE any access token is created. Throwing here means no token is issued.
/// <list type="bullet">
/// <item>Direct connection from LAN/Tailscale (not through the proxy): password only.</item>
/// <item>Anything else (through nginx/DDNS, unknown origin): password + emailed one-time code typed directly after the password
/// (or, if <c>AllowCodeOnlySecondStep</c> is on, the code alone in a second attempt from the same device/client/IP).</item>
/// </list>
/// Responses: wrong password/code -> 401 (AuthenticationException); code required / throttled / misconfigured -> 403
/// (MediaBrowser.Controller.Net.SecurityException, which Jellyfin does not count toward lockout).
/// </summary>
public sealed class TwoFactorAuthenticationProvider : IAuthenticationProvider, IRequiresResolvedUser
{
    private const string InvalidCredentials = "Invalid username or password.";
    private const string Throttled = "Too many failed sign-in attempts. Try again later.";
    private const string GlobalMailKey = "mail:global";

    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IServiceProvider _services;
    private readonly ICryptoProvider _crypto;
    private readonly IOriginClassifier _originClassifier;
    private readonly ChallengeStore _challenges;
    private readonly RateLimiter _limiter;
    private readonly LoginApprovalRegistry _approvals;
    private readonly INotificationService _notifications;
    private readonly IEmailSender _emailSender;
    private readonly IConfigProvider _config;
    private readonly ILogger<TwoFactorAuthenticationProvider> _logger;
    private readonly TimeProvider _time;

    /// <summary>
    /// Initializes a new instance of the <see cref="TwoFactorAuthenticationProvider"/> class.
    /// IAuthorizationContext is resolved lazily from <paramref name="services"/> because it depends on
    /// IUserManager, which itself depends on all authentication providers (constructor cycle).
    /// </summary>
    /// <param name="httpContextAccessor">HTTP context accessor.</param>
    /// <param name="services">Service provider.</param>
    /// <param name="crypto">Jellyfin password hashing.</param>
    /// <param name="originClassifier">Origin classifier.</param>
    /// <param name="challenges">Code store.</param>
    /// <param name="limiter">Rate limiter.</param>
    /// <param name="approvals">Approval registry.</param>
    /// <param name="notifications">Notifications.</param>
    /// <param name="emailSender">Email sender (configuration check only).</param>
    /// <param name="config">Config.</param>
    /// <param name="logger">Logger.</param>
    /// <param name="time">Time provider.</param>
    public TwoFactorAuthenticationProvider(
        IHttpContextAccessor httpContextAccessor,
        IServiceProvider services,
        ICryptoProvider crypto,
        IOriginClassifier originClassifier,
        ChallengeStore challenges,
        RateLimiter limiter,
        LoginApprovalRegistry approvals,
        INotificationService notifications,
        IEmailSender emailSender,
        IConfigProvider config,
        ILogger<TwoFactorAuthenticationProvider> logger,
        TimeProvider time)
    {
        _httpContextAccessor = httpContextAccessor;
        _services = services;
        _crypto = crypto;
        _originClassifier = originClassifier;
        _challenges = challenges;
        _limiter = limiter;
        _approvals = approvals;
        _notifications = notifications;
        _emailSender = emailSender;
        _config = config;
        _logger = logger;
        _time = time;
    }

    /// <inheritdoc />
    public string Name => "Jelly2FA (email code)";

    /// <inheritdoc />
    public bool IsEnabled => true;

    /// <summary>Hook for tests to supply authorization info without Jellyfin's AuthorizationContext.</summary>
    internal Func<HttpContext, Task<AuthorizationInfo>>? AuthorizationInfoOverride { get; set; }

    /// <inheritdoc />
    public Task<ProviderAuthenticationResult> Authenticate(string username, string password)
    {
        // Only the resolved-user overload is used by Jellyfin for local users.
        throw new AuthenticationException(InvalidCredentials);
    }

    /// <inheritdoc />
    public async Task<ProviderAuthenticationResult> Authenticate(string username, string password, User? resolvedUser)
    {
        if (resolvedUser is null)
        {
            throw new AuthenticationException(InvalidCredentials);
        }

        password ??= string.Empty;
        var http = _httpContextAccessor.HttpContext;
        var kind = LoginEndpoints.Classify(http);

        if (kind == LoginKind.Unknown || http is null)
        {
            _logger.LogWarning(
                "Jelly2FA: denied password check for user {UserId} from an unexpected caller ({Path})",
                resolvedUser.Id,
                EmailAddress.SingleLine(http?.Request.Path.Value ?? "(no HTTP request)"));
            throw new SecurityException("Jelly2FA: this sign-in method is not allowed.");
        }

        Configuration.PluginConfiguration config;
        try
        {
            config = _config.Current;
        }
        catch (InvalidOperationException)
        {
            throw new SecurityException("Jelly2FA is not ready.");
        }

        var userKey = "fail:user:" + resolvedUser.Id.ToString("N", CultureInfo.InvariantCulture);
        var userWindow = TimeSpan.FromMinutes(Math.Max(1, config.UserWindowMinutes));

        if (kind == LoginKind.PasswordCheck)
        {
            // Already-authenticated user confirming the current password (password change): password only,
            // but throttled per user (Jellyfin's own lockout is off for enrolled users).
            using var checkSlots = new FailureSlots(_limiter);
            if (!checkSlots.TryTake(userKey, config.MaxFailuresPerUser, userWindow))
            {
                _logger.LogWarning("Jelly2FA: throttled password check for user {UserId}", resolvedUser.Id);
                throw new SecurityException(Throttled);
            }

            if (!VerifyPassword(resolvedUser, password))
            {
                checkSlots.Commit();
                throw new AuthenticationException(InvalidCredentials);
            }

            return Success(username);
        }

        var clientIp = IpUtil.Normalize(http.Connection.RemoteIpAddress);
        var ipKey = "fail:ip:" + IpUtil.ThrottleKey(http.Connection.RemoteIpAddress);
        var ipWindow = TimeSpan.FromMinutes(Math.Max(1, config.IpWindowMinutes));
        var captured = OriginCaptureMiddleware.Get(http);
        var origin = _originClassifier.Classify(captured);

        // Every attempt takes a failure slot up front (atomically, so parallel requests cannot all pass the
        // check) and gives it back unless it really failed. Direct LAN/Tailscale sign-ins are only throttled
        // per IP: failures through the proxy must not be able to lock the user out of the LAN.
        using var slots = new FailureSlots(_limiter);
        if (!slots.TryTake(ipKey, config.MaxFailuresPerIp, ipWindow)
            || (!origin.TrustedDirect && !slots.TryTake(userKey, config.MaxFailuresPerUser, userWindow)))
        {
            _logger.LogWarning("Jelly2FA: throttled sign-in for user {UserId} from {Ip}", resolvedUser.Id, clientIp);
            throw new SecurityException(Throttled);
        }

        var auth = await GetAuthorizationInfo(http).ConfigureAwait(false);
        var deviceId = auth.DeviceId;
        var client = auth.Client;

        if (origin.TrustedDirect)
        {
            if (!VerifyPassword(resolvedUser, password))
            {
                slots.Commit();
                throw new AuthenticationException(InvalidCredentials);
            }

            _approvals.Approve(resolvedUser.Id, deviceId);
            _logger.LogInformation(
                "Jelly2FA: password-only sign-in for user {UserId} ({Reason}, peer {Peer})",
                resolvedUser.Id,
                origin.Reason,
                IpUtil.Normalize(captured?.PeerAddress));
            return Success(username);
        }

        // ---- 2FA path ----
        _logger.LogInformation(
            "Jelly2FA: two-factor required for user {UserId} ({Reason}, peer {Peer}, client ip {Ip})",
            resolvedUser.Id,
            origin.Reason,
            IpUtil.Normalize(captured?.PeerAddress),
            clientIp);

        if (string.IsNullOrEmpty(deviceId) || string.IsNullOrEmpty(client))
        {
            throw new SecurityException("Jelly2FA: missing device information.");
        }

        if (string.IsNullOrEmpty(resolvedUser.Password))
        {
            _logger.LogWarning("Jelly2FA: user {UserId} has no password; remote sign-in refused", resolvedUser.Id);
            throw new SecurityException("Jelly2FA: a password is required for remote sign-in.");
        }

        var enrollment = config.FindUser(resolvedUser.Id);
        if (enrollment is null || !EmailAddress.IsValid(enrollment.Email))
        {
            _notifications.AlertAdmin(
                "noemail:" + resolvedUser.Id.ToString("N", CultureInfo.InvariantCulture),
                "user cannot receive codes",
                $"User '{resolvedUser.Username}' uses the Jelly2FA provider but has no valid email address. Remote sign-in is refused until you enroll the user with an email address.");
            throw new SecurityException("Jelly2FA: no verified email address.");
        }

        var binding = new ChallengeBinding(resolvedUser.Id, deviceId, client);
        var fingerprint = ChallengeStore.Fingerprint(resolvedUser.Password);
        var fullOk = VerifyPassword(resolvedUser, password);

        // Optional: second step with the code only. The code was issued only after a correct password and is
        // bound to user/device/client AND the client IP that requested it; wrong entries count like wrong codes.
        if (!fullOk && config.AllowCodeOnlySecondStep && IsCodeOnly(password) && _challenges.HasPending(binding))
        {
            var result = _challenges.Verify(binding, password, fingerprint, config.MaxCodeAttempts, clientIp);
            if (result == VerifyResult.Success)
            {
                _approvals.Approve(resolvedUser.Id, deviceId);
                _logger.LogInformation(
                    "Jelly2FA: two-factor sign-in (code only) completed for user {UserId} from {Ip} ({Reason})",
                    resolvedUser.Id,
                    clientIp,
                    origin.Reason);
                return Success(username);
            }

            _logger.LogWarning("Jelly2FA: code-only entry rejected for user {UserId} from {Ip}: {Result}", resolvedUser.Id, clientIp, result);
            slots.Commit();
            throw new AuthenticationException(InvalidCredentials);
        }

        if (!fullOk && TrySplitCode(password, out var passwordPart, out var code) && _challenges.HasPending(binding))
        {
            if (VerifyPassword(resolvedUser, passwordPart))
            {
                var result = _challenges.Verify(binding, code, fingerprint, config.MaxCodeAttempts);
                if (result == VerifyResult.Success)
                {
                    _approvals.Approve(resolvedUser.Id, deviceId);
                    _logger.LogInformation(
                        "Jelly2FA: two-factor sign-in completed for user {UserId} from {Ip} ({Reason})",
                        resolvedUser.Id,
                        clientIp,
                        origin.Reason);
                    return Success(username);
                }

                _logger.LogWarning("Jelly2FA: code rejected for user {UserId} from {Ip}: {Result}", resolvedUser.Id, clientIp, result);
            }

            slots.Commit();
            throw new AuthenticationException(InvalidCredentials);
        }

        if (!fullOk)
        {
            slots.Commit();
            throw new AuthenticationException(InvalidCredentials);
        }

        // Correct password, no (valid) code: issue a code (respecting cooldown and budgets) and refuse with 403.
        IssueCodeIfAllowed(config, resolvedUser, enrollment.Email, binding, fingerprint, auth, clientIp);
        throw new SecurityException(config.AllowCodeOnlySecondStep
            ? "Two-factor verification required: enter the code sent by email as the password."
            : "Two-factor verification required: enter your password followed by the code sent by email.");
    }

    /// <inheritdoc />
    public Task ChangePassword(User user, string newPassword)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (string.IsNullOrEmpty(newPassword))
        {
            user.Password = null;
            return Task.CompletedTask;
        }

        user.Password = _crypto.CreatePasswordHash(newPassword).ToString();
        _challenges.RemoveUser(user.Id);
        return Task.CompletedTask;
    }

    /// <summary>Splits "password" + 8 digits.</summary>
    /// <param name="input">Entered password field.</param>
    /// <param name="passwordPart">Password part.</param>
    /// <param name="code">Code part.</param>
    /// <returns>True if the input ends with a code and has a non-empty password part.</returns>
    internal static bool TrySplitCode(string input, out string passwordPart, out string code)
    {
        passwordPart = string.Empty;
        code = string.Empty;
        if (input.Length <= ChallengeStore.CodeLength)
        {
            return false;
        }

        var tail = input.AsSpan(input.Length - ChallengeStore.CodeLength);
        foreach (var ch in tail)
        {
            if (ch is < '0' or > '9')
            {
                return false;
            }
        }

        passwordPart = input[..^ChallengeStore.CodeLength];
        code = tail.ToString();
        return true;
    }

    /// <summary>Whether the input is exactly a code (8 ASCII digits).</summary>
    /// <param name="input">Entered password field.</param>
    /// <returns>True if the input is only a code.</returns>
    internal static bool IsCodeOnly(string input)
    {
        if (input.Length != ChallengeStore.CodeLength)
        {
            return false;
        }

        foreach (var ch in input)
        {
            if (ch is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    private void IssueCodeIfAllowed(
        Configuration.PluginConfiguration config,
        User user,
        string email,
        ChallengeBinding binding,
        byte[] fingerprint,
        AuthorizationInfo auth,
        string clientIp)
    {
        var issuedAt = _challenges.GetIssuedAt(binding);
        if (issuedAt is { } t && _time.GetUtcNow() - t < TimeSpan.FromSeconds(Math.Max(0, config.ResendCooldownSeconds)))
        {
            _logger.LogInformation("Jelly2FA: code for user {UserId} still pending (cooldown), no new email", user.Id);
            return;
        }

        if (!_emailSender.IsConfigured)
        {
            _notifications.AlertAdmin("smtp-missing", "SMTP not configured", "A remote sign-in needed a code but SMTP is not configured. Remote sign-ins are impossible until SMTP is configured.");
            return;
        }

        var hour = TimeSpan.FromHours(1);
        var userMailKey = "mail:user:" + user.Id.ToString("N", CultureInfo.InvariantCulture);
        if (!_limiter.TryAcquire(userMailKey, config.MaxEmailsPerUserPerHour, hour, out var userMailAt))
        {
            _logger.LogWarning("Jelly2FA: per-user email budget exhausted for user {UserId}", user.Id);
            return;
        }

        if (!_limiter.TryAcquire(GlobalMailKey, config.MaxEmailsPerHourGlobal, hour, out var globalMailAt))
        {
            _limiter.Refund(userMailKey, userMailAt);
            _notifications.AlertAdmin("mail-global", "global email budget exhausted", "Jelly2FA stopped sending sign-in codes for up to an hour because the global email budget was exhausted. This can indicate an attack with valid passwords.");
            return;
        }

        var lifetime = Math.Clamp(config.CodeLifetimeMinutes, 1, 60);
        var code = _challenges.Issue(
            binding,
            fingerprint,
            TimeSpan.FromMinutes(lifetime),
            config.MaxPendingPerUser,
            clientIp == IpUtil.Unknown ? null : clientIp);
        if (!_notifications.SendCode(email, user.Username, code, auth.Device, auth.Client, clientIp, lifetime))
        {
            // Not queued: drop the code so the resend cooldown does not block the next attempt, and give the budget back.
            _challenges.Remove(binding);
            _limiter.Refund(userMailKey, userMailAt);
            _limiter.Refund(GlobalMailKey, globalMailAt);
            _logger.LogWarning("Jelly2FA: sign-in code email for user {UserId} could not be queued; no code is pending", user.Id);
            return;
        }

        _logger.LogInformation("Jelly2FA: sign-in code emailed to user {UserId} (client {Client}, ip {Ip})", user.Id, EmailAddress.SingleLine(auth.Client), clientIp);
    }

    private bool VerifyPassword(User user, string password)
    {
        if (string.IsNullOrEmpty(user.Password))
        {
            return string.IsNullOrEmpty(password);
        }

        try
        {
            return _crypto.Verify(PasswordHash.Parse(user.Password), password);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or NotSupportedException)
        {
            _logger.LogError("Jelly2FA: could not verify the stored password hash of user {UserId}: {Message}", user.Id, ex.Message);
            return false;
        }
    }

    private Task<AuthorizationInfo> GetAuthorizationInfo(HttpContext http)
    {
        if (AuthorizationInfoOverride is not null)
        {
            return AuthorizationInfoOverride(http);
        }

        return _services.GetRequiredService<IAuthorizationContext>().GetAuthorizationInfo(http);
    }

    private static ProviderAuthenticationResult Success(string username) => new() { Username = username };

    /// <summary>
    /// Failure-throttle slots taken for one attempt. Slots are given back on dispose unless
    /// <see cref="Commit"/> marked the attempt as a real failure.
    /// </summary>
    private sealed class FailureSlots : IDisposable
    {
        private readonly RateLimiter _limiter;
        private readonly List<(string Key, DateTimeOffset At)> _taken = new(2);
        private bool _committed;

        public FailureSlots(RateLimiter limiter)
        {
            _limiter = limiter;
        }

        public bool TryTake(string key, int max, TimeSpan window)
        {
            if (!_limiter.TryAcquire(key, max, window, out var at))
            {
                return false;
            }

            _taken.Add((key, at));
            return true;
        }

        public void Commit() => _committed = true;

        public void Dispose()
        {
            if (!_committed)
            {
                foreach (var (key, at) in _taken)
                {
                    _limiter.Refund(key, at);
                }
            }

            _taken.Clear();
        }
    }
}
