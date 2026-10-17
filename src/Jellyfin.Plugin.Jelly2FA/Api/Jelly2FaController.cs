using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net.Mime;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Plugin.Jelly2FA.Services;
using MediaBrowser.Common.Api;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA.Api;

/// <summary>
/// Jelly2FA administration API. Everything except /Health requires an administrator.
/// </summary>
[ApiController]
[Route("Jelly2FA")]
[Produces(MediaTypeNames.Application.Json)]
public class Jelly2FaController : ControllerBase
{
    private const string TokenClaim = "Jellyfin-Token";

    private readonly EnrollmentService _enrollment;
    private readonly HealthService _health;
    private readonly IUserManager _userManager;
    private readonly IConfigProvider _config;
    private readonly SecretStore _secrets;
    private readonly EmailQueue _email;
    private readonly ILogger<Jelly2FaController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="Jelly2FaController"/> class.
    /// </summary>
    /// <param name="enrollment">Enrollment.</param>
    /// <param name="health">Health.</param>
    /// <param name="userManager">User manager.</param>
    /// <param name="config">Config.</param>
    /// <param name="secrets">Secrets.</param>
    /// <param name="email">Email queue.</param>
    /// <param name="logger">Logger.</param>
    public Jelly2FaController(EnrollmentService enrollment, HealthService health, IUserManager userManager, IConfigProvider config, SecretStore secrets, EmailQueue email, ILogger<Jelly2FaController> logger)
    {
        _enrollment = enrollment;
        _health = health;
        _userManager = userManager;
        _config = config;
        _secrets = secrets;
        _email = email;
        _logger = logger;
    }

    /// <summary>
    /// Anonymous health check for an external watchdog. Returns 200 when healthy, 503 otherwise. No details.
    /// </summary>
    /// <returns>Status.</returns>
    [HttpGet("Health")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public ActionResult GetHealth()
    {
        bool healthy;
        try
        {
            healthy = _health.GetStatus().Healthy;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Jelly2FA health check failed");
            healthy = false;
        }

        var body = new { Status = healthy ? "ok" : "degraded" };
        return healthy ? Ok(body) : StatusCode(StatusCodes.Status503ServiceUnavailable, body);
    }

    /// <summary>Detailed status.</summary>
    /// <returns>The report.</returns>
    [HttpGet("Status")]
    [Authorize(Policy = Policies.RequiresElevation)]
    public ActionResult<StatusReport> GetStatus() => _health.GetStatus();

    /// <summary>Lists users and their enrollment.</summary>
    /// <returns>Users.</returns>
    [HttpGet("Users")]
    [Authorize(Policy = Policies.RequiresElevation)]
    public ActionResult<IEnumerable<UserStatusDto>> GetUsers()
    {
        var config = _config.Current;
        return Ok(_userManager.GetUsers()
            .OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase)
            .Select(u => new UserStatusDto
            {
                UserId = u.Id,
                Name = u.Username,
                Email = config.FindUser(u.Id)?.Email,
                Enrolled = config.FindUser(u.Id) is not null,
                UsesJelly2FaProvider = string.Equals(u.AuthenticationProviderId, ProviderIds.Jelly2Fa, StringComparison.Ordinal),
                HasPassword = !string.IsNullOrEmpty(u.Password),
                IsAdministrator = u.HasPermission(Jellyfin.Database.Implementations.Enums.PermissionKind.IsAdministrator),
            })
            .ToList());
    }

    /// <summary>Enrolls a user (revokes the user's existing tokens).</summary>
    /// <param name="userId">User id.</param>
    /// <param name="request">Email.</param>
    /// <returns>No content.</returns>
    [HttpPost("Users/{userId}/Enroll")]
    [Authorize(Policy = Policies.RequiresElevation)]
    public async Task<ActionResult> Enroll([FromRoute, Required] Guid userId, [FromBody, Required] EmailRequest request)
    {
        try
        {
            await _enrollment.EnrollAsync(userId, request.Email ?? string.Empty, User.FindFirst(TokenClaim)?.Value).ConfigureAwait(false);
            return NoContent();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return BadRequest(ex.Message);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(ex.Message);
        }
    }

    /// <summary>Changes an enrolled user's email.</summary>
    /// <param name="userId">User id.</param>
    /// <param name="request">Email.</param>
    /// <returns>No content.</returns>
    [HttpPost("Users/{userId}/Email")]
    [Authorize(Policy = Policies.RequiresElevation)]
    public ActionResult UpdateEmail([FromRoute, Required] Guid userId, [FromBody, Required] EmailRequest request)
    {
        try
        {
            _enrollment.UpdateEmail(userId, request.Email ?? string.Empty);
            return NoContent();
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(ex.Message);
        }
    }

    /// <summary>Unenrolls a user (back to password-only).</summary>
    /// <param name="userId">User id.</param>
    /// <returns>No content.</returns>
    [HttpPost("Users/{userId}/Unenroll")]
    [Authorize(Policy = Policies.RequiresElevation)]
    public async Task<ActionResult> Unenroll([FromRoute, Required] Guid userId)
    {
        try
        {
            await _enrollment.UnenrollAsync(userId).ConfigureAwait(false);
            return NoContent();
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(ex.Message);
        }
    }

    /// <summary>Stores the SMTP password (write only; never returned).</summary>
    /// <param name="request">Password.</param>
    /// <returns>No content.</returns>
    [HttpPost("Smtp/Password")]
    [Authorize(Policy = Policies.RequiresElevation)]
    public ActionResult SetSmtpPassword([FromBody, Required] SmtpPasswordRequest request)
    {
        _secrets.SetSmtpPassword(request.Password);
        return NoContent();
    }

    /// <summary>Sends a test email synchronously.</summary>
    /// <param name="request">Recipient.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>No content or the SMTP error.</returns>
    [HttpPost("TestEmail")]
    [Authorize(Policy = Policies.RequiresElevation)]
    public async Task<ActionResult> TestEmail([FromBody, Required] EmailRequest request, CancellationToken cancellationToken)
    {
        if (!EmailAddress.IsValid(request.Email))
        {
            return BadRequest("Invalid email address.");
        }

        try
        {
            await _email.SendNowAsync(
                new EmailMessage(request.Email!, "Jelly2FA test email", "This is a test email from the Jelly2FA plugin. Email delivery works."),
                cancellationToken).ConfigureAwait(false);
            return NoContent();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return StatusCode(StatusCodes.Status502BadGateway, "Sending failed: " + EmailAddress.SingleLine(ex.Message));
        }
    }
}

/// <summary>User row.</summary>
public sealed class UserStatusDto
{
    /// <summary>Gets or sets the id.</summary>
    public Guid UserId { get; set; }

    /// <summary>Gets or sets the name.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the email.</summary>
    public string? Email { get; set; }

    /// <summary>Gets or sets a value indicating whether the user is enrolled.</summary>
    public bool Enrolled { get; set; }

    /// <summary>Gets or sets a value indicating whether the user is on the Jelly2FA provider.</summary>
    public bool UsesJelly2FaProvider { get; set; }

    /// <summary>Gets or sets a value indicating whether the user has a password.</summary>
    public bool HasPassword { get; set; }

    /// <summary>Gets or sets a value indicating whether the user is an administrator.</summary>
    public bool IsAdministrator { get; set; }
}

/// <summary>Email request.</summary>
public sealed class EmailRequest
{
    /// <summary>Gets or sets the email address.</summary>
    public string? Email { get; set; }
}

/// <summary>SMTP password request.</summary>
public sealed class SmtpPasswordRequest
{
    /// <summary>Gets or sets the password (empty clears it).</summary>
    public string? Password { get; set; }
}
