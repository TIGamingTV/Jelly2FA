using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Jellyfin.Plugin.Jelly2FA.Configuration;
using Jellyfin.Plugin.Jelly2FA.Services;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA;

/// <summary>
/// The Jelly2FA plugin entry point.
/// </summary>
public class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    /// <summary>The plugin id.</summary>
    public const string PluginGuid = "aeb8e07d-2227-4d18-ad2f-7f49c81db71b";

    private readonly IUserManager _userManager;
    private readonly ILogger<Plugin> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="Plugin"/> class.
    /// </summary>
    /// <param name="applicationPaths">Application paths.</param>
    /// <param name="xmlSerializer">XML serializer.</param>
    /// <param name="userManager">User manager.</param>
    /// <param name="logger">Logger.</param>
    public Plugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer, IUserManager userManager, ILogger<Plugin> logger)
        : base(applicationPaths, xmlSerializer)
    {
        _userManager = userManager;
        _logger = logger;
        Instance = this;
    }

    /// <summary>Gets the running plugin instance.</summary>
    public static Plugin? Instance { get; private set; }

    /// <inheritdoc />
    public override string Name => "Jelly2FA";

    /// <inheritdoc />
    public override Guid Id => Guid.Parse(PluginGuid, CultureInfo.InvariantCulture);

    /// <inheritdoc />
    public override string Description => "Emailed one-time code for sign-ins through the reverse proxy; password only for direct LAN/Tailscale sign-ins.";

    /// <inheritdoc />
    public IEnumerable<PluginPageInfo> GetPages()
    {
        return new[]
        {
            new PluginPageInfo
            {
                Name = Name,
                EmbeddedResourcePath = string.Format(CultureInfo.InvariantCulture, "{0}.Configuration.configPage.html", GetType().Namespace)
            }
        };
    }

    /// <summary>
    /// On an explicit uninstall, hand enrolled users back to Jellyfin's default provider (with Jellyfin's default
    /// lockout and a reset failed-login counter) and remove the plugin's own data: the enrollment list, the SMTP
    /// password file and the disable marker.
    /// (Jellyfin only calls this while the plugin is loaded. A disabled plugin already handed its users back when
    /// it was disabled. If the plugin merely fails to load, nothing runs and enrolled users fail closed by design.)
    /// </summary>
    public override void OnUninstalling()
    {
        foreach (var user in _userManager.GetUsers())
        {
            try
            {
                if (ProviderSwitch.ToDefaultAsync(_userManager, user).GetAwaiter().GetResult())
                {
                    _logger.LogWarning("Jelly2FA uninstalled: user {UserId} switched back to the default (password-only) provider", user.Id);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Jelly2FA: failed to hand user {UserId} back to the default provider during uninstall", user.Id);
            }
        }

        try
        {
            Configuration.Users = Array.Empty<EnrolledUser>();
            SaveConfiguration();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Jelly2FA: failed to clear the enrollment list during uninstall");
        }

        try
        {
            if (!SecretStore.DeleteFiles(DataFolderPath))
            {
                _logger.LogError("Jelly2FA: could not delete {File} in {Folder}; delete it by hand", SecretStore.FileName, DataFolderPath);
            }
            else if (Directory.Exists(DataFolderPath) && !Directory.EnumerateFileSystemEntries(DataFolderPath).Any())
            {
                Directory.Delete(DataFolderPath);
            }

            var installFolder = string.IsNullOrEmpty(AssemblyFilePath) ? null : Path.GetDirectoryName(AssemblyFilePath);
            if (!string.IsNullOrEmpty(installFolder))
            {
                File.Delete(Path.Combine(installFolder, SuspensionStore.FileName));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogError(ex, "Jelly2FA: failed to delete plugin data during uninstall");
        }

        base.OnUninstalling();
    }
}
