using System;
using System.Linq;
using Jellyfin.Plugin.Jelly2FA.Configuration;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Access to the current plugin configuration (abstracted for tests).
/// </summary>
public interface IConfigProvider
{
    /// <summary>Gets the current configuration. Throws if the plugin is not initialised (callers fail closed).</summary>
    PluginConfiguration Current { get; }

    /// <summary>Persists the configuration.</summary>
    /// <param name="configuration">The configuration.</param>
    void Save(PluginConfiguration configuration);
}

/// <summary>
/// Config provider backed by the plugin instance.
/// </summary>
public sealed class PluginConfigProvider : IConfigProvider
{
    /// <inheritdoc />
    public PluginConfiguration Current => Plugin.Instance?.Configuration
        ?? throw new InvalidOperationException("Jelly2FA plugin is not initialised.");

    /// <inheritdoc />
    public void Save(PluginConfiguration configuration)
    {
        var plugin = Plugin.Instance ?? throw new InvalidOperationException("Jelly2FA plugin is not initialised.");
        plugin.UpdateConfiguration(configuration);
    }
}

/// <summary>
/// Configuration helpers.
/// </summary>
public static class ConfigExtensions
{
    /// <summary>Finds an enrolled user.</summary>
    /// <param name="config">Configuration.</param>
    /// <param name="userId">User id.</param>
    /// <returns>The enrollment or null.</returns>
    public static EnrolledUser? FindUser(this PluginConfiguration config, Guid userId)
        => config.Users.FirstOrDefault(u => u.UserId == userId);
}
