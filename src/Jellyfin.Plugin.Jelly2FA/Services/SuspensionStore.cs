using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Remembers which users were handed back to password sign-in when the plugin was disabled, so they can be
/// switched back to Jelly2FA when it is enabled again.
/// The file lives in the plugin's own installation folder (next to the DLL), which Jellyfin removes on uninstall,
/// so a later fresh install never re-activates anybody by surprise.
/// </summary>
public sealed class SuspensionStore
{
    /// <summary>File name of the marker.</summary>
    public const string FileName = "jelly2fa-suspended.json";

    private readonly object _lock = new();
    private readonly ILogger<SuspensionStore> _logger;
    private readonly Func<string?> _folder;

    /// <summary>
    /// Initializes a new instance of the <see cref="SuspensionStore"/> class.
    /// </summary>
    /// <param name="logger">Logger.</param>
    public SuspensionStore(ILogger<SuspensionStore> logger)
        : this(logger, InstallFolder)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SuspensionStore"/> class with an explicit folder (tests).
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="folder">Folder accessor.</param>
    public SuspensionStore(ILogger<SuspensionStore> logger, Func<string?> folder)
    {
        _logger = logger;
        _folder = folder;
    }

    /// <summary>Gets a value indicating whether users are currently handed back because the plugin was disabled.</summary>
    public bool IsSuspended
    {
        get
        {
            lock (_lock)
            {
                var path = GetPath();
                return path is not null && File.Exists(path);
            }
        }
    }

    /// <summary>Loads the remembered user ids (empty if none).</summary>
    /// <returns>User ids.</returns>
    public IReadOnlyCollection<Guid> Load()
    {
        lock (_lock)
        {
            var path = GetPath();
            if (path is null || !File.Exists(path))
            {
                return Array.Empty<Guid>();
            }

            try
            {
                return JsonSerializer.Deserialize<Guid[]>(File.ReadAllText(path)) ?? Array.Empty<Guid>();
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
            {
                _logger.LogError("Jelly2FA: could not read {Path}: {Message}", path, ex.Message);
                return Array.Empty<Guid>();
            }
        }
    }

    /// <summary>Stores the user ids (atomically).</summary>
    /// <param name="userIds">User ids.</param>
    public void Save(IEnumerable<Guid> userIds)
    {
        lock (_lock)
        {
            var path = GetPath() ?? throw new InvalidOperationException("Plugin installation folder unavailable.");
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(userIds.Distinct().ToArray()));
            File.Move(tmp, path, true);
        }
    }

    /// <summary>Removes one user (e.g. unenrolled while suspended).</summary>
    /// <param name="userId">User id.</param>
    public void Remove(Guid userId)
    {
        lock (_lock)
        {
            var ids = Load();
            if (ids.Contains(userId))
            {
                Save(ids.Where(id => id != userId));
            }
        }
    }

    /// <summary>Deletes the marker.</summary>
    public void Clear()
    {
        lock (_lock)
        {
            var path = GetPath();
            if (path is not null)
            {
                File.Delete(path);
                File.Delete(path + ".tmp");
            }
        }
    }

    private static string? InstallFolder()
    {
        var dll = Plugin.Instance?.AssemblyFilePath;
        return string.IsNullOrEmpty(dll) ? null : Path.GetDirectoryName(dll);
    }

    private string? GetPath()
    {
        var folder = _folder();
        return string.IsNullOrEmpty(folder) ? null : Path.Combine(folder, FileName);
    }
}
