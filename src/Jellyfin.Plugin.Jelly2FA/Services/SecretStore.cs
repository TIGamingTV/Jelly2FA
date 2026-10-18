using System;
using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Stores the SMTP password outside the plugin XML (which admins can read through the API).
/// File: &lt;plugin data folder&gt;/secrets.json, mode 0600, written atomically.
/// The environment variable JELLY2FA_SMTP_PASSWORD takes precedence when set.
/// </summary>
public sealed class SecretStore
{
    /// <summary>Environment variable that overrides the stored password.</summary>
    public const string EnvironmentVariable = "JELLY2FA_SMTP_PASSWORD";

    /// <summary>Name of the secrets file in the plugin data folder.</summary>
    public const string FileName = "secrets.json";

    private readonly object _lock = new();
    private readonly ILogger<SecretStore> _logger;
    private readonly Func<string?> _folder;
    private string? _cached;
    private bool _loaded;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretStore"/> class.
    /// </summary>
    /// <param name="logger">Logger.</param>
    public SecretStore(ILogger<SecretStore> logger)
        : this(logger, () => Plugin.Instance?.DataFolderPath)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretStore"/> class with an explicit folder (tests).
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="folder">Folder accessor.</param>
    public SecretStore(ILogger<SecretStore> logger, Func<string?> folder)
    {
        _logger = logger;
        _folder = folder;
    }

    /// <summary>Gets the SMTP password (empty if none).</summary>
    /// <returns>The password.</returns>
    public string GetSmtpPassword()
    {
        var env = Environment.GetEnvironmentVariable(EnvironmentVariable);
        if (!string.IsNullOrEmpty(env))
        {
            return env;
        }

        lock (_lock)
        {
            if (!_loaded)
            {
                _cached = Load()?.SmtpPassword;
                _loaded = true;
            }

            return _cached ?? string.Empty;
        }
    }

    /// <summary>Gets a value indicating whether a password is available.</summary>
    public bool HasSmtpPassword => GetSmtpPassword().Length > 0;

    /// <summary>Stores (or clears, when empty) the SMTP password.</summary>
    /// <param name="password">Password.</param>
    public void SetSmtpPassword(string? password)
    {
        lock (_lock)
        {
            var path = GetPath() ?? throw new InvalidOperationException("Plugin data folder unavailable.");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var tmp = path + ".tmp";
            var json = JsonSerializer.Serialize(new Secrets { SmtpPassword = password ?? string.Empty });

            // A leftover temp file may have other permissions (the mode below only applies to NEW files):
            // remove it and require creating a fresh file, so the password is never written into it.
            File.Delete(tmp);
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            using (var stream = new FileStream(tmp, options))
            using (var writer = new StreamWriter(stream))
            {
                writer.Write(json);
                writer.Flush();
                stream.Flush(true);
            }

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            File.Move(tmp, path, true);
            _cached = password ?? string.Empty;
            _loaded = true;
        }
    }

    /// <summary>Deletes the stored secrets (plugin uninstall). The environment variable is not affected.</summary>
    /// <param name="folder">Plugin data folder.</param>
    /// <returns>True if nothing is left behind.</returns>
    public static bool DeleteFiles(string? folder)
    {
        if (string.IsNullOrEmpty(folder))
        {
            return true;
        }

        var path = Path.Combine(folder, FileName);
        File.Delete(path);
        File.Delete(path + ".tmp");
        return !File.Exists(path);
    }

    private Secrets? Load()
    {
        var path = GetPath();
        if (path is null || !File.Exists(path))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<Secrets>(File.ReadAllText(path));
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            _logger.LogError("Jelly2FA: could not read {Path}: {Message}", path, ex.Message);
            return null;
        }
    }

    private string? GetPath()
    {
        var folder = _folder();
        return folder is null ? null : Path.Combine(folder, FileName);
    }

    private sealed class Secrets
    {
        public string SmtpPassword { get; set; } = string.Empty;
    }
}
