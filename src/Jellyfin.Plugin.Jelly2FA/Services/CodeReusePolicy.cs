using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Jellyfin.Plugin.Jelly2FA.Configuration;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Effective code reuse settings. Some apps hand the credentials the user typed on to another service
/// (Neptune signs in to Seerr with them, Seerr then signs in to Jellyfin). Without reuse that second
/// sign-in fails because the code was already used. Off by default.
/// </summary>
public static class CodeReusePolicy
{
    /// <summary>Upper bound for <see cref="PluginConfiguration.CodeReuseCount"/>.</summary>
    public const int MaxCount = 10;

    private static readonly char[] Separators = { ',', ';', '\n', '\r', '\t' };

    /// <summary>Additional sign-ins allowed after the first use (0 = off).</summary>
    /// <param name="config">Configuration.</param>
    /// <returns>The clamped count.</returns>
    public static int Count(PluginConfiguration config) => Math.Clamp(config.CodeReuseCount, 0, MaxCount);

    /// <summary>Reuse window after the first use.</summary>
    /// <param name="config">Configuration.</param>
    /// <returns>Minutes (1-60).</returns>
    public static int Minutes(PluginConfiguration config) => Math.Clamp(config.CodeReuseMinutes, 1, 60);

    /// <summary>App names allowed to reuse a code.</summary>
    /// <param name="config">Configuration.</param>
    /// <returns>The trimmed, distinct names.</returns>
    public static IReadOnlyList<string> Clients(PluginConfiguration config)
        => (config.CodeReuseClients ?? string.Empty)
            .Split(Separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    /// <summary>Whether reuse is switched on (count above 0 and at least one app listed).</summary>
    /// <param name="config">Configuration.</param>
    /// <returns>True if on.</returns>
    public static bool Enabled(PluginConfiguration config) => Count(config) > 0 && Clients(config).Count > 0;

    /// <summary>Whether the app may reuse a code (exact name, case-insensitive).</summary>
    /// <param name="config">Configuration.</param>
    /// <param name="client">Client name from the Authorization header.</param>
    /// <returns>True if allowed.</returns>
    public static bool AllowsClient(PluginConfiguration config, string? client)
        => Enabled(config)
           && !string.IsNullOrWhiteSpace(client)
           && Clients(config).Contains(client.Trim(), StringComparer.OrdinalIgnoreCase);

    /// <summary>Whether the real TCP peer may reuse a code (any peer if no addresses are configured).</summary>
    /// <param name="config">Configuration.</param>
    /// <param name="peer">TCP peer before forwarded headers were applied.</param>
    /// <returns>True if allowed.</returns>
    public static bool AllowsPeer(PluginConfiguration config, IPAddress? peer)
    {
        if (string.IsNullOrWhiteSpace(config.CodeReuseAddresses))
        {
            return true;
        }

        if (peer is null)
        {
            return false;
        }

        if (peer.IsIPv4MappedToIPv6)
        {
            peer = peer.MapToIPv4();
        }

        return OriginClassifier.ParseNetworks(config.CodeReuseAddresses).Any(n => n.Contains(peer));
    }

    /// <summary>Entries of <see cref="PluginConfiguration.CodeReuseAddresses"/> that are not an IP or CIDR.</summary>
    /// <param name="config">Configuration.</param>
    /// <returns>The invalid entries.</returns>
    public static IReadOnlyList<string> InvalidAddresses(PluginConfiguration config)
        => (config.CodeReuseAddresses ?? string.Empty)
            .Split(new[] { ',', ';', ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries)
            .Where(e => !OriginClassifier.TryParseNetwork(e, out _))
            .ToArray();
}

/// <summary>Code reuse settings shown in the code email.</summary>
/// <param name="Count">Additional sign-ins allowed after the first use.</param>
/// <param name="Minutes">Reuse window in minutes.</param>
/// <param name="Clients">App names allowed to reuse.</param>
public sealed record ReuseInfo(int Count, int Minutes, IReadOnlyList<string> Clients)
{
    /// <summary>Reads the effective reuse settings.</summary>
    /// <param name="config">Configuration.</param>
    /// <returns>The settings, or null if reuse is off.</returns>
    public static ReuseInfo? From(PluginConfiguration config)
        => CodeReusePolicy.Enabled(config)
            ? new ReuseInfo(CodeReusePolicy.Count(config), CodeReusePolicy.Minutes(config), CodeReusePolicy.Clients(config))
            : null;
}
