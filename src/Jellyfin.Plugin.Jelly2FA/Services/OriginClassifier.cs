using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Configuration;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Result of classifying where a login came from.
/// </summary>
/// <param name="TrustedDirect">True only for a direct (non-proxied) connection from a trusted LAN/Tailscale address.</param>
/// <param name="Reason">Human readable reason (for logs).</param>
public sealed record OriginDecision(bool TrustedDirect, string Reason);

/// <summary>
/// Decides whether a login is a trusted direct connection (password only) or must use 2FA.
/// </summary>
public interface IOriginClassifier
{
    /// <summary>Gets a value indicating whether at least one reverse proxy address is configured.</summary>
    bool ProxyConfigured { get; }

    /// <summary>Classifies an origin.</summary>
    /// <param name="origin">Captured origin, or null if capture did not run.</param>
    /// <returns>The decision.</returns>
    OriginDecision Classify(RequestOrigin? origin);
}

/// <summary>
/// Default origin classifier.
/// Rule: anything that came through a proxy (peer is a proxy address, or ANY forwarding header is present)
/// needs 2FA. Only a direct connection from Jellyfin's LAN networks or the configured trusted networks is
/// password-only. Every unknown/failed case needs 2FA (fail closed). Forwarded headers are never trusted
/// for this decision, so they cannot be spoofed to skip 2FA.
/// </summary>
public sealed class OriginClassifier : IOriginClassifier
{
    private readonly INetworkManager _networkManager;
    private readonly IServerConfigurationManager _serverConfig;
    private readonly IConfigProvider _config;

    /// <summary>
    /// Initializes a new instance of the <see cref="OriginClassifier"/> class.
    /// </summary>
    /// <param name="networkManager">Network manager.</param>
    /// <param name="serverConfig">Server configuration.</param>
    /// <param name="config">Plugin configuration.</param>
    public OriginClassifier(INetworkManager networkManager, IServerConfigurationManager serverConfig, IConfigProvider config)
    {
        _networkManager = networkManager;
        _serverConfig = serverConfig;
        _config = config;
    }

    /// <inheritdoc />
    public bool ProxyConfigured => GetProxyNetworks().Count > 0;

    /// <inheritdoc />
    public OriginDecision Classify(RequestOrigin? origin)
    {
        if (origin is null)
        {
            return new OriginDecision(false, "origin capture did not run");
        }

        if (origin.HadForwardingHeaders)
        {
            return new OriginDecision(false, "request carried forwarding headers (proxied)");
        }

        var peer = origin.PeerAddress;
        if (peer is null)
        {
            return new OriginDecision(false, "no peer address");
        }

        if (peer.IsIPv4MappedToIPv6)
        {
            peer = peer.MapToIPv4();
        }

        var proxies = GetProxyNetworks();
        if (proxies.Count == 0)
        {
            // Without a known proxy address we cannot tell nginx apart from a LAN client: require 2FA for everyone.
            return new OriginDecision(false, "no reverse proxy address configured (fail closed)");
        }

        if (proxies.Any(n => n.Contains(peer)))
        {
            return new OriginDecision(false, "peer is the reverse proxy");
        }

        var config = _config.Current;
        if (IPAddress.IsLoopback(peer))
        {
            return config.TrustLoopback
                ? new OriginDecision(true, "direct loopback connection (TrustLoopback)")
                : new OriginDecision(false, "loopback is not trusted");
        }

        if (config.TrustJellyfinLocalNetworks && _networkManager.IsInLocalNetwork(peer))
        {
            return new OriginDecision(true, "direct connection from a Jellyfin LAN network");
        }

        if (ParseNetworks(config.TrustedDirectNetworks).Any(n => n.Contains(peer)))
        {
            return new OriginDecision(true, "direct connection from a trusted network");
        }

        return new OriginDecision(false, "direct connection from an untrusted address");
    }

    /// <summary>Parses a comma/semicolon/whitespace separated list of IPs and CIDRs; invalid entries are ignored.</summary>
    /// <param name="value">The list.</param>
    /// <returns>Parsed networks.</returns>
    internal static List<IPNetwork> ParseNetworks(string? value)
    {
        var result = new List<IPNetwork>();
        if (string.IsNullOrWhiteSpace(value))
        {
            return result;
        }

        foreach (var raw in value.Split(new[] { ',', ';', ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (TryParseNetwork(raw, out var network))
            {
                result.Add(network);
            }
        }

        return result;
    }

    internal static bool TryParseNetwork(string raw, out IPNetwork network)
    {
        if (raw.Contains('/', StringComparison.Ordinal))
        {
            return IPNetwork.TryParse(raw, out network);
        }

        if (IPAddress.TryParse(raw, out var ip))
        {
            if (ip.IsIPv4MappedToIPv6)
            {
                ip = ip.MapToIPv4();
            }

            network = new IPNetwork(ip, ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
            return true;
        }

        network = default;
        return false;
    }

    private List<IPNetwork> GetProxyNetworks()
    {
        var list = ParseNetworks(_config.Current.ProxyAddresses);
        var known = _serverConfig.GetNetworkConfiguration().KnownProxies ?? Array.Empty<string>();
        list.AddRange(ParseNetworks(string.Join(',', known)));
        return list;
    }
}
