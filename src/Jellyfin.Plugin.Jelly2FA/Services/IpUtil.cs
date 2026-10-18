using System.Net;
using System.Net.Sockets;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>IP address helpers shared by the provider, the token watcher and the rate limiter.</summary>
public static class IpUtil
{
    /// <summary>Text used when no address is known.</summary>
    public const string Unknown = "unknown";

    /// <summary>Normalises an address for display/binding (IPv4-mapped IPv6 becomes IPv4).</summary>
    /// <param name="ip">Address.</param>
    /// <returns>The address text, or <see cref="Unknown"/>.</returns>
    public static string Normalize(IPAddress? ip)
    {
        if (ip is null)
        {
            return Unknown;
        }

        return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
    }

    /// <summary>
    /// Key for per-IP throttling. IPv6 clients usually control a whole /64, so they are throttled per /64;
    /// IPv4 clients per address.
    /// </summary>
    /// <param name="ip">Address.</param>
    /// <returns>The throttle key.</returns>
    public static string ThrottleKey(IPAddress? ip)
    {
        if (ip is null)
        {
            return Unknown;
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if (ip.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return ip.ToString();
        }

        var bytes = ip.GetAddressBytes();
        for (var i = 8; i < bytes.Length; i++)
        {
            bytes[i] = 0;
        }

        return new IPAddress(bytes).ToString() + "/64";
    }
}
