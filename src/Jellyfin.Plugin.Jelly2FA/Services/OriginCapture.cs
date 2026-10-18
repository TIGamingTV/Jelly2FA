using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// What the TCP connection looked like BEFORE Jellyfin's forwarded-headers middleware rewrote it.
/// </summary>
/// <param name="PeerAddress">The real TCP peer (e.g. nginx, or a LAN/Tailscale client connecting directly).</param>
/// <param name="HadForwardingHeaders">Whether the request carried any proxy/forwarding header.</param>
public sealed record RequestOrigin(IPAddress? PeerAddress, bool HadForwardingHeaders);

/// <summary>
/// Captures the raw connection origin as the very first middleware of the pipeline.
/// </summary>
public sealed class OriginCaptureMiddleware
{
    /// <summary>Headers that indicate the request was relayed by a proxy.</summary>
    internal static readonly string[] ForwardingHeaders =
    {
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Forwarded-Protocol",
        "X-Forwarded-Port",
        "X-Real-IP",
        "Forwarded",
        "X-Original-For",
        "X-Client-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
    };

    private static readonly object _itemKey = new();
    private static int _seenRequests;

    private readonly RequestDelegate _next;

    /// <summary>
    /// Initializes a new instance of the <see cref="OriginCaptureMiddleware"/> class.
    /// </summary>
    /// <param name="next">Next middleware.</param>
    public OriginCaptureMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    /// <summary>Gets a value indicating whether the middleware has processed at least one request (self-check).</summary>
    public static bool IsActive => Volatile.Read(ref _seenRequests) != 0;

    /// <summary>Reads the captured origin, or null if the middleware did not run for this request.</summary>
    /// <param name="context">HTTP context.</param>
    /// <returns>The origin or null.</returns>
    public static RequestOrigin? Get(HttpContext context)
        => context.Items.TryGetValue(_itemKey, out var value) ? value as RequestOrigin : null;

    /// <summary>Stores an origin (used by the middleware and by tests).</summary>
    /// <param name="context">HTTP context.</param>
    /// <param name="origin">Origin.</param>
    internal static void Set(HttpContext context, RequestOrigin origin) => context.Items[_itemKey] = origin;

    /// <summary>Middleware entry point.</summary>
    /// <param name="context">HTTP context.</param>
    /// <returns>A task.</returns>
    public Task Invoke(HttpContext context)
    {
        var hadForwarding = false;
        foreach (var header in ForwardingHeaders)
        {
            if (context.Request.Headers.ContainsKey(header))
            {
                hadForwarding = true;
                break;
            }
        }

        var peer = context.Connection.RemoteIpAddress;
        if (peer is not null && peer.IsIPv4MappedToIPv6)
        {
            peer = peer.MapToIPv4();
        }

        Set(context, new RequestOrigin(peer, hadForwarding));
        if (_seenRequests == 0)
        {
            Interlocked.Exchange(ref _seenRequests, 1);
        }

        return _next(context);
    }
}

/// <summary>
/// Inserts <see cref="OriginCaptureMiddleware"/> in front of Jellyfin's pipeline (before UseForwardedHeaders),
/// followed by <see cref="PluginStateMiddleware"/> (reacts to Disable/Enable of this plugin).
/// </summary>
public sealed class OriginCaptureStartupFilter : IStartupFilter
{
    /// <inheritdoc />
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return app =>
        {
            app.UseMiddleware<OriginCaptureMiddleware>();
            app.UseMiddleware<PluginStateMiddleware>();
            next(app);
        };
    }
}
