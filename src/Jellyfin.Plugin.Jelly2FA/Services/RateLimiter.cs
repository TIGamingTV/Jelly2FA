using System;
using System.Collections.Generic;
using System.Linq;

namespace Jellyfin.Plugin.Jelly2FA.Services;

/// <summary>
/// Thread-safe in-memory sliding-window counters (failed logins, email budgets, alert throttling).
/// Memory is bounded: when too many keys exist, the stalest are dropped.
/// </summary>
public sealed class RateLimiter
{
    private const int MaxKeys = 20_000;

    private readonly object _lock = new();
    private readonly Dictionary<string, List<DateTimeOffset>> _events = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;

    /// <summary>
    /// Initializes a new instance of the <see cref="RateLimiter"/> class.
    /// </summary>
    /// <param name="time">Time provider.</param>
    public RateLimiter(TimeProvider time)
    {
        _time = time;
    }

    /// <summary>Whether the key reached <paramref name="max"/> events within the window.</summary>
    /// <param name="key">Key.</param>
    /// <param name="max">Maximum events.</param>
    /// <param name="window">Window.</param>
    /// <returns>True if limited.</returns>
    public bool IsLimited(string key, int max, TimeSpan window)
    {
        lock (_lock)
        {
            return CountInternal(key, window) >= Math.Max(1, max);
        }
    }

    /// <summary>Records an event.</summary>
    /// <param name="key">Key.</param>
    /// <param name="window">Window used to prune old events.</param>
    public void Record(string key, TimeSpan window)
    {
        lock (_lock)
        {
            RecordInternal(key, window);
        }
    }

    /// <summary>Atomically checks the limit and records an event if not limited.</summary>
    /// <param name="key">Key.</param>
    /// <param name="max">Maximum events.</param>
    /// <param name="window">Window.</param>
    /// <returns>True if the event was allowed (and recorded).</returns>
    public bool TryAcquire(string key, int max, TimeSpan window) => TryAcquire(key, max, window, out _);

    /// <summary>Atomically checks the limit and records an event if not limited.</summary>
    /// <param name="key">Key.</param>
    /// <param name="max">Maximum events.</param>
    /// <param name="window">Window.</param>
    /// <param name="recordedAt">Timestamp of the recorded event (pass it to <see cref="Refund"/> to undo).</param>
    /// <returns>True if the event was allowed (and recorded).</returns>
    public bool TryAcquire(string key, int max, TimeSpan window, out DateTimeOffset recordedAt)
    {
        lock (_lock)
        {
            if (CountInternal(key, window) >= Math.Max(1, max))
            {
                recordedAt = default;
                return false;
            }

            recordedAt = RecordInternal(key, window);
            return true;
        }
    }

    /// <summary>Removes one previously recorded event (undo of <see cref="TryAcquire(string, int, TimeSpan, out DateTimeOffset)"/>).</summary>
    /// <param name="key">Key.</param>
    /// <param name="recordedAt">The timestamp returned when the event was recorded.</param>
    public void Refund(string key, DateTimeOffset recordedAt)
    {
        lock (_lock)
        {
            if (!_events.TryGetValue(key, out var list))
            {
                return;
            }

            var index = list.LastIndexOf(recordedAt);
            if (index >= 0)
            {
                list.RemoveAt(index);
            }

            if (list.Count == 0)
            {
                _events.Remove(key);
            }
        }
    }

    /// <summary>Clears a key.</summary>
    /// <param name="key">Key.</param>
    public void Reset(string key)
    {
        lock (_lock)
        {
            _events.Remove(key);
        }
    }

    private DateTimeOffset RecordInternal(string key, TimeSpan window)
    {
        CountInternal(key, window);
        if (!_events.TryGetValue(key, out var list))
        {
            if (_events.Count >= MaxKeys)
            {
                Evict();
            }

            list = new List<DateTimeOffset>();
            _events[key] = list;
        }

        var now = _time.GetUtcNow();
        list.Add(now);
        return now;
    }

    private int CountInternal(string key, TimeSpan window)
    {
        if (!_events.TryGetValue(key, out var list))
        {
            return 0;
        }

        var cutoff = _time.GetUtcNow() - window;
        var expired = 0;
        while (expired < list.Count && list[expired] <= cutoff)
        {
            expired++;
        }

        if (expired > 0)
        {
            list.RemoveRange(0, expired);
        }

        if (list.Count == 0)
        {
            _events.Remove(key);
            return 0;
        }

        return list.Count;
    }

    private void Evict()
    {
        var victims = _events
            .OrderBy(e => e.Value.Count == 0 ? DateTimeOffset.MinValue : e.Value[^1])
            .Take(MaxKeys / 10)
            .Select(e => e.Key)
            .ToList();
        foreach (var key in victims)
        {
            _events.Remove(key);
        }
    }
}
