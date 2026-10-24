using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Jelly2FA.Tests;

/// <summary>A logged entry: level, rendered message, template and the named values.</summary>
internal sealed record LogEntry(LogLevel Level, string Message, string? Template, IReadOnlyDictionary<string, object?> Values);

/// <summary>Logger that keeps every entry (thread-safe).</summary>
internal sealed class ListLogger<T> : ILogger<T>
{
    private readonly ConcurrentQueue<LogEntry> _entries = new();

    public IReadOnlyList<LogEntry> Entries => _entries.ToArray();

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        var values = new Dictionary<string, object?>(StringComparer.Ordinal);
        string? template = null;
        if (state is IEnumerable<KeyValuePair<string, object?>> pairs)
        {
            foreach (var (key, value) in pairs)
            {
                if (key == "{OriginalFormat}")
                {
                    template = value as string;
                }
                else
                {
                    values[key] = value;
                }
            }
        }

        _entries.Enqueue(new LogEntry(logLevel, formatter(state, exception), template, values));
    }
}
