using System.Collections.Concurrent;
using AISecutity.Detection;

namespace AISecutity.Middleware;

/// <summary>
/// Middleware that fingerprints every incoming request at the network level.
/// 
/// This is the defense against the "client-side trust" attack:
/// Even if a bot sends perfectly spoofed telemetry JSON, this middleware
/// checks the HTTP request itself for automation signatures.
/// 
/// It also tracks telemetry-to-request correlation:
/// If a session claims 15 mouse events but the server only received 3 HTTP
/// requests from that IP, the telemetry is fabricated.
/// </summary>
public class RequestFingerprintMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestFingerprintMiddleware> _logger;
    private readonly RequestFingerprintAnalyzer _analyzer;

    // Track request counts per IP for correlation
    private static readonly ConcurrentDictionary<string, RequestHistory> _requestHistory = new();

    public RequestFingerprintMiddleware(RequestDelegate next, ILogger<RequestFingerprintMiddleware> logger)
    {
        _next = next;
        _logger = logger;
        _analyzer = new RequestFingerprintAnalyzer();
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var path = context.Request.Path.Value ?? "";

        // Skip fingerprinting for SDK and dashboard endpoints (they're API calls from JS)
        if (path.StartsWith("/api/sdk") || path.StartsWith("/sdk/") || path.StartsWith("/api/fingerprint"))
        {
            await _next(context);
            return;
        }

        // Fingerprint the request
        var fingerprint = _analyzer.Analyze(context);

        // Track request history for this IP
        var history = _requestHistory.GetOrAdd(ip, _ => new RequestHistory());
        history.AddRequest(fingerprint);

        // Store fingerprint in HttpContext for downstream use
        context.Items["RequestFingerprint"] = fingerprint;
        context.Items["RequestHistory"] = history;

        // If fingerprint score is very high (obvious automation tool), block immediately
        if (fingerprint.Score >= 0.85)
        {
            _logger.LogWarning(
                "[FINGERPRINT] Blocked {IP} — score {Score:F2}. Signals: {Signals}",
                ip, fingerprint.Score,
                string.Join(", ", fingerprint.Signals.Where(s => s.Score > 0.5).Select(s => $"{s.Name}={s.Score:F1}")));

            context.Response.StatusCode = 403;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "Forbidden",
                message = "Request blocked by server-side fingerprinting.",
                reason = "Automated tool detected at network level.",
                fingerprintScore = fingerprint.Score,
                signals = fingerprint.Signals.Where(s => s.Score > 0.5).Select(s => new { s.Name, s.Score, s.Detail }),
            });
            return;
        }

        // Add fingerprint headers to response (for debugging/transparency)
        context.Response.Headers["X-Fingerprint-Score"] = fingerprint.Score.ToString("F2");
        context.Response.Headers["X-Fingerprint-Automated"] = fingerprint.IsLikelyAutomated.ToString();

        await _next(context);
    }
}

/// <summary>
/// Tracks request history per IP for telemetry correlation.
/// </summary>
public class RequestHistory
{
    private readonly ConcurrentQueue<RequestFingerprint> _requests = new();
    private readonly TimeSpan _window = TimeSpan.FromMinutes(5);

    public void AddRequest(RequestFingerprint fp)
    {
        _requests.Enqueue(fp);
        Cleanup();
    }

    /// <summary>
    /// Get the number of requests from this IP in the last N minutes.
    /// </summary>
    public int GetRequestCount()
    {
        Cleanup();
        return _requests.Count;
    }

    /// <summary>
    /// Get the average fingerprint score for this IP.
    /// Consistently high scores = definitely automated.
    /// </summary>
    public double GetAverageScore()
    {
        Cleanup();
        if (_requests.IsEmpty) return 0;
        return _requests.Average(r => r.Score);
    }

    /// <summary>
    /// Check if claimed telemetry event count is plausible given actual HTTP requests.
    /// If someone claims 50 mouse events but only made 2 HTTP requests, they're lying.
    /// </summary>
    public double GetTelemetryCorrelation(int claimedEventCount)
    {
        int actualRequests = GetRequestCount();
        if (actualRequests == 0) return 0.5;

        // Each HTTP request can reasonably carry 1-50 events (batched telemetry)
        // If claimed events >> actual requests × 50, it's suspicious
        double maxPlausibleEvents = actualRequests * 50;
        if (claimedEventCount > maxPlausibleEvents)
            return 0.9; // Fabricated telemetry

        // If claimed events are reasonable relative to request count
        return 0.1;
    }

    private void Cleanup()
    {
        var cutoff = DateTime.UtcNow - _window;
        while (_requests.TryPeek(out var oldest) && oldest.Timestamp < cutoff)
        {
            _requests.TryDequeue(out _);
        }
    }
}

public static class RequestFingerprintExtensions
{
    public static IApplicationBuilder UseRequestFingerprinting(this IApplicationBuilder app)
    {
        return app.UseMiddleware<RequestFingerprintMiddleware>();
    }
}
