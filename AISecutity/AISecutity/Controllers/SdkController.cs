using AISecutity.Detection;
using AISecutity.Models;
using Microsoft.AspNetCore.Mvc;

namespace AISecutity.Controllers;

/// <summary>
/// SDK API — receives telemetry from customer websites via the JavaScript tracker.
/// This is the endpoint that the drop-in script sends data to.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class SdkController : ControllerBase
{
    private readonly IAiDetectionEngine _engine;
    private readonly MlDetectionClient _mlClient;
    private readonly ILogger<SdkController> _logger;

    // In-memory store of customer sessions (in production: Redis)
    private static readonly Dictionary<string, CustomerSession> _sessions = new();
    private static readonly object _lock = new();

    public SdkController(IAiDetectionEngine engine, MlDetectionClient mlClient, ILogger<SdkController> logger)
    {
        _engine = engine;
        _mlClient = mlClient;
        _logger = logger;
    }

    /// <summary>
    /// Receive telemetry batch from the JavaScript tracker.
    /// POST api/sdk/track
    /// </summary>
    [HttpPost("track")]
    public async Task<ActionResult> Track([FromBody] SdkPayload payload)
    {
        if (string.IsNullOrEmpty(payload.ApiKey))
            return Unauthorized(new { error = "Missing API key" });

        if (payload.Events == null || payload.Events.Count == 0)
            return Ok(new { received = 0 });

        // Store/update session
        CustomerSession session;
        lock (_lock)
        {
            if (!_sessions.TryGetValue(payload.SessionId, out session!))
            {
                session = new CustomerSession
                {
                    ApiKey = payload.ApiKey,
                    SessionId = payload.SessionId,
                    UserAgent = payload.UserAgent,
                    Url = payload.Url,
                    StartedAt = DateTime.UtcNow,
                };
                _sessions[payload.SessionId] = session;
            }
            session.Events.AddRange(payload.Events);
            session.LastSeenAt = DateTime.UtcNow;
        }

        // Analyze if we have enough events
        DetectionResult? result = null;
        if (session.Events.Count >= 5)
        {
            var activitySession = new ActivitySession
            {
                SessionId = session.SessionId,
                UserId = payload.ApiKey,
                UserAgent = session.UserAgent,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                Events = session.Events,
            };

            result = _engine.Analyze(activitySession);
            session.LastScore = result.AiProbabilityScore;
            session.IsBot = result.IsLikelyAiAgent;
            session.LastAction = result.RecommendedAction;
        }

        return Ok(new
        {
            received = payload.Events.Count,
            totalEvents = session.Events.Count,
            score = session.LastScore,
            isBot = session.IsBot,
            action = session.LastAction,
        });
    }

    /// <summary>
    /// Dashboard API: Get all sessions for an API key.
    /// GET api/sdk/dashboard?apiKey=xxx
    /// </summary>
    [HttpGet("dashboard")]
    public ActionResult GetDashboard([FromQuery] string apiKey)
    {
        if (string.IsNullOrEmpty(apiKey))
            return BadRequest("API key required");

        List<CustomerSession> sessions;
        lock (_lock)
        {
            sessions = _sessions.Values
                .Where(s => s.ApiKey == apiKey)
                .OrderByDescending(s => s.LastSeenAt)
                .Take(100)
                .ToList();
        }

        var bots = sessions.Count(s => s.IsBot);
        var humans = sessions.Count(s => !s.IsBot && s.Events.Count >= 5);
        var pending = sessions.Count(s => s.Events.Count < 5);

        return Ok(new
        {
            apiKey,
            summary = new
            {
                totalSessions = sessions.Count,
                botsDetected = bots,
                humansVerified = humans,
                pendingAnalysis = pending,
                detectionRate = sessions.Count > 0 ? (double)bots / sessions.Count * 100 : 0,
            },
            sessions = sessions.Select(s => new
            {
                s.SessionId,
                s.UserAgent,
                s.Url,
                s.StartedAt,
                s.LastSeenAt,
                eventCount = s.Events.Count,
                s.LastScore,
                s.IsBot,
                s.LastAction,
                duration = (s.LastSeenAt - s.StartedAt).TotalSeconds,
            }),
        });
    }

    /// <summary>
    /// Get the JavaScript tracker script with the API key embedded.
    /// GET api/sdk/script?apiKey=xxx
    /// </summary>
    [HttpGet("script")]
    public ActionResult GetScript([FromQuery] string apiKey, [FromQuery] string? endpoint = null)
    {
        var scriptEndpoint = endpoint ?? $"{Request.Scheme}://{Request.Host}/api/sdk/track";

        var html = $@"<!-- AISecutity Bot Detection -->
<script src=""{Request.Scheme}://{Request.Host}/sdk/tracker.js"" 
        data-api-key=""{apiKey}""
        data-endpoint=""{scriptEndpoint}"">
</script>";

        return Ok(new
        {
            snippet = html,
            instructions = new[]
            {
                "1. Copy the snippet below into your website's <head> tag",
                "2. Replace YOUR_API_KEY with your actual key",
                "3. Bot detection starts automatically",
                "4. View results at /api/sdk/dashboard?apiKey=YOUR_KEY",
            },
        });
    }

    /// <summary>
    /// Reset all sessions for an API key (clear dashboard).
    /// DELETE api/sdk/reset?apiKey=xxx
    /// </summary>
    [HttpDelete("reset")]
    public ActionResult Reset([FromQuery] string apiKey)
    {
        if (string.IsNullOrEmpty(apiKey))
            return BadRequest("API key required");

        int removed;
        lock (_lock)
        {
            var toRemove = _sessions.Where(kv => kv.Value.ApiKey == apiKey).Select(kv => kv.Key).ToList();
            removed = toRemove.Count;
            foreach (var key in toRemove)
                _sessions.Remove(key);
        }

        return Ok(new { message = $"Cleared {removed} sessions for {apiKey}" });
    }

    /// <summary>
    /// Get detailed info about a specific session (signals, events, etc.)
    /// GET api/sdk/session/{sessionId}?apiKey=xxx
    /// </summary>
    [HttpGet("session/{sessionId}")]
    public ActionResult GetSession(string sessionId, [FromQuery] string apiKey)
    {
        CustomerSession? session;
        lock (_lock)
        {
            _sessions.TryGetValue(sessionId, out session);
        }

        if (session == null || session.ApiKey != apiKey)
            return NotFound(new { error = "Session not found" });

        // Run detection to get full signal breakdown
        var activitySession = new ActivitySession
        {
            SessionId = session.SessionId,
            UserId = session.ApiKey,
            UserAgent = session.UserAgent,
            IpAddress = "unknown",
            Events = session.Events,
        };

        var result = session.Events.Count >= 2 ? _engine.Analyze(activitySession) : null;

        return Ok(new
        {
            session.SessionId,
            session.UserAgent,
            session.Url,
            session.StartedAt,
            session.LastSeenAt,
            session.IsBot,
            session.LastScore,
            session.LastAction,
            eventCount = session.Events.Count,
            duration = (session.LastSeenAt - session.StartedAt).TotalSeconds,
            signals = result?.Signals.Select(s => new { s.SignalName, s.Score, s.Description }),
            events = session.Events.Take(50).Select(e => new
            {
                e.Timestamp,
                e.EventType,
                e.Endpoint,
                e.DurationMs,
                mouseSpeed = e.Mouse?.Speed,
                mouseX = e.Mouse?.X,
                mouseY = e.Mouse?.Y,
                hasCurve = e.Mouse?.HasCurve,
                keyDelay = e.Keyboard?.InterKeyDelayMs,
                keyErrors = e.Keyboard?.ErrorRate,
            }),
        });
    }
}

public class SdkPayload
{
    public string ApiKey { get; set; } = "";
    public string SessionId { get; set; } = "";
    public string UserAgent { get; set; } = "";
    public string Url { get; set; } = "";
    public List<ActivityEvent> Events { get; set; } = new();
}

public class CustomerSession
{
    public string ApiKey { get; set; } = "";
    public string SessionId { get; set; } = "";
    public string UserAgent { get; set; } = "";
    public string Url { get; set; } = "";
    public DateTime StartedAt { get; set; }
    public DateTime LastSeenAt { get; set; }
    public List<ActivityEvent> Events { get; set; } = new();
    public double LastScore { get; set; }
    public bool IsBot { get; set; }
    public string LastAction { get; set; } = "pending";
}
