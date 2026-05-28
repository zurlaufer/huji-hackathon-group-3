using AISecutity.Data;
using AISecutity.Data.Entities;
using AISecutity.Detection;
using AISecutity.Models;
using Microsoft.AspNetCore.Mvc;

namespace AISecutity.Controllers;

[ApiController]
[Route("api/[controller]")]
public class BanController : ControllerBase
{
    private readonly BanService _banService;
    private readonly IAiDetectionEngine _engine;
    private readonly MlDetectionClient _mlClient;

    public BanController(BanService banService, IAiDetectionEngine engine, MlDetectionClient mlClient)
    {
        _banService = banService;
        _engine = engine;
        _mlClient = mlClient;
    }

    /// <summary>
    /// Analyze a session and ban the actor if detected as bot.
    /// Uses ML model as fallback for uncertain cases.
    /// POST api/ban/analyze-and-ban
    /// </summary>
    [HttpPost("analyze-and-ban")]
    public async Task<ActionResult> AnalyzeAndBan([FromBody] ActivitySession session, [FromQuery] string ipAddress = "unknown")
    {
        var result = _engine.Analyze(session);

        // If rule engine is uncertain (0.05-0.60), consult ML model
        if (result.AiProbabilityScore >= 0.05 && result.AiProbabilityScore < 0.60)
        {
            var mlResult = await _mlClient.PredictAsync(session);
            if (mlResult != null && mlResult.Confidence >= 0.80)
            {
                result.Signals.Add(new DetectionSignal
                {
                    SignalName = "ML_Model_v2",
                    Weight = 0.25,
                    Score = mlResult.BotProbability,
                    Description = $"ML: {mlResult.Prediction} (confidence: {mlResult.Confidence:F2})"
                });

                // Blend scores: 60% rule engine + 40% ML
                double newScore = result.AiProbabilityScore * 0.6 + mlResult.BotProbability * 0.4;

                if (mlResult.Prediction == "bot" && mlResult.Confidence >= 0.90)
                {
                    newScore = Math.Max(newScore, 0.65);
                    result.IsLikelyAiAgent = true;
                    result.RecommendedAction = "challenge";
                    result.ThreatLevel = "high";
                }

                result.AiProbabilityScore = Math.Round(Math.Min(1.0, newScore), 4);

                if (result.AiProbabilityScore >= 0.75)
                {
                    result.IsLikelyAiAgent = true;
                    result.RecommendedAction = "block";
                    result.ThreatLevel = "critical";
                }
                else if (result.AiProbabilityScore >= 0.60)
                {
                    result.IsLikelyAiAgent = true;
                    result.RecommendedAction = "challenge";
                    result.ThreatLevel = "high";
                }
            }
        }

        // Record the incident regardless
        await _banService.RecordIncident(result, ipAddress, session.UserAgent);

        if (result.IsLikelyAiAgent)
        {
            var ban = await _banService.BanActor(result, ipAddress, session.UserAgent);
            return Ok(new
            {
                detected = true,
                result.AiProbabilityScore,
                ban = new
                {
                    ban.Id,
                    ban.BanType,
                    ban.Penalty,
                    ban.ExpiresAt,
                    ban.Reason,
                    ban.TriggeredRule,
                },
                result.Signals,
            });
        }

        return Ok(new
        {
            detected = false,
            result.AiProbabilityScore,
            message = "Session appears human. No ban applied.",
            result.Signals,
        });
    }

    /// <summary>
    /// Check if an IP is currently banned.
    /// GET api/ban/check?ip=10.0.0.1
    /// </summary>
    [HttpGet("check")]
    public async Task<ActionResult> CheckBan([FromQuery] string ip, [FromQuery] string? sessionId = null)
    {
        var ban = await _banService.GetActiveBan(ip, sessionId);
        if (ban == null)
            return Ok(new { banned = false, ip });

        return Ok(new
        {
            banned = true,
            ip,
            ban.BanType,
            ban.Penalty,
            ban.TarpitDelayMs,
            ban.Reason,
            ban.ExpiresAt,
            ban.TotalIncidents,
        });
    }

    /// <summary>
    /// Get all currently active bans.
    /// GET api/ban/active
    /// </summary>
    [HttpGet("active")]
    public async Task<ActionResult<List<BannedActor>>> GetActiveBans()
    {
        var bans = await _banService.GetActiveBans();
        return Ok(bans);
    }

    /// <summary>
    /// Get incident history for an IP.
    /// GET api/ban/incidents?ip=10.0.0.1
    /// </summary>
    [HttpGet("incidents")]
    public async Task<ActionResult<List<SecurityIncident>>> GetIncidents([FromQuery] string ip)
    {
        var incidents = await _banService.GetIncidentsByIp(ip);
        return Ok(incidents);
    }

    /// <summary>
    /// Manually lift a ban.
    /// DELETE api/ban/{id}
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<ActionResult> LiftBan(int id)
    {
        var success = await _banService.LiftBan(id);
        if (!success) return NotFound();
        return Ok(new { message = "Ban lifted.", id });
    }
}
