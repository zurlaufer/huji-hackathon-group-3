using AISecutity.Detection;
using AISecutity.Models;
using Microsoft.AspNetCore.Mvc;

namespace AISecutity.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DetectionController : ControllerBase
{
    private readonly IAiDetectionEngine _engine;
    private readonly MlDetectionClient _mlClient;

    public DetectionController(IAiDetectionEngine engine, MlDetectionClient mlClient)
    {
        _engine = engine;
        _mlClient = mlClient;
    }

    /// <summary>
    /// Analyze a single session using rule engine + ML model.
    /// The ML model is consulted when the rule engine is uncertain (score 0.30-0.60).
    /// POST api/detection/analyze
    /// </summary>
    [HttpPost("analyze")]
    public async Task<ActionResult<DetectionResult>> Analyze([FromBody] ActivitySession session)
    {
        if (session.Events == null || session.Events.Count == 0)
            return BadRequest("No events provided.");

        var result = _engine.Analyze(session);

        // If rule engine is uncertain, ask the ML model
        if (result.AiProbabilityScore >= 0.05 && result.AiProbabilityScore < 0.60)
        {
            var mlResult = await _mlClient.PredictAsync(session);
            if (mlResult != null)
            {
                // ML model overrides if it's confident
                if (mlResult.Confidence >= 0.80)
                {
                    bool mlSaysBot = mlResult.Prediction == "bot";

                    // Add ML signal to the result
                    result.Signals.Add(new DetectionSignal
                    {
                        SignalName = "ML_Model_v2",
                        Weight = 0.25,
                        Score = mlResult.BotProbability,
                        Description = $"ML prediction: {mlResult.Prediction} (confidence: {mlResult.Confidence:F2}, model: {mlResult.ModelVersion})"
                    });

                    // Recalculate combined score with ML input
                    double mlBoost = mlResult.BotProbability * 0.3;
                    double newScore = result.AiProbabilityScore * 0.6 + mlResult.BotProbability * 0.4;

                    if (mlSaysBot && mlResult.Confidence >= 0.90)
                    {
                        // High-confidence ML says bot — override to challenge/block
                        newScore = Math.Max(newScore, 0.65);
                        result.RecommendedAction = "challenge";
                        result.ThreatLevel = "high";
                        result.IsLikelyAiAgent = true;
                    }

                    result.AiProbabilityScore = Math.Round(Math.Min(1.0, newScore), 4);

                    // Update action based on new score
                    if (result.AiProbabilityScore >= 0.75)
                    {
                        result.RecommendedAction = "block";
                        result.ThreatLevel = "critical";
                        result.IsLikelyAiAgent = true;
                    }
                    else if (result.AiProbabilityScore >= 0.60)
                    {
                        result.RecommendedAction = "challenge";
                        result.ThreatLevel = "high";
                        result.IsLikelyAiAgent = true;
                    }
                }
            }
        }

        return Ok(result);
    }

    /// <summary>
    /// Analyze multiple sessions in batch.
    /// POST api/detection/analyze-batch
    /// </summary>
    [HttpPost("analyze-batch")]
    public ActionResult<List<DetectionResult>> AnalyzeBatch([FromBody] List<ActivitySession> sessions)
    {
        if (sessions == null || sessions.Count == 0)
            return BadRequest("No sessions provided.");

        var results = sessions.Select(s => _engine.Analyze(s)).ToList();
        return Ok(results);
    }

    /// <summary>
    /// Quick health check / summary endpoint.
    /// GET api/detection/status
    /// </summary>
    [HttpGet("status")]
    public ActionResult GetStatus()
    {
        return Ok(new
        {
            status = "running",
            ruleEngine = "v3.1 (12 signals)",
            mlModel = "v2.0 (GradientBoosting)",
            blockThreshold = 0.75,
            challengeThreshold = 0.60,
            monitorThreshold = 0.40,
        });
    }
}
