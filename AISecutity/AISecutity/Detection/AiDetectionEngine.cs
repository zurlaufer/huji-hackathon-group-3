using AISecutity.Models;

namespace AISecutity.Detection;

/// <summary>
/// Core AI agent detection algorithm (v2 — hardened against evasion bots).
/// Analyzes behavioral patterns to distinguish AI agents from human users.
/// 
/// Key signals:
/// 1. Timing regularity - AI agents have unnaturally consistent intervals
/// 2. Speed - AI can act faster than humanly possible
/// 3. Mouse linearity - bots move in straight lines, humans curve
/// 4. Mouse speed profile - bots have unnaturally high/consistent mouse speed
/// 5. Keyboard patterns - AI types at constant speed with no typos
/// 6. Navigation patterns - AI targets API endpoints directly
/// 7. API endpoint targeting - any /api/ access from a "browser" session is suspicious
/// 8. Session rhythm - AI doesn't take breaks or hesitate
/// 
/// v2 changes (based on challenge bot analysis):
/// - Added MouseSpeedProfile signal (avg speed + speed variance)
/// - Added ApiTargeting signal (detects /api/ endpoint access)
/// - Improved NavigationPattern to catch browsing-then-targeting behavior
/// - Lowered threshold from 0.65 to 0.55
/// - Rebalanced weights to emphasize new signals
/// </summary>
public class AiDetectionEngine : IAiDetectionEngine
{
    // Tiered thresholds — separate "monitor", "challenge", and "block" levels
    private const double MonitorThreshold = 0.25;   // Log it, watch closely
    private const double ChallengeThreshold = 0.40; // Show CAPTCHA
    private const double BlockThreshold = 0.55;     // Hard block

    // Threshold adjustments based on user history
    private const double FirstVisitBonus = 0.10;    // First-timers get +0.10 threshold (more lenient)
    private const double CleanHistoryBonus = 0.15;  // Users with clean history get +0.15
    private const double VerifiedUserBonus = 0.20;  // Verified users get +0.20

    public DetectionResult Analyze(ActivitySession session)
    {
        return Analyze(session, null);
    }

    public DetectionResult Analyze(ActivitySession session, SessionContext? context)
    {
        var signals = new List<DetectionSignal>();
        var events = session.Events.OrderBy(e => e.Timestamp).ToList();

        if (events.Count < 2)
        {
            return new DetectionResult
            {
                SessionId = session.SessionId,
                UserId = session.UserId,
                AiProbabilityScore = 0,
                IsLikelyAiAgent = false,
                RecommendedAction = "allow",
                ThreatLevel = "none",
                TotalEventsAnalyzed = events.Count,
                Signals = signals
            };
        }

        // Run each detection heuristic
        signals.Add(AnalyzeTimingRegularity(events));
        signals.Add(AnalyzeTimingJitter(events));
        signals.Add(AnalyzeTimingDistribution(events));    // NEW v3: catches Camoufox
        signals.Add(AnalyzeActionSpeed(events));
        signals.Add(AnalyzeMouseBehavior(events));
        signals.Add(AnalyzeMouseJerk(events));             // NEW v3: jerk analysis
        signals.Add(AnalyzeMouseSpeedProfile(events));
        signals.Add(AnalyzeKeyboardBehavior(events));
        signals.Add(AnalyzeNavigationPattern(events));
        signals.Add(AnalyzeNavigationBehavior(events));
        signals.Add(AnalyzeScrollBehavior(events));        // NEW v3.2: reading focal point
        signals.Add(AnalyzeHumanProof(events));            // NEW v4: catches Camoufox
        signals.Add(AnalyzeApiTargeting(events));
        signals.Add(AnalyzeSessionRhythm(events));

        // Weighted score calculation
        double totalWeight = signals.Sum(s => s.Weight);
        double weightedScore = signals.Sum(s => s.Score * s.Weight) / totalWeight;

        // Hybrid boost: multiple strong signals firing together
        int strongSignals = signals.Count(s => s.Score >= 0.55);  // 0.55 threshold catches Camoufox
        double maxSignal = signals.Max(s => s.Score);
        double secondMaxSignal = signals.OrderByDescending(s => s.Score).Skip(1).First().Score;

        double combinedScore = weightedScore;
        if (strongSignals >= 3)
            combinedScore = Math.Max(combinedScore + 0.20, 0.65);
        else if (strongSignals >= 2 && secondMaxSignal >= 0.55)   // Lowered from 0.6 to catch Camoufox
            combinedScore = Math.Max(combinedScore + 0.15, 0.55);

        if (maxSignal >= 0.9)
            combinedScore += 0.05;

        combinedScore = Math.Min(1.0, combinedScore);

        // === SESSION HISTORY ADJUSTMENT ===
        // Adjust effective thresholds based on user history
        double effectiveBlockThreshold = BlockThreshold;
        double effectiveChallengeThreshold = ChallengeThreshold;
        double effectiveMonitorThreshold = MonitorThreshold;
        bool isReturning = false;

        if (context != null)
        {
            isReturning = !context.IsFirstVisit;

            if (context.IsVerifiedUser)
            {
                // Verified users (logged in, passed CAPTCHA before) get maximum leeway
                effectiveBlockThreshold += VerifiedUserBonus;
                effectiveChallengeThreshold += VerifiedUserBonus;
                effectiveMonitorThreshold += VerifiedUserBonus;
            }
            else if (context.HasCleanHistory)
            {
                // Users with 3+ clean sessions get significant leeway
                effectiveBlockThreshold += CleanHistoryBonus;
                effectiveChallengeThreshold += CleanHistoryBonus;
                effectiveMonitorThreshold += CleanHistoryBonus;
            }
            else if (context.IsFirstVisit)
            {
                // First-time visitors get slight leeway (benefit of the doubt)
                effectiveBlockThreshold += FirstVisitBonus;
                effectiveChallengeThreshold += FirstVisitBonus;
            }

            // If user has previous bot flags, LOWER the threshold (stricter)
            if (context.PreviousBotFlags > 0)
            {
                double penalty = Math.Min(0.15, context.PreviousBotFlags * 0.05);
                effectiveBlockThreshold -= penalty;
                effectiveChallengeThreshold -= penalty;
            }
        }

        // === DETERMINE ACTION TIER ===
        string action;
        string threatLevel;
        bool isLikelyBot;

        if (combinedScore >= effectiveBlockThreshold)
        {
            action = "block";
            threatLevel = "critical";
            isLikelyBot = true;
        }
        else if (combinedScore >= effectiveChallengeThreshold)
        {
            action = "challenge";
            threatLevel = "high";
            isLikelyBot = true;
        }
        else if (combinedScore >= effectiveMonitorThreshold)
        {
            action = "monitor";
            threatLevel = "medium";
            isLikelyBot = false; // Don't flag as bot yet, just watch
        }
        else
        {
            action = "allow";
            threatLevel = combinedScore > 0.20 ? "low" : "none";
            isLikelyBot = false;
        }

        return new DetectionResult
        {
            SessionId = session.SessionId,
            UserId = session.UserId,
            AiProbabilityScore = Math.Round(combinedScore, 4),
            IsLikelyAiAgent = isLikelyBot,
            RecommendedAction = action,
            ThreatLevel = threatLevel,
            IsReturningUser = isReturning,
            TotalEventsAnalyzed = events.Count,
            Signals = signals
        };
    }

    /// <summary>
    /// AI agents tend to have very regular intervals between actions.
    /// Humans are erratic - sometimes fast, sometimes slow.
    /// Low standard deviation in timing = suspicious.
    /// </summary>
    private DetectionSignal AnalyzeTimingRegularity(List<ActivityEvent> events)
    {
        var intervals = new List<double>();
        for (int i = 1; i < events.Count; i++)
        {
            var gap = (events[i].Timestamp - events[i - 1].Timestamp).TotalMilliseconds;
            intervals.Add(gap);
        }

        if (intervals.Count == 0)
            return new DetectionSignal { SignalName = "TimingRegularity", Weight = 0.15, Score = 0 };

        double mean = intervals.Average();
        double stdDev = Math.Sqrt(intervals.Sum(x => Math.Pow(x - mean, 2)) / intervals.Count);

        // Coefficient of variation: stdDev / mean
        // Humans typically have CV > 0.7, sophisticated bots 0.3-0.5, obvious bots < 0.2
        double cv = mean > 0 ? stdDev / mean : 0;

        double score;
        if (cv < 0.1) score = 1.0;        // extremely regular = definitely bot
        else if (cv < 0.2) score = 0.9;
        else if (cv < 0.35) score = 0.75;
        else if (cv < 0.5) score = 0.6;   // suspicious zone — challenge bots land here
        else if (cv < 0.7) score = 0.4;   // borderline
        else if (cv < 1.0) score = 0.2;
        else score = 0.1;                  // very irregular = human

        return new DetectionSignal
        {
            SignalName = "TimingRegularity",
            Weight = 0.15,
            Score = score,
            Description = $"Coefficient of variation: {cv:F3}. Lower = more robotic."
        };
    }

    /// <summary>
    /// NEW v3: Timing Jitter Analysis — specifically catches DrissionPage and similar tools.
    /// 
    /// DrissionPage signature: page loads take ~6000ms ± 200ms (very tight cluster).
    /// The "jitter" between consecutive intervals is suspiciously low.
    /// 
    /// Real humans have HIGH jitter — the difference between one action and the next
    /// varies wildly (sometimes 1s, sometimes 8s, sometimes 20s).
    /// 
    /// Bots (especially browser automation) have LOW jitter because:
    /// - Page load times are consistent (network + render = fixed cost)
    /// - Sleep/wait commands produce uniform delays
    /// - No human hesitation, distraction, or reading time
    /// 
    /// We measure:
    /// 1. Inter-interval jitter (difference between consecutive intervals)
    /// 2. Clustering (do intervals cluster around a single value?)
    /// 3. Absence of outliers (humans always have some very long/short gaps)
    /// </summary>
    private DetectionSignal AnalyzeTimingJitter(List<ActivityEvent> events)
    {
        var intervals = new List<double>();
        for (int i = 1; i < events.Count; i++)
        {
            var gap = (events[i].Timestamp - events[i - 1].Timestamp).TotalMilliseconds;
            intervals.Add(gap);
        }

        if (intervals.Count < 4)
            return new DetectionSignal { SignalName = "TimingJitter", Weight = 0.15, Score = 0.5, Description = "Insufficient data for jitter analysis." };

        // 1. Inter-interval jitter: how much does each gap differ from the previous gap?
        // Low jitter = bot (each action takes roughly the same time as the last)
        var jitters = new List<double>();
        for (int i = 1; i < intervals.Count; i++)
        {
            jitters.Add(Math.Abs(intervals[i] - intervals[i - 1]));
        }

        double meanInterval = intervals.Average();
        double meanJitter = jitters.Average();

        // Normalize jitter relative to mean interval
        // Humans: jitter/mean > 0.5 (highly variable)
        // DrissionPage: jitter/mean < 0.1 (almost identical intervals)
        double jitterRatio = meanInterval > 0 ? meanJitter / meanInterval : 0;

        // 2. Clustering: what % of intervals fall within ±15% of the median?
        double median = intervals.OrderBy(x => x).ElementAt(intervals.Count / 2);
        double clusterBand = median * 0.15; // ±15%
        int clustered = intervals.Count(i => Math.Abs(i - median) < clusterBand);
        double clusterRatio = (double)clustered / intervals.Count;

        // 3. Outlier absence: humans always have at least some intervals that are
        // 3x longer or 3x shorter than the median
        int outliers = intervals.Count(i => i > median * 3 || i < median / 3);
        double outlierRatio = (double)outliers / intervals.Count;
        bool hasNoOutliers = outlierRatio < 0.05;

        // Score calculation
        double jitterScore;
        if (jitterRatio < 0.05) jitterScore = 1.0;       // Almost zero jitter = definitely bot
        else if (jitterRatio < 0.10) jitterScore = 0.9;   // DrissionPage lands here
        else if (jitterRatio < 0.20) jitterScore = 0.7;
        else if (jitterRatio < 0.35) jitterScore = 0.5;
        else if (jitterRatio < 0.50) jitterScore = 0.3;
        else jitterScore = 0.1;                            // High jitter = human

        double clusterScore;
        if (clusterRatio > 0.85) clusterScore = 0.95;     // >85% of intervals in tight cluster
        else if (clusterRatio > 0.70) clusterScore = 0.75;
        else if (clusterRatio > 0.50) clusterScore = 0.5;
        else clusterScore = 0.1;

        double outlierScore = hasNoOutliers ? 0.7 : 0.1;

        double score = jitterScore * 0.50 + clusterScore * 0.30 + outlierScore * 0.20;

        return new DetectionSignal
        {
            SignalName = "TimingJitter",
            Weight = 0.15,
            Score = Math.Round(score, 4),
            Description = $"Jitter ratio: {jitterRatio:F3} (lower=bot), Cluster: {clusterRatio:F2}, Outliers: {outlierRatio:F2}."
        };
    }

    /// <summary>
    /// NEW v3: Timing Distribution Shape — catches Camoufox and similar tools.
    /// 
    /// Human timing follows a LOG-NORMAL distribution (right-skewed):
    /// - Most actions are moderate speed (1-3 seconds)
    /// - Occasional long pauses (5-20 seconds) create a right tail
    /// - Skewness > 1.0 is typical for humans
    /// 
    /// Bot timing (Camoufox, Playwright) uses UNIFORM random:
    /// - random.uniform(min, max) produces flat distribution
    /// - Skewness ≈ 0 (symmetric)
    /// - No right tail (max is capped)
    /// 
    /// We detect this by measuring:
    /// 1. Skewness of interval distribution
    /// 2. Kurtosis (peakedness) — uniform is flat, log-normal is peaked
    /// 3. Ratio of median to mean — log-normal has mean > median
    /// </summary>
    private DetectionSignal AnalyzeTimingDistribution(List<ActivityEvent> events)
    {
        var intervals = new List<double>();
        for (int i = 1; i < events.Count; i++)
        {
            var gap = (events[i].Timestamp - events[i - 1].Timestamp).TotalMilliseconds;
            intervals.Add(gap);
        }

        if (intervals.Count < 6)
            return new DetectionSignal { SignalName = "TimingDistribution", Weight = 0.10, Score = 0.5, Description = "Insufficient data for distribution analysis." };

        double mean = intervals.Average();
        double median = intervals.OrderBy(x => x).ElementAt(intervals.Count / 2);
        double stdDev = Math.Sqrt(intervals.Sum(x => Math.Pow(x - mean, 2)) / intervals.Count);

        if (stdDev == 0)
            return new DetectionSignal { SignalName = "TimingDistribution", Weight = 0.10, Score = 0.9, Description = "Zero variance = bot." };

        // 1. Skewness: humans > 1.0 (right-skewed), bots ≈ 0 (symmetric/uniform)
        double skewness = intervals.Sum(x => Math.Pow((x - mean) / stdDev, 3)) / intervals.Count;

        // 2. Mean/Median ratio: log-normal has mean > median (ratio > 1.2)
        // Uniform has mean ≈ median (ratio ≈ 1.0)
        double meanMedianRatio = median > 0 ? mean / median : 1;

        // 3. Tail weight: what % of intervals are > 2x the median?
        // Humans have a heavy right tail (10-20%), uniform bots don't (< 5%)
        int tailCount = intervals.Count(i => i > median * 2);
        double tailRatio = (double)tailCount / intervals.Count;

        // Score
        double skewScore;
        if (skewness < 0.2) skewScore = 0.85;       // Symmetric = uniform = bot
        else if (skewness < 0.5) skewScore = 0.65;  // Slightly skewed = suspicious
        else if (skewness < 1.0) skewScore = 0.4;   // Moderately skewed = borderline
        else skewScore = 0.1;                         // Highly skewed = human (log-normal)

        double ratioScore;
        if (meanMedianRatio < 1.05) ratioScore = 0.8;   // Mean ≈ median = uniform
        else if (meanMedianRatio < 1.15) ratioScore = 0.5;
        else ratioScore = 0.1;                            // Mean >> median = log-normal

        double tailScore;
        if (tailRatio < 0.03) tailScore = 0.8;      // No tail = uniform/bot
        else if (tailRatio < 0.08) tailScore = 0.5;
        else tailScore = 0.1;                         // Heavy tail = human

        double score = skewScore * 0.40 + ratioScore * 0.30 + tailScore * 0.30;

        return new DetectionSignal
        {
            SignalName = "TimingDistribution",
            Weight = 0.10,
            Score = Math.Round(score, 4),
            Description = $"Skewness: {skewness:F2} (low=uniform/bot), Mean/Median: {meanMedianRatio:F2}, Tail: {tailRatio:F2}."
        };
    }

    /// <summary>
    /// AI agents can perform actions faster than any human.
    /// Sub-100ms response times for complex actions are suspicious.
    /// Also flags sessions where ALL actions are suspiciously fast (< 500ms).
    /// </summary>
    private DetectionSignal AnalyzeActionSpeed(List<ActivityEvent> events)
    {
        var intervals = new List<double>();
        for (int i = 1; i < events.Count; i++)
        {
            var gap = (events[i].Timestamp - events[i - 1].Timestamp).TotalMilliseconds;
            intervals.Add(gap);
        }

        if (intervals.Count == 0)
            return new DetectionSignal { SignalName = "ActionSpeed", Weight = 0.15, Score = 0 };

        // What percentage of actions happen faster than humanly possible?
        int superFastActions = intervals.Count(i => i < 50);   // < 50ms between actions
        int fastActions = intervals.Count(i => i < 200);       // < 200ms
        int quickActions = intervals.Count(i => i < 500);      // < 500ms — still suspicious in bulk

        double superFastRatio = (double)superFastActions / intervals.Count;
        double fastRatio = (double)fastActions / intervals.Count;
        double quickRatio = (double)quickActions / intervals.Count;

        // v2: Also check if average interval is suspiciously low
        double avgInterval = intervals.Average();
        double avgPenalty = avgInterval < 800 ? 0.3 : avgInterval < 1500 ? 0.1 : 0;

        double score = Math.Min(1.0, superFastRatio * 3.0 + fastRatio * 0.5 + quickRatio * 0.2 + avgPenalty);

        return new DetectionSignal
        {
            SignalName = "ActionSpeed",
            Weight = 0.15,
            Score = Math.Round(score, 4),
            Description = $"{superFastRatio * 100:F1}% under 50ms, {fastRatio * 100:F1}% under 200ms, {quickRatio * 100:F1}% under 500ms. Avg interval: {avgInterval:F0}ms."
        };
    }

    /// <summary>
    /// Human mouse movements have natural curves and acceleration.
    /// Bot movements are linear (straight lines) with constant speed.
    /// </summary>
    private DetectionSignal AnalyzeMouseBehavior(List<ActivityEvent> events)
    {
        var mouseEvents = events.Where(e => e.Mouse != null).ToList();

        if (mouseEvents.Count < 3)
            return new DetectionSignal { SignalName = "MouseBehavior", Weight = 0.10, Score = 0.5, Description = "Insufficient mouse data." };

        int linearMoves = 0;
        int totalMoves = 0;

        for (int i = 2; i < mouseEvents.Count; i++)
        {
            var p1 = mouseEvents[i - 2].Mouse!;
            var p2 = mouseEvents[i - 1].Mouse!;
            var p3 = mouseEvents[i].Mouse!;

            // Check if three consecutive points are collinear (straight line)
            double cross = Math.Abs(
                (p2.X - p1.X) * (p3.Y - p1.Y) - (p3.X - p1.X) * (p2.Y - p1.Y)
            );

            totalMoves++;
            if (cross < 10) // nearly collinear
                linearMoves++;
        }

        // Also check for lack of curves explicitly
        int noCurveCount = mouseEvents.Count(e => e.Mouse!.HasCurve == false);
        double noCurveRatio = (double)noCurveCount / mouseEvents.Count;

        double linearRatio = totalMoves > 0 ? (double)linearMoves / totalMoves : 0;
        double score = Math.Min(1.0, linearRatio * 0.6 + noCurveRatio * 0.4);

        return new DetectionSignal
        {
            SignalName = "MouseBehavior",
            Weight = 0.10,
            Score = Math.Round(score, 4),
            Description = $"Linear movement ratio: {linearRatio:F2}, No-curve ratio: {noCurveRatio:F2}."
        };
    }

    /// <summary>
    /// NEW v3: Mouse Jerk Analysis — the strongest anti-automation signal.
    /// 
    /// Jerk = rate of change of acceleration (3rd derivative of position).
    /// 
    /// Human hands produce SMOOTH jerk profiles because:
    /// - Muscles have inertia — can't change acceleration instantly
    /// - Natural movements follow "minimum jerk" trajectories
    /// - Jerk values are continuous and bounded
    /// 
    /// Bot mouse movements produce ABNORMAL jerk because:
    /// - Bezier curves have mathematical discontinuities at control points
    /// - Linear interpolation has zero jerk (then infinite at direction changes)
    /// - Automation tools sample at fixed intervals (uniform spacing = zero jerk)
    /// 
    /// We measure:
    /// 1. Jerk smoothness — ratio of smooth vs abrupt acceleration changes
    /// 2. Zero-jerk ratio — % of movements with exactly zero jerk (impossible for humans)
    /// 3. Jerk variance — humans have moderate variance, bots have either zero or extreme
    /// </summary>
    private DetectionSignal AnalyzeMouseJerk(List<ActivityEvent> events)
    {
        var mouseEvents = events.Where(e => e.Mouse != null).ToList();

        if (mouseEvents.Count < 4)
            return new DetectionSignal { SignalName = "MouseJerk", Weight = 0.12, Score = 0.5, Description = "Insufficient mouse data for jerk analysis." };

        // Calculate velocities between consecutive points
        var velocitiesX = new List<double>();
        var velocitiesY = new List<double>();

        for (int i = 1; i < mouseEvents.Count; i++)
        {
            double dx = mouseEvents[i].Mouse!.X - mouseEvents[i - 1].Mouse!.X;
            double dy = mouseEvents[i].Mouse!.Y - mouseEvents[i - 1].Mouse!.Y;
            var dt = (mouseEvents[i].Timestamp - mouseEvents[i - 1].Timestamp).TotalSeconds;
            if (dt <= 0) dt = 0.001;

            velocitiesX.Add(dx / dt);
            velocitiesY.Add(dy / dt);
        }

        if (velocitiesX.Count < 3)
            return new DetectionSignal { SignalName = "MouseJerk", Weight = 0.12, Score = 0.5, Description = "Insufficient velocity data." };

        // Calculate accelerations
        var accX = new List<double>();
        var accY = new List<double>();

        for (int i = 1; i < velocitiesX.Count; i++)
        {
            var dt = (mouseEvents[i + 1].Timestamp - mouseEvents[i].Timestamp).TotalSeconds;
            if (dt <= 0) dt = 0.001;
            accX.Add((velocitiesX[i] - velocitiesX[i - 1]) / dt);
            accY.Add((velocitiesY[i] - velocitiesY[i - 1]) / dt);
        }

        if (accX.Count < 2)
            return new DetectionSignal { SignalName = "MouseJerk", Weight = 0.12, Score = 0.5, Description = "Insufficient acceleration data." };

        // Calculate jerk (change in acceleration)
        var jerks = new List<double>();
        for (int i = 1; i < accX.Count; i++)
        {
            var dt = (mouseEvents[i + 2].Timestamp - mouseEvents[i + 1].Timestamp).TotalSeconds;
            if (dt <= 0) dt = 0.001;
            double jerkX = (accX[i] - accX[i - 1]) / dt;
            double jerkY = (accY[i] - accY[i - 1]) / dt;
            double jerkMagnitude = Math.Sqrt(jerkX * jerkX + jerkY * jerkY);
            jerks.Add(jerkMagnitude);
        }

        if (jerks.Count == 0)
            return new DetectionSignal { SignalName = "MouseJerk", Weight = 0.12, Score = 0.5, Description = "Could not compute jerk." };

        // 1. Zero-jerk ratio: what % of jerk values are near zero?
        // Bots with constant speed have zero jerk. Humans never have exactly zero.
        double jerkThreshold = 100; // Below this = effectively zero
        int zeroJerks = jerks.Count(j => j < jerkThreshold);
        double zeroJerkRatio = (double)zeroJerks / jerks.Count;

        // 2. Jerk variance: humans have moderate, consistent jerk.
        // Bots have either all-zero or extreme spikes (no middle ground).
        double meanJerk = jerks.Average();
        double stdJerk = Math.Sqrt(jerks.Sum(j => Math.Pow(j - meanJerk, 2)) / jerks.Count);
        double jerkCV = meanJerk > 0 ? stdJerk / meanJerk : 0;

        // 3. Smoothness: ratio of "smooth" transitions (jerk < 2x mean) vs spikes
        int smoothTransitions = jerks.Count(j => j < meanJerk * 2);
        double smoothRatio = (double)smoothTransitions / jerks.Count;

        // Score: high zero-jerk = bot, very low jerk CV = bot, very high smoothness = bot
        double zeroScore;
        if (zeroJerkRatio > 0.7) zeroScore = 0.9;      // Mostly zero jerk = automation
        else if (zeroJerkRatio > 0.5) zeroScore = 0.7;
        else if (zeroJerkRatio > 0.3) zeroScore = 0.4;
        else zeroScore = 0.1;                            // Low zero-jerk = human

        // Jerk CV: humans ~0.8-1.5, bots either <0.3 (constant) or >3.0 (spiky)
        double cvScore;
        if (jerkCV < 0.3) cvScore = 0.85;               // Too consistent = bot
        else if (jerkCV > 3.0) cvScore = 0.7;           // Too spiky = bot (Bezier control points)
        else if (jerkCV < 0.6) cvScore = 0.5;
        else cvScore = 0.1;                              // Normal variance = human

        double score = zeroScore * 0.45 + cvScore * 0.35 + (smoothRatio > 0.9 ? 0.6 : 0.1) * 0.20;

        return new DetectionSignal
        {
            SignalName = "MouseJerk",
            Weight = 0.12,
            Score = Math.Round(score, 4),
            Description = $"Zero-jerk ratio: {zeroJerkRatio:F2}, Jerk CV: {jerkCV:F2}, Smooth ratio: {smoothRatio:F2}."
        };
    }

    /// <summary>
    /// NEW v2: Analyzes mouse speed characteristics.
    /// Challenge bots have:
    /// - High average speed (>900 px/s vs human avg 697 px/s)
    /// - Low speed variance (CV < 0.25 vs human CV 0.37)
    /// - Speed clustered near the max of human range (1000-1200 px/s)
    /// </summary>
    private DetectionSignal AnalyzeMouseSpeedProfile(List<ActivityEvent> events)
    {
        var mouseEvents = events.Where(e => e.Mouse?.Speed != null).ToList();

        if (mouseEvents.Count < 3)
            return new DetectionSignal { SignalName = "MouseSpeedProfile", Weight = 0.20, Score = 0.5, Description = "Insufficient mouse speed data." };

        var speeds = mouseEvents.Select(e => e.Mouse!.Speed!.Value).ToList();

        double avgSpeed = speeds.Average();
        double stdDev = Math.Sqrt(speeds.Sum(x => Math.Pow(x - avgSpeed, 2)) / speeds.Count);
        double speedCv = avgSpeed > 0 ? stdDev / avgSpeed : 0;

        // Signal 1: Average speed too high (humans avg ~700, bots avg ~1050)
        double speedScore;
        if (avgSpeed > 1100) speedScore = 0.9;
        else if (avgSpeed > 950) speedScore = 0.75;
        else if (avgSpeed > 850) speedScore = 0.6;
        else if (avgSpeed > 750) speedScore = 0.3;
        else speedScore = 0.1;

        // Signal 2: Speed too consistent (low CV = robotic)
        // Humans have CV ~0.37, bots ~0.24
        double consistencyScore;
        if (speedCv < 0.10) consistencyScore = 0.95;
        else if (speedCv < 0.20) consistencyScore = 0.8;
        else if (speedCv < 0.28) consistencyScore = 0.65;  // Challenge bots land here
        else if (speedCv < 0.35) consistencyScore = 0.4;
        else consistencyScore = 0.1;

        // Signal 3: Too many movements at max human speed (>1000 px/s)
        int highSpeedCount = speeds.Count(s => s > 1000);
        double highSpeedRatio = (double)highSpeedCount / speeds.Count;
        double highSpeedScore = highSpeedRatio > 0.7 ? 0.9 : highSpeedRatio > 0.5 ? 0.7 : highSpeedRatio > 0.3 ? 0.4 : 0.1;

        double score = speedScore * 0.4 + consistencyScore * 0.35 + highSpeedScore * 0.25;

        return new DetectionSignal
        {
            SignalName = "MouseSpeedProfile",
            Weight = 0.20,
            Score = Math.Round(score, 4),
            Description = $"Avg speed: {avgSpeed:F0}px/s, Speed CV: {speedCv:F3}, High-speed ratio: {highSpeedRatio:F2}."
        };
    }

    /// <summary>
    /// AI typing is perfectly consistent with zero errors.
    /// Humans have variable inter-key delays and make typos.
    /// </summary>
    private DetectionSignal AnalyzeKeyboardBehavior(List<ActivityEvent> events)
    {
        var keyEvents = events.Where(e => e.Keyboard != null).ToList();

        if (keyEvents.Count < 2)
            return new DetectionSignal { SignalName = "KeyboardBehavior", Weight = 0.10, Score = 0.5, Description = "Insufficient keyboard data." };

        var delays = keyEvents
            .Where(e => e.Keyboard!.InterKeyDelayMs.HasValue)
            .Select(e => e.Keyboard!.InterKeyDelayMs!.Value)
            .ToList();

        double score = 0.5;

        if (delays.Count >= 2)
        {
            double mean = delays.Average();
            double stdDev = Math.Sqrt(delays.Sum(x => Math.Pow(x - mean, 2)) / delays.Count);
            double cv = mean > 0 ? stdDev / mean : 0;

            // Very consistent typing = bot
            double typingScore = cv < 0.1 ? 1.0 : cv < 0.2 ? 0.7 : cv < 0.4 ? 0.3 : 0.1;

            // Zero or near-zero error rate = suspicious
            var errorRates = keyEvents
                .Where(e => e.Keyboard!.ErrorRate.HasValue)
                .Select(e => e.Keyboard!.ErrorRate!.Value)
                .ToList();

            double errorScore = 0.5;
            if (errorRates.Count > 0)
            {
                double avgError = errorRates.Average();
                errorScore = avgError < 0.01 ? 0.9 : avgError < 0.03 ? 0.6 : avgError < 0.05 ? 0.3 : 0.1;
            }

            // v2: Also check if typing speed is superhuman (< 50ms between keys)
            double speedPenalty = mean < 30 ? 0.4 : mean < 60 ? 0.2 : mean < 100 ? 0.1 : 0;

            score = Math.Min(1.0, typingScore * 0.5 + errorScore * 0.3 + speedPenalty + 0.2 * (mean < 100 ? 1.0 : 0.0));
        }

        return new DetectionSignal
        {
            SignalName = "KeyboardBehavior",
            Weight = 0.10,
            Score = Math.Round(score, 4),
            Description = $"Analyzed {keyEvents.Count} keyboard events for consistency and error patterns."
        };
    }

    /// <summary>
    /// NEW v3: Navigation Behavior — catches Stealth Crawlers.
    /// 
    /// Stealth crawlers visit pages in sequential/systematic order and never revisit.
    /// Real humans:
    /// - Revisit pages (back button, re-reading)
    /// - Skip around randomly (not sequential)
    /// - Have "favorite" pages they return to
    /// 
    /// Signals:
    /// 1. Revisit ratio: humans revisit ~15% of pages, bots 0%
    /// 2. Sequential pattern: visiting /products/1, /2, /3... in order
    /// 3. Coverage efficiency: bots visit many unique pages with zero waste
    /// </summary>
    private DetectionSignal AnalyzeNavigationBehavior(List<ActivityEvent> events)
    {
        var endpoints = events
            .Select(e => e.Endpoint)
            .Where(e => !string.IsNullOrEmpty(e))
            .ToList();

        if (endpoints.Count < 5)
            return new DetectionSignal { SignalName = "NavigationBehavior", Weight = 0.12, Score = 0.5, Description = "Insufficient navigation data." };

        // 1. Revisit ratio: how often does the user go back to a previously visited page?
        int revisits = 0;
        var visited = new HashSet<string>();
        for (int i = 0; i < endpoints.Count; i++)
        {
            if (visited.Contains(endpoints[i]))
                revisits++;
            visited.Add(endpoints[i]);
        }
        double revisitRatio = (double)revisits / endpoints.Count;

        // Humans revisit 10-30% of pages. Bots almost never revisit (0-5%).
        double revisitScore;
        if (revisitRatio < 0.02) revisitScore = 0.9;       // Never revisits = bot
        else if (revisitRatio < 0.05) revisitScore = 0.7;
        else if (revisitRatio < 0.10) revisitScore = 0.5;
        else if (revisitRatio < 0.20) revisitScore = 0.3;
        else revisitScore = 0.1;                            // Lots of revisits = human

        // 2. Sequential pattern detection: are numbered pages visited in order?
        // e.g., /products/1, /products/2, /products/3...
        int sequentialPairs = 0;
        int totalPairs = 0;
        for (int i = 1; i < endpoints.Count; i++)
        {
            // Extract trailing numbers from paths
            var num1 = ExtractTrailingNumber(endpoints[i - 1]);
            var num2 = ExtractTrailingNumber(endpoints[i]);

            if (num1.HasValue && num2.HasValue)
            {
                totalPairs++;
                if (num2.Value == num1.Value + 1) // Sequential: 1→2, 2→3, etc.
                    sequentialPairs++;
            }
        }
        double seqRatio = totalPairs > 0 ? (double)sequentialPairs / totalPairs : 0;

        double seqScore;
        if (seqRatio > 0.6) seqScore = 0.95;    // Clearly sequential crawling
        else if (seqRatio > 0.4) seqScore = 0.7;
        else if (seqRatio > 0.2) seqScore = 0.4;
        else seqScore = 0.1;                      // Random order = human

        // 3. Consecutive same-page ratio: humans often stay on a page (scroll, click within)
        // Bots move to a new page every action
        int samePage = 0;
        for (int i = 1; i < endpoints.Count; i++)
        {
            if (endpoints[i] == endpoints[i - 1])
                samePage++;
        }
        double samePageRatio = (double)samePage / (endpoints.Count - 1);

        // Humans stay on same page ~30-50% of actions (scrolling, clicking within page)
        // Bots change page almost every action (samePageRatio < 10%)
        double stayScore;
        if (samePageRatio < 0.05) stayScore = 0.85;   // Never stays = bot
        else if (samePageRatio < 0.15) stayScore = 0.6;
        else if (samePageRatio < 0.25) stayScore = 0.3;
        else stayScore = 0.1;                           // Stays often = human

        double score = revisitScore * 0.40 + seqScore * 0.30 + stayScore * 0.30;

        return new DetectionSignal
        {
            SignalName = "NavigationBehavior",
            Weight = 0.12,
            Score = Math.Round(score, 4),
            Description = $"Revisit ratio: {revisitRatio:F2} (low=bot), Sequential: {seqRatio:F2}, Same-page: {samePageRatio:F2}."
        };
    }

    private int? ExtractTrailingNumber(string path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        var parts = path.TrimEnd('/').Split('/');
        var last = parts.LastOrDefault();
        if (int.TryParse(last, out int num)) return num;
        return null;
    }

    /// <summary>
    /// AI agents navigate directly to target endpoints without browsing.
    /// v2: Also detects the "browse then target" pattern where bots
    /// pretend to browse before hitting API endpoints.
    /// </summary>
    private DetectionSignal AnalyzeNavigationPattern(List<ActivityEvent> events)
    {
        var allEndpoints = events.Select(e => e.Endpoint).Where(e => !string.IsNullOrEmpty(e)).ToList();

        if (allEndpoints.Count < 2)
            return new DetectionSignal { SignalName = "NavigationPattern", Weight = 0.15, Score = 0.5, Description = "Insufficient navigation data." };

        // Check for API endpoint access (regardless of event type)
        int apiEndpoints = allEndpoints.Count(e => e.StartsWith("/api/"));
        double apiRatio = (double)apiEndpoints / allEndpoints.Count;

        // Navigation efficiency (unique / total)
        int uniqueEndpoints = allEndpoints.Distinct().Count();
        double efficiencyRatio = (double)uniqueEndpoints / allEndpoints.Count;

        // v2: Check for "browse then target" pattern
        // If session starts with browsing pages then switches to API calls
        bool hasBrowseThenTarget = false;
        if (apiEndpoints > 0)
        {
            int firstApiIndex = allEndpoints.FindIndex(e => e.StartsWith("/api/"));
            int browseBeforeApi = allEndpoints.Take(firstApiIndex).Count(e => !e.StartsWith("/api/"));
            if (browseBeforeApi >= 2 && firstApiIndex > allEndpoints.Count * 0.3)
            {
                hasBrowseThenTarget = true; // Suspicious: browsed first, then targeted APIs
            }
        }

        // Sequential rapid navigation (any event type)
        var navEvents = events.Where(e => e.EventType == "navigation" || e.EventType == "api_call").ToList();
        int sequentialApiCalls = 0;
        for (int i = 1; i < navEvents.Count; i++)
        {
            var gap = (navEvents[i].Timestamp - navEvents[i - 1].Timestamp).TotalMilliseconds;
            if (gap < 2000 && navEvents[i].Endpoint.StartsWith("/api/"))
                sequentialApiCalls++;
        }
        double seqRatio = navEvents.Count > 1 ? (double)sequentialApiCalls / (navEvents.Count - 1) : 0;

        // Combined score
        double apiScore = apiRatio > 0.3 ? 0.9 : apiRatio > 0.15 ? 0.7 : apiRatio > 0.05 ? 0.5 : apiRatio > 0 ? 0.3 : 0;
        double browseThenTargetScore = hasBrowseThenTarget ? 0.7 : 0;
        double seqScore = seqRatio > 0.3 ? 0.8 : seqRatio > 0.1 ? 0.5 : 0;

        double score = Math.Min(1.0, apiScore * 0.4 + browseThenTargetScore * 0.3 + seqScore * 0.2 + efficiencyRatio * 0.1);

        return new DetectionSignal
        {
            SignalName = "NavigationPattern",
            Weight = 0.15,
            Score = Math.Round(score, 4),
            Description = $"API ratio: {apiRatio:F2}, Efficiency: {efficiencyRatio:F2}, Browse-then-target: {hasBrowseThenTarget}, Seq API ratio: {seqRatio:F2}."
        };
    }

    /// <summary>
    /// NEW v3.2: Scroll Behavior / Reading Focal Point Analysis.
    /// 
    /// Humans read content at a natural "focal point" — typically 30-40% from the
    /// top of the viewport. They scroll in small increments to keep text in this zone.
    /// 
    /// Key human patterns:
    /// 1. Small scroll deltas (50-150px per scroll = 2-5 lines of text)
    /// 2. Scroll frequency matches reading speed (every 3-8 seconds)
    /// 3. Mouse Y position stays near the reading zone during scrolling
    /// 4. Variable scroll amounts (faster through boring content, slower through interesting)
    /// 
    /// Bot patterns:
    /// 1. Large uniform jumps (viewport height or fixed increments)
    /// 2. Constant scroll intervals (no reading speed correlation)
    /// 3. Mouse position doesn't correlate with scroll behavior
    /// 4. Scrolls entire page in 3-5 steps then leaves
    /// </summary>
    private DetectionSignal AnalyzeScrollBehavior(List<ActivityEvent> events)
    {
        var scrollEvents = events.Where(e => e.EventType == "scroll").ToList();

        if (scrollEvents.Count < 3)
            return new DetectionSignal { SignalName = "ScrollBehavior", Weight = 0.08, Score = 0.5, Description = "Insufficient scroll data." };

        // Extract scroll deltas and timing
        var deltas = new List<double>();
        var scrollIntervals = new List<double>();
        var mouseYDuringScroll = new List<int>();

        for (int i = 0; i < scrollEvents.Count; i++)
        {
            // Get delta from ScrollData if available, otherwise estimate from mouse Y movement
            if (scrollEvents[i].Scroll?.DeltaY != null && scrollEvents[i].Scroll!.DeltaY != 0)
            {
                deltas.Add(Math.Abs(scrollEvents[i].Scroll!.DeltaY));
            }
            else if (scrollEvents[i].Mouse != null)
            {
                // Estimate scroll from mouse Y position changes between scroll events
                if (i > 0 && scrollEvents[i - 1].Mouse != null)
                {
                    int dy = Math.Abs(scrollEvents[i].Mouse!.Y - scrollEvents[i - 1].Mouse!.Y);
                    if (dy > 0) deltas.Add(dy);
                }
            }

            // Mouse Y during scroll
            if (scrollEvents[i].Mouse != null)
            {
                mouseYDuringScroll.Add(scrollEvents[i].Mouse!.Y);
            }

            // Scroll intervals
            if (i > 0)
            {
                var gap = (scrollEvents[i].Timestamp - scrollEvents[i - 1].Timestamp).TotalMilliseconds;
                scrollIntervals.Add(gap);
            }
        }

        double score = 0.5; // Default neutral

        // 1. Scroll delta analysis: humans scroll 50-150px, bots scroll 300-1000px
        if (deltas.Count >= 2)
        {
            double avgDelta = deltas.Average();
            double deltaCV = deltas.Count > 1
                ? Math.Sqrt(deltas.Sum(d => Math.Pow(d - avgDelta, 2)) / deltas.Count) / avgDelta
                : 0;

            // Large uniform scrolls = bot
            double deltaScore;
            if (avgDelta > 500 && deltaCV < 0.2) deltaScore = 0.9;      // Big uniform jumps
            else if (avgDelta > 300 && deltaCV < 0.3) deltaScore = 0.7;  // Large-ish uniform
            else if (avgDelta > 200 && deltaCV < 0.15) deltaScore = 0.6; // Medium but too consistent
            else if (deltaCV < 0.1) deltaScore = 0.7;                     // Any size but zero variance
            else deltaScore = 0.1;                                         // Variable = human

            score = deltaScore * 0.35;
        }
        else
        {
            score = 0.5 * 0.35;
        }

        // 2. Scroll interval regularity: humans scroll at variable rates
        if (scrollIntervals.Count >= 2)
        {
            double avgInterval = scrollIntervals.Average();
            double intervalCV = Math.Sqrt(scrollIntervals.Sum(i => Math.Pow(i - avgInterval, 2)) / scrollIntervals.Count) / avgInterval;

            // Very regular scroll intervals = bot (reading at constant speed is unnatural)
            double intervalScore;
            if (intervalCV < 0.15) intervalScore = 0.9;    // Almost metronomic
            else if (intervalCV < 0.25) intervalScore = 0.7;
            else if (intervalCV < 0.40) intervalScore = 0.4;
            else intervalScore = 0.1;                       // Variable = human

            score += intervalScore * 0.30;
        }
        else
        {
            score += 0.5 * 0.30;
        }

        // 3. Mouse Y focal point: humans keep mouse near reading zone (30-40% of viewport)
        // Bots either have no mouse correlation or mouse stays fixed
        if (mouseYDuringScroll.Count >= 3)
        {
            double avgMouseY = mouseYDuringScroll.Average();
            double mouseYCV = Math.Sqrt(mouseYDuringScroll.Sum(y => Math.Pow(y - avgMouseY, 2)) / mouseYDuringScroll.Count) / Math.Max(1, avgMouseY);

            // If mouse Y increases linearly with scroll (bot scrolling pattern)
            bool isLinearMouseY = true;
            for (int i = 1; i < mouseYDuringScroll.Count; i++)
            {
                if (mouseYDuringScroll[i] < mouseYDuringScroll[i - 1] - 20) // Mouse went UP = human re-reading
                {
                    isLinearMouseY = false;
                    break;
                }
            }

            double focalScore;
            if (isLinearMouseY && mouseYCV > 0.5) focalScore = 0.8;  // Mouse just goes down linearly = bot
            else if (mouseYCV < 0.1) focalScore = 0.7;                // Mouse doesn't move at all during scroll = bot
            else focalScore = 0.1;                                     // Mouse moves around reading zone = human

            score += focalScore * 0.35;
        }
        else
        {
            score += 0.5 * 0.35;
        }

        return new DetectionSignal
        {
            SignalName = "ScrollBehavior",
            Weight = 0.08,
            Score = Math.Round(score, 4),
            Description = $"Analyzed {scrollEvents.Count} scroll events. Deltas: {deltas.Count}, Intervals: {scrollIntervals.Count}."
        };
    }

    /// <summary>
    /// <summary>
    /// NEW v4: Human Proof — catches Camoufox and similar perfect-evasion bots.
    /// 
    /// Real humans ALWAYS leave "proof of humanity" in their sessions:
    /// - They type something (search, form, comment)
    /// - They revisit pages (back button, re-reading)
    /// - They have idle gaps (distracted, thinking)
    /// - They scroll up (re-reading something)
    /// - They have typing errors
    /// 
    /// Camoufox-style bots avoid all detection signals but they also avoid
    /// leaving human proof. Zero proof in 10+ events = suspicious.
    /// </summary>
    private DetectionSignal AnalyzeHumanProof(List<ActivityEvent> events)
    {
        if (events.Count < 8)
            return new DetectionSignal { SignalName = "HumanProof", Weight = 0.12, Score = 0.5, Description = "Too few events." };

        int proofPoints = 0;

        // 1. Has keyboard events
        if (events.Any(e => e.Keyboard != null)) proofPoints += 2;

        // 2. Has revisits (same page appears again non-consecutively)
        var endpoints = events.Select(e => e.Endpoint).Where(e => !string.IsNullOrEmpty(e)).ToList();
        var seen = new HashSet<string>();
        for (int i = 0; i < endpoints.Count; i++)
        {
            if (seen.Contains(endpoints[i]) && (i == 0 || endpoints[i] != endpoints[i-1]))
            { proofPoints += 2; break; }
            seen.Add(endpoints[i]);
        }

        // 3. Has idle gap > 8s
        for (int i = 1; i < events.Count; i++)
        {
            if ((events[i].Timestamp - events[i-1].Timestamp).TotalMilliseconds > 8000)
            { proofPoints += 1; break; }
        }

        // 4. Has scroll up (mouse Y decreases during scroll)
        var scrolls = events.Where(e => e.EventType == "scroll" && e.Mouse != null).ToList();
        for (int i = 1; i < scrolls.Count; i++)
        {
            if (scrolls[i].Mouse!.Y < scrolls[i-1].Mouse!.Y - 20)
            { proofPoints += 1; break; }
        }

        // 5. Has typing errors
        if (events.Any(e => e.Keyboard?.ErrorRate > 0.02)) proofPoints += 2;

        // Score: 0 proof = very suspicious, 6+ = definitely human
        double score = proofPoints switch
        {
            0 => 0.90,
            1 => 0.75,
            2 => 0.55,
            3 => 0.35,
            4 => 0.20,
            _ => 0.05,
        };

        return new DetectionSignal
        {
            SignalName = "HumanProof",
            Weight = 0.12,
            Score = Math.Round(score, 4),
            Description = $"Human proof points: {proofPoints}/8. {(proofPoints == 0 ? "No typing, no revisits, no idle gaps." : "")}"
        };
    }

    /// <summary>
    /// NEW v2: Dedicated signal for API endpoint targeting.
    /// Real humans browsing a website almost NEVER hit /api/ endpoints directly.
    /// Any /api/ access from a browser session is a strong bot indicator.
    /// </summary>
    private DetectionSignal AnalyzeApiTargeting(List<ActivityEvent> events)
    {
        var allEndpoints = events.Select(e => e.Endpoint).Where(e => !string.IsNullOrEmpty(e)).ToList();

        if (allEndpoints.Count == 0)
            return new DetectionSignal { SignalName = "ApiTargeting", Weight = 0.15, Score = 0, Description = "No endpoints to analyze." };

        int apiHits = allEndpoints.Count(e => e.StartsWith("/api/"));
        double apiRatio = (double)apiHits / allEndpoints.Count;

        // Any API access at all is suspicious for a "browser" session
        double score;
        if (apiHits == 0) score = 0.0;          // No API access = normal human
        else if (apiRatio < 0.05) score = 0.3;  // Minimal API access
        else if (apiRatio < 0.10) score = 0.5;
        else if (apiRatio < 0.20) score = 0.7;  // Challenge bots land here (~13%)
        else if (apiRatio < 0.40) score = 0.85;
        else score = 1.0;                        // Heavy API usage = definitely bot

        // Bonus: check for data-extraction patterns (search, list, detail)
        bool hasSearch = allEndpoints.Any(e => e.Contains("search") || e.Contains("q="));
        bool hasList = allEndpoints.Any(e => e.EndsWith("/products") || e.EndsWith("/reviews"));
        bool hasDetail = allEndpoints.Any(e => e.Contains("/products/") && e.Split('/').Length > 3);

        if (hasSearch && hasList && apiHits > 0)
            score = Math.Min(1.0, score + 0.15);

        return new DetectionSignal
        {
            SignalName = "ApiTargeting",
            Weight = 0.15,
            Score = Math.Round(score, 4),
            Description = $"API hits: {apiHits}/{allEndpoints.Count} ({apiRatio * 100:F1}%). Search pattern: {hasSearch && hasList}."
        };
    }

    /// <summary>
    /// Looks at the overall session rhythm.
    /// AI agents don't take breaks, don't hesitate, and maintain constant activity.
    /// Humans have bursts of activity followed by idle periods.
    /// v2: Also checks for "fake pauses" that are too evenly distributed.
    /// </summary>
    private DetectionSignal AnalyzeSessionRhythm(List<ActivityEvent> events)
    {
        var intervals = new List<double>();
        for (int i = 1; i < events.Count; i++)
        {
            intervals.Add((events[i].Timestamp - events[i - 1].Timestamp).TotalMilliseconds);
        }

        if (intervals.Count < 5)
            return new DetectionSignal { SignalName = "SessionRhythm", Weight = 0.05, Score = 0.5, Description = "Insufficient data for rhythm analysis." };

        // Count "pauses" (gaps > 3 seconds) - humans pause to think
        int pauses = intervals.Count(i => i > 3000);
        double pauseRatio = (double)pauses / intervals.Count;

        // Count "idle gaps" (gaps > 10 seconds) - humans get distracted
        int idleGaps = intervals.Count(i => i > 10000);

        // v2: Check if pauses are too evenly spaced (bots add fake pauses at regular intervals)
        double pauseRegularity = 0;
        if (pauses >= 2)
        {
            var pauseIndices = new List<int>();
            for (int i = 0; i < intervals.Count; i++)
            {
                if (intervals[i] > 3000) pauseIndices.Add(i);
            }

            if (pauseIndices.Count >= 2)
            {
                var pauseGaps = new List<int>();
                for (int i = 1; i < pauseIndices.Count; i++)
                {
                    pauseGaps.Add(pauseIndices[i] - pauseIndices[i - 1]);
                }

                if (pauseGaps.Count > 0)
                {
                    double pauseMean = pauseGaps.Average();
                    double pauseStd = Math.Sqrt(pauseGaps.Sum(x => Math.Pow(x - pauseMean, 2)) / pauseGaps.Count);
                    pauseRegularity = pauseMean > 0 ? pauseStd / pauseMean : 0;
                    // If pauses are very regularly spaced (low CV), they might be fake
                }
            }
        }

        // AI agents have zero or near-zero pauses
        double score;
        if (pauseRatio < 0.02 && idleGaps == 0) score = 0.95;
        else if (pauseRatio < 0.05) score = 0.7;
        else if (pauseRatio < 0.10) score = 0.5;
        else if (pauseRatio < 0.15) score = 0.35;
        else score = 0.1; // lots of pauses = human

        // v2: Penalize if pauses are too regularly spaced
        if (pauseRegularity < 0.3 && pauses >= 2)
            score = Math.Min(1.0, score + 0.2); // Fake pauses detected

        return new DetectionSignal
        {
            SignalName = "SessionRhythm",
            Weight = 0.05,
            Score = Math.Round(score, 4),
            Description = $"Pause ratio: {pauseRatio:F2}, Idle gaps: {idleGaps}, Pause regularity CV: {pauseRegularity:F2}."
        };
    }
}
