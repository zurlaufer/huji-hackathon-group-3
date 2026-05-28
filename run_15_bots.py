"""Run 15 different bots against the demo site and register them in the dashboard."""

import json
import random
import time
from datetime import datetime, timedelta, timezone
import requests

SDK_URL = "http://localhost:5000/api/sdk/track"
DETECT_URL = "http://localhost:5000/api/ban/analyze-and-ban"
API_KEY = "shopmax-demo-key"


def ts(base, offset_ms):
    t = base + timedelta(milliseconds=offset_ms)
    return t.isoformat()


def make_bot(name, bot_type, events):
    """Send bot to both SDK dashboard and detection engine."""
    session_id = f"{name}-{int(time.time())}"
    
    session = {
        "sessionId": session_id,
        "userId": name,
        "userAgent": events[0].get("ua", "Bot/1.0"),
        "ipAddress": f"10.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}",
        "events": [{"sessionId": session_id, "userId": name, **e} for e in events],
    }

    # Register in dashboard
    sdk_payload = {
        "apiKey": API_KEY,
        "sessionId": session_id,
        "userAgent": session["userAgent"],
        "url": "http://localhost:8080",
        "events": session["events"],
    }
    requests.post(SDK_URL, json=sdk_payload, timeout=5)

    # Detect
    resp = requests.post(DETECT_URL, json=session, params={"ipAddress": session["ipAddress"]}, timeout=5)
    if resp.status_code == 200:
        r = resp.json()
        return session_id, r.get("detected", False), r.get("aiProbabilityScore", 0), bot_type
    return session_id, None, 0, bot_type


def gen_events(base, intervals, event_type, endpoint, mouse_speed, has_curve):
    """Generate events from parameters."""
    events = []
    offset = 0
    for i, interval in enumerate(intervals):
        offset += interval
        events.append({
            "timestamp": ts(base, offset),
            "eventType": event_type if isinstance(event_type, str) else event_type[i % len(event_type)],
            "endpoint": endpoint if isinstance(endpoint, str) else endpoint[i % len(endpoint)],
            "durationMs": random.randint(50, 500),
            "mouse": {"x": random.randint(100, 1800), "y": random.randint(100, 900),
                      "speed": mouse_speed + random.uniform(-50, 50), "hasCurve": has_curve},
            "keyboard": None,
            "scroll": None,
        })
    return events


def main():
    print("=" * 60)
    print("  RUNNING 15 DIFFERENT BOTS — Watch the dashboard!")
    print("  Dashboard: http://localhost:8080/dashboard.html")
    print("=" * 60)

    base = datetime.now(timezone.utc)
    results = []

    bots = [
        # 1. Speed scraper
        ("speed-scraper", "Speed Scraper", gen_events(
            base, [random.uniform(50, 150) for _ in range(15)],
            ["api_call", "navigation"], ["/api/products", "/api/prices", "/products/1"],
            5000, False)),

        # 2. Slow methodical crawler
        ("slow-crawler", "Slow Crawler", gen_events(
            base, [random.uniform(2000, 3000) for _ in range(12)],
            "navigation", [f"/products/{i}" for i in range(1, 13)],
            800, True)),

        # 3. Form brute-forcer
        ("brute-forcer", "Brute Force", gen_events(
            base, [random.uniform(200, 500) for _ in range(20)],
            ["navigation", "keypress", "form_submit", "navigation"],
            ["/login", "/login", "/login", "/login"],
            4000, False)),

        # 4. Content scraper (scrolls fast)
        ("content-scraper", "Content Scraper", gen_events(
            base, [random.uniform(800, 1200) for _ in range(18)],
            ["navigation", "scroll", "scroll", "scroll"],
            ["/blog/post-1", "/blog/post-1", "/blog/post-1", "/blog/post-2"],
            600, False)),

        # 5. Price monitor bot
        ("price-monitor", "Price Monitor", gen_events(
            base, [random.uniform(100, 300) for _ in range(10)],
            "api_call", ["/api/products/1", "/api/products/2", "/api/products/3", "/api/prices"],
            0, False)),

        # 6. SEO crawler
        ("seo-crawler", "SEO Crawler", gen_events(
            base, [random.uniform(1500, 2500) for _ in range(14)],
            "navigation", ["/", "/products", "/about", "/blog", "/contact", "/faq", "/sitemap"],
            900, True)),

        # 7. Account checker
        ("account-checker", "Account Checker", gen_events(
            base, [random.uniform(300, 700) for _ in range(16)],
            ["navigation", "keypress", "form_submit", "navigation"],
            ["/login", "/login", "/api/auth/check", "/account"],
            3500, False)),

        # 8. Image scraper
        ("image-scraper", "Image Scraper", gen_events(
            base, [random.uniform(100, 400) for _ in range(12)],
            "navigation", ["/products/1/image", "/products/2/image", "/products/3/image"],
            0, False)),

        # 9. Headless Chrome bot
        ("headless-chrome", "Headless Chrome", gen_events(
            base, [random.gauss(6000, 150) for _ in range(8)],
            "navigation", ["/", "/products", "/about", "/contact", "/blog", "/faq", "/cart", "/"],
            1200, False)),

        # 10. Playwright bot
        ("playwright-bot", "Playwright", gen_events(
            base, [random.uniform(1000, 2000) for _ in range(10)],
            ["click", "navigation", "scroll"],
            ["/products", "/products/3", "/products/3", "/cart"],
            1100, True)),

        # 11. Selenium bot
        ("selenium-bot", "Selenium", gen_events(
            base, [random.gauss(3000, 300) for _ in range(11)],
            ["navigation", "click", "click"],
            ["/", "/products", "/products/5", "/cart", "/checkout"],
            950, False)),

        # 12. Data harvester
        ("data-harvester", "Data Harvester", gen_events(
            base, [random.uniform(500, 1000) for _ in range(15)],
            ["navigation", "scroll", "scroll", "navigation"],
            ["/products", "/products", "/products", "/products/1"],
            700, False)),

        # 13. Sneaky residential proxy bot
        ("residential-bot", "Residential Proxy", gen_events(
            base, [random.lognormvariate(7.0, 0.4) for _ in range(9)],
            "navigation", ["/", "/products", "/products/2", "/products/5", "/cart"],
            750, True)),

        # 14. API abuser
        ("api-abuser", "API Abuser", gen_events(
            base, [random.uniform(30, 80) for _ in range(25)],
            "api_call", ["/api/products", "/api/search?q=shoes", "/api/cart/add", "/api/checkout"],
            0, False)),

        # 15. Click farm bot
        ("click-farm", "Click Farm", gen_events(
            base, [random.uniform(2000, 4000) for _ in range(10)],
            "click", ["/products/1", "/products/2", "/products/3", "/products/4", "/products/5"],
            1000, True)),
    ]

    # Add user-agents
    uas = {
        "speed-scraper": "python-requests/2.31.0",
        "slow-crawler": "Mozilla/5.0 (compatible; Googlebot/2.1)",
        "brute-forcer": "Mozilla/5.0 (Windows NT 10.0) Chrome/125.0",
        "content-scraper": "Scrapy/2.11.0",
        "price-monitor": "PriceBot/1.0",
        "seo-crawler": "Mozilla/5.0 (compatible; AhrefsBot/7.0)",
        "account-checker": "Mozilla/5.0 (Linux; Android 14) Chrome/125.0",
        "image-scraper": "curl/8.4.0",
        "headless-chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/148.0",
        "playwright-bot": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0",
        "selenium-bot": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0",
        "data-harvester": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1",
        "residential-bot": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) Safari/605.1",
        "api-abuser": "Go-http-client/2.0",
        "click-farm": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/126.0",
    }

    for name, bot_type, events in bots:
        for e in events:
            e["ua"] = uas.get(name, "Bot/1.0")

        sid, detected, score, btype = make_bot(name, bot_type, events)
        status = "🚨 CAUGHT" if detected else ("⚠️ MISSED" if detected is False else "❌ ERROR")
        results.append({"name": name, "type": btype, "detected": detected, "score": score})
        print(f"  {bot_type:<20} score={score:.3f}  {status}")
        time.sleep(0.3)

    # Summary
    caught = sum(1 for r in results if r["detected"])
    missed = sum(1 for r in results if r["detected"] is False)
    print(f"\n  {'─' * 50}")
    print(f"  Results: {caught}/15 caught, {missed} missed")
    print(f"\n  Now check: http://localhost:8080/dashboard.html")
    print("=" * 60)


if __name__ == "__main__":
    main()
