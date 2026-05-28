"""
Bot that scrapes the ShopMax site AND sends its activity directly
to the detection engine to see if it gets caught.

No need to wait for the tracker — this bot reports itself.
"""

from DrissionPage import ChromiumPage, ChromiumOptions
import time
import json
import requests
from datetime import datetime, timezone

TARGET = "http://localhost:8080"
DETECT_API = "http://localhost:5000/api/ban/analyze-and-ban"


def main():
    print("=" * 60)
    print("  BOT SCRAPER + DETECTION CHECK")
    print("=" * 60)

    # Start headless Chrome
    print("\n  Starting browser...")
    co = ChromiumOptions()
    co.headless()
    co.set_argument('--no-sandbox')

    page = ChromiumPage(co)
    print(f"  Target: {TARGET}\n")

    # Record all activity as events
    events = []
    session_id = f"scraper-bot-{int(time.time())}"
    start = time.time()

    def record(event_type, endpoint, mouse_x=0, mouse_y=0, speed=0):
        events.append({
            "sessionId": session_id,
            "userId": "scraper-bot",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "eventType": event_type,
            "endpoint": endpoint,
            "durationMs": int((time.time() - start) * 100) % 500,
            "mouse": {"x": mouse_x, "y": mouse_y, "speed": speed, "hasCurve": False} if mouse_x else None,
            "keyboard": None,
        })

    # === SCRAPE THE SITE ===
    print("  Scraping...")

    # Page 1: Home
    page.get(TARGET)
    record("navigation", "/", 500, 300, 1200)
    time.sleep(0.5)

    # Rapid clicks on products
    products = []
    cards = page.eles('css:.product-card')
    for i, card in enumerate(cards):
        try:
            name = card.ele('css:h3').text
            price = card.ele('css:.price').text
            products.append({"name": name, "price": price})
            record("click", f"/products/{i+1}", 400 + i*100, 300, 1100 + i*50)
            print(f"    [{i+1}] {name} — {price}")
        except:
            pass
        time.sleep(0.2)  # Bot-fast

    # Scrape blog
    posts = []
    blog_items = page.eles('css:.blog-post')
    for i, post in enumerate(blog_items):
        try:
            title = post.ele('css:h3').text
            posts.append(title)
            record("scroll", f"/blog/post-{i+1}", 500, 200 + i*150, 900)
        except:
            pass
        time.sleep(0.2)

    # Rapid reloads
    for i in range(4):
        page.get(TARGET)
        record("navigation", "/", 500, 300, 1300)
        time.sleep(0.3)

    page.quit()

    print(f"\n  Scraped {len(products)} products, {len(posts)} blog posts")
    print(f"  Recorded {len(events)} activity events")

    # === SEND TO DETECTION ENGINE ===
    print(f"\n  Sending to detection engine...")

    session_data = {
        "sessionId": session_id,
        "userId": "scraper-bot",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/148.0.0.0",
        "ipAddress": "10.0.0.99",
        "events": events,
    }

    # Also send to SDK dashboard so it shows up there
    sdk_payload = {
        "apiKey": "shopmax-demo-key",
        "sessionId": session_id,
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/148.0.0.0",
        "url": TARGET,
        "events": events,
    }
    requests.post("http://localhost:5000/api/sdk/track", json=sdk_payload)

    resp = requests.post(DETECT_API, json=session_data, params={"ipAddress": "10.0.0.99"})

    if resp.status_code == 200:
        result = resp.json()
        detected = result.get("detected", False)
        score = result.get("aiProbabilityScore", 0)

        print(f"\n  {'🚨 BOT DETECTED!' if detected else '✅ Not detected'}")
        print(f"  Score: {score:.4f}")

        if result.get("ban"):
            ban = result["ban"]
            print(f"  Banned: {ban['banType']} / {ban['penalty']}")
            print(f"  Reason: {ban['reason']}")
            print(f"  Triggered: {ban['triggeredRule']}")

        print(f"\n  Signal breakdown:")
        for s in result.get("signals", []):
            bar = "█" * int(s["score"] * 15)
            print(f"    {s['signalName']:25} {s['score']:.2f} {bar}")
    else:
        print(f"  API error: {resp.status_code} {resp.text[:200]}")

    # Save scraped data
    with open("scraped_data.json", "w") as f:
        json.dump({"products": products, "posts": posts, "detected": detected, "score": score}, f, indent=2)

    print(f"\n  Data saved to scraped_data.json")
    print("=" * 60)


if __name__ == "__main__":
    main()
