"""
Bot that scrapes the ShopMax demo site.
Run this while the demo site is open in your browser to see it appear
as a BOT in the dashboard.

Usage:
    python scrape_demo_site.py

Make sure these are running first:
    - AISecutity API: dotnet run --urls http://localhost:5000
    - Demo site: python -m http.server 8080 (in customer-demo-site/)
"""

from DrissionPage import ChromiumPage, ChromiumOptions
import time
import json

TARGET = "http://localhost:8080"


def main():
    print("=" * 60)
    print("  BOT SCRAPER — Scraping ShopMax Demo Site")
    print("  This will show up as a BOT in the dashboard")
    print("=" * 60)

    # Start headless Chrome
    print("\n  Starting browser...")
    co = ChromiumOptions()
    co.headless()
    co.set_argument('--no-sandbox')
    co.set_argument('--disable-gpu')

    try:
        page = ChromiumPage(co)
    except Exception as e:
        print(f"  Chrome failed: {e}")
        print("  Make sure Chrome/Chromium is installed")
        return

    print(f"  Target: {TARGET}")
    print(f"  Scraping products...\n")

    # Navigate to the site
    page.get(TARGET)
    time.sleep(3)

    # Scrape product data
    products = []
    try:
        cards = page.eles('css:.product-card')
        for i, card in enumerate(cards):
            try:
                name = card.ele('css:h3').text
                price = card.ele('css:.price').text
                products.append({"name": name, "price": price})
                print(f"  [{i+1}] {name} — {price}")
            except:
                pass
            time.sleep(0.1)
    except:
        print("  Could not find product cards, trying text extraction...")
        text = page.html
        # Extract from raw HTML
        import re
        prices = re.findall(r'\$[\d.]+', text)
        titles = re.findall(r'<h3>(.*?)</h3>', text)
        for t, p in zip(titles, prices):
            products.append({"name": t, "price": p})
            print(f"  Found: {t} — {p}")

    # Scrape blog posts
    print(f"\n  Scraping blog posts...")
    posts = []
    try:
        blog_items = page.eles('css:.blog-post')
        for i, post in enumerate(blog_items):
            try:
                title = post.ele('css:h3').text
                content = post.ele('css:p').text[:80]
                posts.append({"title": title, "content": content})
                print(f"  [{i+1}] {title}")
            except:
                pass
            time.sleep(0.1)
    except:
        pass

    # Rapid page visits (bot behavior)
    print(f"\n  Rapid navigation (bot-like)...")
    for i in range(3):
        try:
            page.get(TARGET)
            time.sleep(1)
            print(f"  Reload {i+1}/3")
        except:
            break

    page.quit()

    # Save scraped data
    data = {
        "scraped_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": TARGET,
        "products": products,
        "blog_posts": posts,
    }

    with open("scraped_data.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"\n  Done! Scraped {len(products)} products, {len(posts)} blog posts")
    print(f"  Data saved to: scraped_data.json")
    print(f"\n  Now check the dashboard: http://localhost:8080/dashboard.html")
    print(f"  You should see this session flagged as a BOT 🤖")
    print("=" * 60)


if __name__ == "__main__":
    main()
