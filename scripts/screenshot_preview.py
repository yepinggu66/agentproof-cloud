"""Take preview screenshots of the AgentProof.cloud site with Playwright.

Usage:  python scripts/screenshot_preview.py [base_url] [out_dir]
Requires the service running (see README) and ``playwright`` installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8791"
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else ".tmp/shots")
OUT.mkdir(parents=True, exist_ok=True)

errors: list[str] = []


def shot(page, name: str, full: bool = False) -> None:
    path = OUT / name
    page.screenshot(path=str(path), full_page=full)
    print("saved", path)


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))
        page.on("console", lambda msg: errors.append(f"console.{msg.type}: {msg.text}") if msg.type == "error" else None)

        # 1. home
        page.goto(BASE + "/#/home", wait_until="networkidle")
        page.wait_for_timeout(600)
        shot(page, "01-home-hero.png")
        shot(page, "01b-home-full.png", full=True)

        # 2. scanner with dangerous sample
        page.click("[data-sample='danger']")
        page.click("#scanBtn")
        page.wait_for_selector("#scanResult:not([hidden])", timeout=15000)
        page.wait_for_timeout(700)
        page.locator("#scanResult").scroll_into_view_if_needed()
        page.evaluate("window.scrollBy(0, -110)")
        page.wait_for_timeout(400)
        shot(page, "02-scan-result.png")

        # 3. pricing
        page.goto(BASE + "/#/pricing", wait_until="networkidle")
        page.wait_for_timeout(500)
        shot(page, "03-pricing.png", full=True)

        # 4. signup -> success
        page.fill("#companyInput", "Acme Support")
        page.fill("#emailInput", "ops@acme.dev")
        page.select_option("#planSelect", "pro")
        page.click("#signupBtn")
        page.wait_for_selector("#signupSuccess:not([hidden])", timeout=15000)
        page.wait_for_timeout(600)
        page.locator("#signupSuccess").scroll_into_view_if_needed()
        page.wait_for_timeout(300)
        shot(page, "04-signup-success.png")

        # 5. console
        page.goto(BASE + "/#/console", wait_until="networkidle")
        page.wait_for_selector("#consoleRoot:not([hidden])", timeout=15000)
        page.wait_for_timeout(800)
        shot(page, "05-console.png")

        page.fill("#simAction", "order.refund")
        page.select_option("#simDecision", "DENY")
        page.fill("#simReason", "金额超过 500 需人工复核")
        page.click("#simulateBtn")
        page.wait_for_timeout(1500)
        page.click("#verifyBtn")
        page.wait_for_timeout(1500)
        page.locator("#verifyVerdict").scroll_into_view_if_needed()
        page.evaluate("window.scrollBy(0, -240)")
        page.wait_for_timeout(400)
        shot(page, "06-console-verified.png")

        # 6. integrations
        page.goto(BASE + "/#/integrations", wait_until="networkidle")
        page.wait_for_timeout(500)
        page.click("[data-vendor='vanta']")
        page.wait_for_timeout(1200)
        shot(page, "07-integrations.png")

        # 7. mobile
        mobile = browser.new_page(viewport={"width": 390, "height": 844})
        mobile.goto(BASE + "/#/home", wait_until="networkidle")
        mobile.wait_for_timeout(500)
        shot(mobile, "08-mobile-home.png")

        browser.close()

    if errors:
        print("\nPAGE ERRORS:")
        for item in errors:
            print(" -", item)
        return 1
    print("no page errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
