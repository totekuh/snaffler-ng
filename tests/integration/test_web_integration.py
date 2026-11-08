"""Integration tests for web dashboard — runs against installed .deb package.

Tests the full stack: real snaffler scan against Samba share serving tests/data/,
web dashboard serving the resulting DB, hit with real browser via Playwright.
"""

import csv
import io
import sqlite3

import pytest
import requests
from playwright.sync_api import sync_playwright

SCAN_DB = "/work/scan.db"


@pytest.fixture(scope="module")
def finding_count():
    """Total findings from the real scan — single source of truth for assertions."""
    conn = sqlite3.connect(SCAN_DB)
    total = conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
    conn.close()
    return total


@pytest.fixture(scope="module")
def triage_counts():
    """Per-triage counts from the real scan."""
    conn = sqlite3.connect(SCAN_DB)
    rows = conn.execute("SELECT triage, COUNT(*) FROM finding GROUP BY triage").fetchall()
    conn.close()
    return dict(rows)


# ── API tests (no browser needed) ──────────────────────────────

class TestWebAPI:
    """HTTP API tests against the running server."""

    def test_dashboard_returns_html(self, web_server):
        _, port = web_server
        r = requests.get(f"http://127.0.0.1:{port}/")
        assert r.status_code == 200
        assert "text/html" in r.headers["Content-Type"]
        assert "Snaffler Results" in r.text

    def test_progress_reports_complete(self, web_server):
        _, port = web_server
        r = requests.get(f"http://127.0.0.1:{port}/api/progress")
        data = r.json()
        assert data["phase"] == "complete"
        assert data["scan_complete"] is True

    def test_findings_returns_all(self, web_server, finding_count):
        _, port = web_server
        r = requests.get(f"http://127.0.0.1:{port}/api/findings")
        data = r.json()
        assert len(data["findings"]) == finding_count

    def test_findings_pagination(self, web_server, finding_count):
        _, port = web_server
        r = requests.get(f"http://127.0.0.1:{port}/api/findings?limit=2")
        data = r.json()
        assert len(data["findings"]) == 2
        if finding_count > 2:
            assert data["has_more"] is True

        r2 = requests.get(
            f"http://127.0.0.1:{port}/api/findings?limit=2&since_rowid={data['max_rowid']}"
        )
        data2 = r2.json()
        assert len(data2["findings"]) > 0

    def test_findings_severity_filter(self, web_server):
        _, port = web_server
        r = requests.get(f"http://127.0.0.1:{port}/api/findings?min_interest=3")
        data = r.json()
        triages = {f["triage"] for f in data["findings"]}
        assert "Green" not in triages
        assert "Yellow" not in triages

    def test_findings_all_pages_equal_total(self, web_server, finding_count):
        """Paginate through all findings — sum must equal total."""
        _, port = web_server
        collected = 0
        cursor = 0
        for _ in range(100):
            r = requests.get(f"http://127.0.0.1:{port}/api/findings?limit=10&since_rowid={cursor}")
            data = r.json()
            collected += len(data["findings"])
            cursor = data["max_rowid"]
            if not data["has_more"]:
                break
        assert collected == finding_count

    def test_stats_endpoint(self, web_server):
        _, port = web_server
        r = requests.get(f"http://127.0.0.1:{port}/api/stats")
        assert r.status_code == 200
        data = r.json()
        assert "findings" in data
        assert "computers" in data
        assert "shares" in data
        assert data["findings"]["total"] > 0

    def test_export_csv(self, web_server, finding_count):
        _, port = web_server
        r = requests.get(f"http://127.0.0.1:{port}/api/export/csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers["Content-Type"]
        reader = csv.reader(io.StringIO(r.text))
        rows = list(reader)
        assert rows[0][0] == "triage"
        assert len(rows) == finding_count + 1  # header + findings

    def test_export_json(self, web_server, finding_count):
        _, port = web_server
        r = requests.get(f"http://127.0.0.1:{port}/api/export/json")
        assert r.status_code == 200
        data = r.json()
        assert len(data["findings"]) == finding_count

    def test_export_csv_matches_json(self, web_server):
        """CSV and JSON export same finding count."""
        _, port = web_server
        csv_r = requests.get(f"http://127.0.0.1:{port}/api/export/csv")
        json_r = requests.get(f"http://127.0.0.1:{port}/api/export/json")
        csv_count = len(list(csv.reader(io.StringIO(csv_r.text)))) - 1
        json_count = len(json_r.json()["findings"])
        assert csv_count == json_count

    def test_static_css_served(self, web_server):
        _, port = web_server
        r = requests.get(f"http://127.0.0.1:{port}/static/css/base.css")
        assert r.status_code == 200
        assert "text/css" in r.headers["Content-Type"]

    def test_static_js_served(self, web_server):
        _, port = web_server
        r = requests.get(f"http://127.0.0.1:{port}/static/js/dashboard.js")
        assert r.status_code == 200
        assert "javascript" in r.headers["Content-Type"]

    def test_no_cache_header(self, web_server):
        _, port = web_server
        r = requests.get(f"http://127.0.0.1:{port}/")
        assert r.headers.get("Cache-Control") == "no-store"


# ── Browser tests (Playwright + Chromium) ───────────────────────

class TestWebBrowser:
    """Full browser tests — JS execution, DOM state, user interaction."""

    @pytest.fixture
    def page(self, web_server):
        _, port = web_server
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            pg = browser.new_page()
            pg.goto(f"http://127.0.0.1:{port}/", wait_until="networkidle")
            pg.wait_for_function("document.querySelectorAll('#tbl tbody tr').length > 0", timeout=10000)
            pg.wait_for_function("document.getElementById('phase-text').textContent === 'Complete'", timeout=10000)
            yield pg
            browser.close()

    def test_title_has_finding_count(self, page, finding_count):
        title = page.title()
        assert f"({finding_count})" in title
        assert "Snaffler Results" in title

    def test_phase_shows_complete(self, page):
        text = page.text_content("#phase-text")
        assert text == "Complete"

    def test_phase_dot_not_pulsing(self, page):
        dot = page.locator("#phase-dot")
        assert "active" not in (dot.get_attribute("class") or "")

    def test_findings_table_populated(self, page, finding_count):
        rows = page.locator("#tbl tbody tr")
        assert rows.count() == finding_count

    def test_severity_counts_match_db(self, page, triage_counts):
        for triage, expected in triage_counts.items():
            el_id = f"sev-{triage.lower()}"
            displayed = int(page.text_content(f"#{el_id}").replace(",", ""))
            assert displayed == expected, f"{triage}: expected {expected}, got {displayed}"

    def test_card_shares_nonzero(self, page):
        shares = page.text_content("#card-shares")
        parts = shares.split("/")
        assert int(parts[0].strip().replace(",", "")) > 0

    def test_rate_indicators_hidden(self, page):
        box = page.locator("#rate-box")
        assert not box.is_visible()

    def test_triage_filter(self, page, triage_counts):
        if "Red" not in triage_counts:
            pytest.skip("No Red findings in scan")
        page.click('.badge[data-triage="Red"]')
        page.wait_for_timeout(300)
        visible = page.locator("#tbl tbody tr:visible")
        assert visible.count() == triage_counts["Red"]
        for i in range(visible.count()):
            assert visible.nth(i).get_attribute("data-triage") == "Red"

    def test_clear_filter(self, page, finding_count):
        page.click('.badge[data-triage="Red"]')
        page.wait_for_timeout(100)
        page.click("#clear-filter")
        page.wait_for_timeout(100)
        visible = page.locator("#tbl tbody tr:visible")
        assert visible.count() == finding_count

    def test_search_filter(self, page):
        page.fill("#search", "password")
        page.wait_for_timeout(300)
        visible = page.locator("#tbl tbody tr:visible")
        assert visible.count() >= 1

    def test_modal_opens_on_row_click(self, page):
        page.locator("#tbl tbody tr").first.click()
        page.wait_for_timeout(200)
        overlay = page.locator("#overlay")
        assert not overlay.locator(".hidden").count()
        assert page.locator("#m-path").text_content() != ""

    def test_modal_closes_on_escape(self, page):
        page.locator("#tbl tbody tr").first.click()
        page.wait_for_timeout(200)
        page.keyboard.press("Escape")
        page.wait_for_timeout(200)
        assert "hidden" in (page.locator("#overlay").get_attribute("class") or "")

    def test_modal_copy_button_exists(self, page):
        page.locator("#tbl tbody tr").first.click()
        page.wait_for_timeout(200)
        assert page.locator("#copy-path").is_visible()

    def test_column_sort(self, page):
        page.click('th[data-col="1"]')
        page.wait_for_timeout(200)
        th = page.locator('th[data-col="1"]')
        assert "sort-asc" in (th.get_attribute("class") or "")

    def test_url_updates_on_filter(self, page):
        page.click('.badge[data-triage="Red"]')
        page.wait_for_timeout(200)
        assert "triage=Red" in page.url

    def test_url_filter_restored_on_load(self, web_server, triage_counts):
        if "Red" not in triage_counts:
            pytest.skip("No Red findings in scan")
        _, port = web_server
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            pg = browser.new_page()
            pg.goto(f"http://127.0.0.1:{port}/?triage=Red", wait_until="networkidle")
            pg.wait_for_function("document.querySelectorAll('#tbl tbody tr').length > 0", timeout=10000)
            pg.wait_for_timeout(500)
            visible = pg.locator("#tbl tbody tr:visible")
            assert visible.count() == triage_counts["Red"]
            browser.close()

    def test_no_js_errors(self, web_server):
        """Verify zero console errors during page load and interaction."""
        _, port = web_server
        errors = []
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            pg = browser.new_page()
            pg.on("pageerror", lambda err: errors.append(str(err)))
            pg.goto(f"http://127.0.0.1:{port}/", wait_until="networkidle")
            pg.wait_for_function(
                "document.querySelectorAll('#tbl tbody tr').length > 0", timeout=10000
            )
            pg.click('.badge[data-triage="Red"]')
            pg.wait_for_timeout(200)
            pg.click("#clear-filter")
            pg.wait_for_timeout(200)
            pg.fill("#search", "test")
            pg.wait_for_timeout(200)
            pg.fill("#search", "")
            pg.wait_for_timeout(200)
            pg.locator("#tbl tbody tr:visible").first.click()
            pg.keyboard.press("Escape")
            pg.wait_for_timeout(500)
            browser.close()
        assert errors == [], f"JS console errors: {errors}"
