#!/usr/bin/env python3
"""Public OSINT Market Research Aggregator.

Discovers public company websites from a small, user-supplied query list using
DuckDuckGo's public HTML results page. It then reviews only robot-permitted,
non-platform company pages and stores explicitly published role-based business
email addresses.

Deliberate safeguards:
- Stable, truthful user agent; no proxy, user-agent rotation or fingerprint masking.
- No CAPTCHA bypass. A block marker stops SERP processing immediately.
- One result page per query; no pagination; minimum 30-second gap between queries.
- Conservative robots.txt policy: unavailable/disallowed robots.txt means skip.
- Excludes search engines, social networks, LinkedIn and common directories.
- Ignores person-named and personal-webmail email addresses.

Use this script only for internal market research on public websites and only
where the collection and any subsequent marketing use are lawful.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import random
import re
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote_plus, unquote, urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from urllib.robotparser import RobotFileParser

from playwright.sync_api import Browser, Error as PlaywrightError, Page, sync_playwright

APP_NAME = "PublicOSINTMarketResearch"
APP_VERSION = "1.0.0"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
SERP_URL = "https://html.duckduckgo.com/html/?q="
REQUEST_TIMEOUT_SECONDS = 15
PAGE_TIMEOUT_MS = 25_000
COMPANY_DELAY_MIN_SECONDS = 8
COMPANY_DELAY_MAX_SECONDS = 15
QUERY_DELAY_MIN_SECONDS = 30
QUERY_DELAY_MAX_SECONDS = 60
MAX_CONTACT_PAGES_PER_SITE = 2
DEBUG_DIR: Path | None = None
FAST_MODE = False

# These hosts are not treated as company sites. Extend deliberately if a source
# is unsuitable for your authorised research workflow.
DISALLOWED_HOST_SUFFIXES = {
    "duckduckgo.com",
    "google.com",
    "bing.com",
    "linkedin.com",
    "facebook.com",
    "instagram.com",
    "x.com",
    "twitter.com",
    "youtube.com",
    "tiktok.com",
    "clutch.co",
    "designrush.com",
    "sortlist.com",
    "themanifest.com",
    "yelp.com",
    "yellowpages.com",
    "crunchbase.com",
    "zoominfo.com",
    "apollo.io",
    "goodfirms.co",
}


PERSONAL_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "hotmail.com", "icloud.com", "live.com",
    "me.com", "msn.com", "outlook.com", "proton.me", "protonmail.com", "yahoo.com",
}
CONTACT_LINK_KEYWORDS = ("contact", "about", "team", "company", "support")
EMAIL_PATTERN = re.compile(r"(?<![\w.+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63})(?![\w.-])", re.IGNORECASE)
BLOCK_MARKERS = (
    "captcha", "unusual traffic", "access denied", "verify you are human",
    "checking your browser", "cf-chl", "temporarily blocked",
)


@dataclass(frozen=True)
class PublicBusinessLead:
    target_url: str
    company_name: str
    verified_corporate_email: str
    source_page: str
    search_query: str
    collected_at_utc: str


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path

    def event(self, status: str, url: str, detail: str = "") -> None:
        record = {"timestamp_utc": utc_now(), "status": status, "url": url, "detail": detail}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


class LeadStore:
    def __init__(self, database_path: Path, csv_path: Path) -> None:
        self.csv_path = csv_path
        self.connection = sqlite3.connect(database_path)
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS public_business_leads (
                source_page TEXT NOT NULL,
                verified_corporate_email TEXT NOT NULL,
                target_url TEXT NOT NULL,
                company_name TEXT NOT NULL,
                search_query TEXT NOT NULL,
                collected_at_utc TEXT NOT NULL,
                PRIMARY KEY (source_page, verified_corporate_email)
            )
            """
        )
        self.connection.commit()
        self._ensure_csv_header()

    def _ensure_csv_header(self) -> None:
        if self.csv_path.exists() and self.csv_path.stat().st_size > 0:
            return
        with self.csv_path.open("w", encoding="utf-8", newline="") as handle:
            csv.writer(handle).writerow(
                ["Target URL", "Company Name/Title", "Verified Corporate Email", "Source Page", "Search Query", "Collected At UTC"]
            )

    def save_if_new(self, lead: PublicBusinessLead) -> bool:
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO public_business_leads
            (source_page, verified_corporate_email, target_url, company_name, search_query, collected_at_utc)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (lead.source_page, lead.verified_corporate_email, lead.target_url, lead.company_name, lead.search_query, lead.collected_at_utc),
        )
        self.connection.commit()
        if cursor.rowcount != 1:
            return False
        with self.csv_path.open("a", encoding="utf-8", newline="") as handle:
            csv.writer(handle).writerow(
                [lead.target_url, lead.company_name, lead.verified_corporate_email, lead.source_page, lead.search_query, lead.collected_at_utc]
            )
        return True

    def close(self) -> None:
        self.connection.close()


class RobotsPolicy:
    """Conservative robots validator; request failures cause an intentional skip."""

    def __init__(self, audit: AuditLog) -> None:
        self.audit = audit
        self.cache: dict[str, RobotFileParser | None] = {}

    def allows(self, url: str) -> bool:
        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self.cache:
            self.cache[origin] = self._fetch(origin)
        parser = self.cache[origin]
        if parser is None:
            self.audit.event("robots_unavailable_skip", url, "robots.txt could not be obtained")
            return False
        allowed = parser.can_fetch(USER_AGENT, url)
        if not allowed:
            self.audit.event("robots_disallow_skip", url, "robots.txt disallows collector")
        return allowed

    def _fetch(self, origin: str) -> RobotFileParser | None:
        robots_url = f"{origin}/robots.txt"
        request = Request(robots_url, headers={"User-Agent": USER_AGENT})
        try:
            with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            if exc.code == 404:
                parser = RobotFileParser()
                parser.set_url(robots_url)
                parser.parse([])
                return parser
            self.audit.event("robots_http_error", robots_url, f"HTTP {exc.code}")
            return None
        except (URLError, TimeoutError, OSError) as exc:
            self.audit.event("robots_network_error", robots_url, str(exc))
            return None
        parser = RobotFileParser()
        parser.set_url(robots_url)
        parser.parse(raw.splitlines())
        return parser


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.startswith("//"):
        value = "https:" + value
    if not value.startswith(("http://", "https://")):
        return ""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


def hostname(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def same_host(left: str, right: str) -> bool:
    return hostname(left) == hostname(right)


def is_disallowed_host(url: str) -> bool:
    current = hostname(url)
    return any(current == suffix or current.endswith("." + suffix) for suffix in DISALLOWED_HOST_SUFFIXES)


def is_allowed_role_address(email: str) -> bool:
    local_part, _, domain = email.lower().partition("@")
    return bool(local_part and domain and domain not in PERSONAL_EMAIL_DOMAINS)


def extract_role_emails(html: str, mailto_values: Iterable[str]) -> list[str]:
    candidates = {match.group(1).strip(".,;:)]}>\"'").lower() for match in EMAIL_PATTERN.finditer(html)}
    for raw in mailto_values:
        value = unquote(raw).split("?", 1)[0].strip().lower()
        if EMAIL_PATTERN.fullmatch(value):
            candidates.add(value)
    return sorted(email for email in candidates if is_allowed_role_address(email))


def page_is_blocked(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in BLOCK_MARKERS)


def debug_snapshot(page: Page, label: str) -> None:
    if DEBUG_DIR is None:
        return
    DEBUG_DIR.mkdir(parents=True, exist_ok=True)
    safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label)[:100]
    try:
        (DEBUG_DIR / f"{safe_label}.html").write_text(page.content(), encoding="utf-8")
        page.screenshot(path=str(DEBUG_DIR / f"{safe_label}.png"), full_page=True)
    except PlaywrightError as exc:
        logging.debug("debug snapshot failed for %s: %s", label, exc)


def polite_company_delay() -> None:
    if FAST_MODE:
        time.sleep(random.uniform(0.5, 1.0))
    else:
        time.sleep(random.uniform(COMPANY_DELAY_MIN_SECONDS, COMPANY_DELAY_MAX_SECONDS))


def query_delay() -> None:
    if FAST_MODE:
        time.sleep(random.uniform(1.0, 2.0))
    else:
        time.sleep(random.uniform(QUERY_DELAY_MIN_SECONDS, QUERY_DELAY_MAX_SECONDS))


def load_queries(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"Query file not found: {path}")
    values: list[str] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "query" not in reader.fieldnames:
            raise ValueError("Query CSV must have a query column")
        for row in reader:
            query = (row.get("query") or "").strip()
            if query:
                values.append(query)
    return list(dict.fromkeys(values))


def resolve_ddg_result(href: str) -> str:
    """Returns a direct public URL from either a direct link or DDG redirect link."""
    href = href.strip()
    absolute = urljoin("https://html.duckduckgo.com/", href)
    parsed = urlsplit(absolute)
    if (parsed.hostname or "").lower().endswith("duckduckgo.com"):
        target = parse_qs(parsed.query).get("uddg", [""])[0]
        return normalize_url(unquote(target))
    return normalize_url(absolute)


def discover_serp_urls(page: Page, query: str, result_limit: int, audit: AuditLog) -> list[str] | None:
    search_url = SERP_URL + quote_plus(query)
    try:
        response = page.goto(search_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
        if response is None or response.status >= 400:
            audit.event("serp_http_error", search_url, f"HTTP {response.status if response else 'none'}")
            return []
        page.wait_for_timeout(500)
        debug_snapshot(page, f"serp_{abs(hash(query))}")
        page_text = page.locator("body").inner_text(timeout=4_000)
    except PlaywrightError as exc:
        audit.event("serp_navigation_error", search_url, str(exc))
        return []

    if page_is_blocked(page_text):
        audit.event("serp_blocked_stop", search_url, "block or CAPTCHA marker detected; no retry")
        logging.warning("DuckDuckGo displayed a block marker. Stopping remaining queries.")
        return None

    candidates: list[str] = []
    raw_result_links = 0
    blocked_result_links = 0
    all_links = 0
    try:
        anchors = page.locator("a[href]")
        anchor_count = min(anchors.count(), 400)
        all_links = anchor_count
        for index in range(anchor_count):
            anchor = anchors.nth(index)
            classes = (anchor.get_attribute("class") or "").lower()
            href = anchor.get_attribute("href") or ""
            is_result = (
                "result__a" in classes
                or "result-link" in classes
                or anchor.get_attribute("data-testid") == "result-title-a"
            )
            if not is_result:
                continue
            raw_result_links += 1
            candidate = resolve_ddg_result(href)
            if not candidate:
                continue
            if is_disallowed_host(candidate):
                blocked_result_links += 1
                continue
            candidates.append(candidate)
    except PlaywrightError as exc:
        audit.event("serp_extract_error", search_url, str(exc))
        return []

    deduplicated = list(dict.fromkeys(candidates))[:result_limit]
    detail = (
        f"query={query}; all_links={all_links}; raw_result_links={raw_result_links}; "
        f"blocked_hosts={blocked_result_links}; allowed_urls={len(deduplicated)}"
    )
    audit.event("serp_urls_discovered", search_url, detail)
    logging.info("SERP diagnostics: %s", detail)
    if not deduplicated:
        logging.warning(
            "No allowed company URLs found. Debug files: %s. "
            "Check public_osint_audit.jsonl for the exact reason.",
            DEBUG_DIR or "debug disabled",
        )
    return deduplicated


def visit_company_page(page: Page, url: str, audit: AuditLog) -> bool:
    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
        if response is None:
            audit.event("navigation_no_response", url)
            return False
        if response.status >= 400:
            audit.event("company_http_error", url, f"HTTP {response.status}")
            return False
        page.wait_for_timeout(500)
        debug_snapshot(page, f"company_{abs(hash(url))}")
        return True
    except PlaywrightError as exc:
        audit.event("company_navigation_error", url, str(exc))
        return False


def discover_contact_pages(page: Page, target_url: str, limit: int) -> list[str]:
    links: list[str] = []
    try:
        anchors = page.locator("a[href]")
        for index in range(min(anchors.count(), 250)):
            anchor = anchors.nth(index)
            href = anchor.get_attribute("href") or ""
            label = (anchor.inner_text(timeout=1_500) or "").lower()
            candidate = normalize_url(urljoin(page.url, href))
            if not candidate or not same_host(candidate, target_url):
                continue
            if any(keyword in f"{label} {candidate.lower()}" for keyword in CONTACT_LINK_KEYWORDS):
                links.append(candidate)
    except PlaywrightError:
        return []
    return [item for item in list(dict.fromkeys(links)) if item != normalize_url(target_url)][:limit]


def extract_company_title(page: Page) -> str:
    for selector, attribute in (("h1", None), ('meta[property="og:title"]', "content"), ("title", None)):
        try:
            locator = page.locator(selector).first
            value = locator.get_attribute(attribute, timeout=2_000) if attribute else locator.inner_text(timeout=2_000)
            value = re.sub(r"\s+", " ", value or "").strip()
            if value:
                return value[:160]
        except PlaywrightError:
            continue
    return "Unknown company"


def extract_and_store(page: Page, target_url: str, query: str, audit: AuditLog, store: LeadStore) -> int:
    try:
        html = page.content()
        mailtos = page.locator('a[href^="mailto:"]').evaluate_all(
            "els => els.map(el => el.getAttribute('href').replace(/^mailto:/i, ''))"
        )
    except PlaywrightError as exc:
        audit.event("company_extract_error", page.url, str(exc))
        return 0

    if page_is_blocked(html):
        audit.event("company_blocked_stop_host", page.url, "block or CAPTCHA marker detected")
        return -1

    company_name = extract_company_title(page)
    saved = 0
    for email in extract_role_emails(html, mailtos):
        lead = PublicBusinessLead(
            target_url=target_url,
            company_name=company_name,
            verified_corporate_email=email,
            source_page=normalize_url(page.url),
            search_query=query,
            collected_at_utc=utc_now(),
        )
        if store.save_if_new(lead):
            saved += 1
            audit.event("corporate_email_saved", page.url, email)
            logging.info("saved %s from %s", email, page.url)
    return saved


def research_company(
    page: Page,
    company_url: str,
    query: str,
    robots: RobotsPolicy,
    audit: AuditLog,
    store: LeadStore,
    max_contact_pages: int,
) -> int:
    if is_disallowed_host(company_url):
        audit.event("platform_or_directory_skip", company_url, "disallowed host")
        return 0
    if not robots.allows(company_url):
        return 0

    polite_company_delay()
    if not visit_company_page(page, company_url, audit):
        return 0
    saved = extract_and_store(page, company_url, query, audit, store)
    if saved < 0:
        return 0

    for contact_url in discover_contact_pages(page, company_url, max_contact_pages):
        if not robots.allows(contact_url):
            continue
        polite_company_delay()
        if not visit_company_page(page, contact_url, audit):
            continue
        found = extract_and_store(page, company_url, query, audit, store)
        if found < 0:
            break
        saved += found
    return saved


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Public OSINT research from rate-limited DuckDuckGo queries")
    parser.add_argument("--queries", default="market_research_queries.csv", help="CSV containing one query column")
    parser.add_argument("--output", default="public_business_leads.csv", help="Progressive output CSV")
    parser.add_argument("--database", default="public_osint_state.sqlite3", help="SQLite deduplication state")
    parser.add_argument("--audit-log", default="public_osint_audit.jsonl", help="JSONL audit log")
    parser.add_argument("--results-per-query", type=int, default=10, choices=range(1, 16), metavar="1-15")
    parser.add_argument("--max-contact-pages-per-site", type=int, default=MAX_CONTACT_PAGES_PER_SITE, choices=range(0, 4), metavar="0-3")
    parser.add_argument("--max-queries", type=int, default=0, choices=range(0, 101), metavar="0-100", help="Limit queries for diagnostics; 0 means all")
    parser.add_argument("--debug-dir", default="", help="Save SERP/company HTML and screenshots to this directory")
    parser.add_argument("--fast", action="store_true", help="Short diagnostic delays; use only for a local test, not production collection")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING"))
    parser.add_argument("--headed", action="store_true", help="Show browser for observation; does not alter behavior")
    return parser.parse_args()


def main() -> int:
    global DEBUG_DIR, FAST_MODE
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(message)s")
    DEBUG_DIR = Path(args.debug_dir).expanduser().resolve() if args.debug_dir else None
    FAST_MODE = bool(args.fast)
    query_path = Path(args.queries).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()
    database_path = Path(args.database).expanduser().resolve()
    audit_path = Path(args.audit_log).expanduser().resolve()

    try:
        queries = load_queries(query_path)
    except (FileNotFoundError, ValueError) as exc:
        logging.error("%s", exc)
        return 2
    if not queries:
        logging.error("No queries found in %s", query_path)
        return 2
    if args.max_queries:
        queries = queries[:args.max_queries]

    audit = AuditLog(audit_path)
    store = LeadStore(database_path, output_path)
    robots = RobotsPolicy(audit)
    saved_total = 0
    audit.event("run_started", str(query_path), f"queries={len(queries)}")

    try:
        with sync_playwright() as playwright:
            browser: Browser = playwright.chromium.launch(headless=not args.headed)
            context = browser.new_context(user_agent=USER_AGENT, locale="en-US")
            context.set_default_timeout(PAGE_TIMEOUT_MS)
            page = context.new_page()

            for query_index, query in enumerate(queries, start=1):
                logging.info("query %d/%d: %s", query_index, len(queries), query)
                urls = discover_serp_urls(page, query, args.results_per_query, audit)
                if urls is None:
                    break
                for url_index, company_url in enumerate(urls, start=1):
                    logging.info("company %d/%d: %s", url_index, len(urls), company_url)
                    saved_total += research_company(
                        page=page,
                        company_url=company_url,
                        query=query,
                        robots=robots,
                        audit=audit,
                        store=store,
                        max_contact_pages=args.max_contact_pages_per_site,
                    )
                if query_index < len(queries):
                    logging.info("waiting before next query")
                    query_delay()
            context.close()
            browser.close()
    except PlaywrightError as exc:
        logging.error("Playwright error: %s", exc)
        audit.event("playwright_fatal", "", str(exc))
        return 3
    finally:
        store.close()

    audit.event("run_completed", str(output_path), f"new_corporate_emails={saved_total}")
    logging.info("completed; new corporate emails saved: %d", saved_total)
    logging.info("output: %s", output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
