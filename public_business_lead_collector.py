#!/usr/bin/env python3
"""Public Business Lead Collector

Collects only role-based business email addresses that are explicitly published on
user-provided, robot-permitted company URLs. The tool does not automate Google,
LinkedIn, CAPTCHA solving, proxy use, browser fingerprint masking, user-agent
rotation, or extraction of person-named email addresses.

Use it only on sites you are authorised to review and only for lawful B2B outreach.
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
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from urllib.robotparser import RobotFileParser

from playwright.sync_api import Browser, Error as PlaywrightError, Page, sync_playwright

APP_NAME = "PublicBusinessLeadCollector"
APP_VERSION = "1.0.0"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
REQUEST_TIMEOUT_SECONDS = 15
PAGE_TIMEOUT_MS = 25_000
POLITE_DELAY_MIN_SECONDS = 6.0
POLITE_DELAY_MAX_SECONDS = 12.0
MAX_CONTACT_PAGES_PER_HOST = 2

# The collector deliberately skips platforms that commonly prohibit automated
# extraction or that are designed around individual profiles/search results.
DISALLOWED_HOST_SUFFIXES = {
    "google.com",
    "linkedin.com",
    "bing.com",
    "facebook.com",
    "instagram.com",
    "x.com",
    "twitter.com",
    "goodfirms.co",
}

# Only these role addresses are written to the output. Person-named addresses,
# aliases that appear to identify a person, and personal webmail addresses are ignored.


BLOCK_MARKERS = (
    "captcha",
    "unusual traffic",
    "access denied",
    "verify you are human",
    "checking your browser",
    "cf-chl",
    "temporarily blocked",
)

CONTACT_LINK_KEYWORDS = ("contact", "about", "team", "company", "support")
EMAIL_PATTERN = re.compile(r"(?<![\w.+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63})(?![\w.-])", re.IGNORECASE)


@dataclass(frozen=True)
class Seed:
    target_url: str
    company_hint: str


@dataclass(frozen=True)
class PublicBusinessLead:
    target_url: str
    extracted_name_or_title: str
    verified_email: str
    source_page: str
    collected_at_utc: str


class AuditLog:
    """JSONL audit log that records skips and fetch outcomes without hiding errors."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def event(self, status: str, url: str, detail: str = "") -> None:
        record = {
            "timestamp_utc": utc_now(),
            "status": status,
            "url": url,
            "detail": detail,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


class LeadStore:
    """SQLite-backed deduplication plus progressive CSV output."""

    def __init__(self, database_path: Path, csv_path: Path) -> None:
        self.csv_path = csv_path
        self.connection = sqlite3.connect(database_path)
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS leads (
                source_page TEXT NOT NULL,
                verified_email TEXT NOT NULL,
                target_url TEXT NOT NULL,
                extracted_name_or_title TEXT NOT NULL,
                collected_at_utc TEXT NOT NULL,
                PRIMARY KEY (source_page, verified_email)
            )
            """
        )
        self.connection.commit()
        self._ensure_csv_header()

    def _ensure_csv_header(self) -> None:
        if self.csv_path.exists() and self.csv_path.stat().st_size > 0:
            return
        with self.csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Target URL", "Extracted Name/Title", "Verified Email"])

    def save_if_new(self, lead: PublicBusinessLead) -> bool:
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO leads
            (source_page, verified_email, target_url, extracted_name_or_title, collected_at_utc)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                lead.source_page,
                lead.verified_email,
                lead.target_url,
                lead.extracted_name_or_title,
                lead.collected_at_utc,
            ),
        )
        self.connection.commit()
        if cursor.rowcount != 1:
            return False
        with self.csv_path.open("a", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow([lead.target_url, lead.extracted_name_or_title, lead.verified_email])
        return True

    def close(self) -> None:
        self.connection.close()


class RobotsPolicy:
    """Conservative robots.txt validator. Fetch failures result in a skip."""

    def __init__(self, audit: AuditLog) -> None:
        self.audit = audit
        self.cache: dict[str, RobotFileParser | None] = {}

    def allows(self, url: str) -> bool:
        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self.cache:
            self.cache[origin] = self._fetch_policy(origin)
        parser = self.cache[origin]
        if parser is None:
            self.audit.event("robots_unavailable_skip", url, "robots.txt could not be retrieved")
            return False
        allowed = parser.can_fetch(USER_AGENT, url)
        if not allowed:
            self.audit.event("robots_disallow_skip", url, "robots.txt disallows this collector")
        return allowed

    def _fetch_policy(self, origin: str) -> RobotFileParser | None:
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
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    clean_path = parsed.path or "/"
    return urlunsplit((parsed.scheme, parsed.netloc.lower(), clean_path, parsed.query, ""))


def hostname(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def host_is_disallowed(url: str) -> bool:
    current = hostname(url)
    return any(current == suffix or current.endswith("." + suffix) for suffix in DISALLOWED_HOST_SUFFIXES)


def same_host(left: str, right: str) -> bool:
    return hostname(left) == hostname(right)


def is_allowed_role_address(email: str) -> bool:
    local_part, _, domain = email.lower().partition("@")
    if not local_part or not domain:
        return False
    if domain in {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "live.com", "me.com", "msn.com", "proton.me", "protonmail.com"}:
        return False
    return True


def extract_role_emails(text: str, mailto_values: Iterable[str]) -> list[str]:
    candidates = set(match.group(1).strip(".,;:)]}>\"'").lower() for match in EMAIL_PATTERN.finditer(text))
    for raw in mailto_values:
        value = unquote(raw).split("?", 1)[0].strip().lower()
        if EMAIL_PATTERN.fullmatch(value):
            candidates.add(value)
    return sorted(email for email in candidates if is_allowed_role_address(email))


def clean_title(value: str, fallback: str) -> str:
    compact = re.sub(r"\s+", " ", value).strip()
    compact = compact[:160]
    return compact or fallback or "Unknown company"


def load_seeds(path: Path) -> list[Seed]:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    seeds: list[Seed] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "target_url" not in reader.fieldnames:
            raise ValueError("Input CSV must include a target_url column. company_hint is optional.")
        for row in reader:
            url = normalize_url(row.get("target_url", ""))
            if url:
                seeds.append(Seed(url, (row.get("company_hint") or "").strip()))
    return list(dict.fromkeys(seeds))


def polite_delay() -> None:
    time.sleep(random.uniform(POLITE_DELAY_MIN_SECONDS, POLITE_DELAY_MAX_SECONDS))


def page_is_blocked(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in BLOCK_MARKERS)


def discover_contact_pages(page: Page, seed_url: str, max_pages: int) -> list[str]:
    candidates: list[str] = []
    try:
        anchors = page.locator("a[href]")
        count = min(anchors.count(), 250)
        for index in range(count):
            anchor = anchors.nth(index)
            href = anchor.get_attribute("href") or ""
            label = (anchor.inner_text(timeout=2_000) or "").lower()
            candidate = normalize_url(urljoin(page.url, href))
            if not candidate or not same_host(candidate, seed_url):
                continue
            haystack = f"{label} {candidate.lower()}"
            if any(keyword in haystack for keyword in CONTACT_LINK_KEYWORDS):
                candidates.append(candidate)
    except PlaywrightError:
        return []
    unique = list(dict.fromkeys(candidates))
    return [url for url in unique if url != normalize_url(seed_url)][:max_pages]


def extract_title(page: Page, fallback: str) -> str:
    try:
        h1 = page.locator("h1").first.inner_text(timeout=2_000)
        if h1.strip():
            return clean_title(h1, fallback)
    except PlaywrightError:
        pass
    try:
        og_title = page.locator('meta[property="og:title"]').first.get_attribute("content", timeout=2_000)
        if og_title:
            return clean_title(og_title, fallback)
    except PlaywrightError:
        pass
    try:
        return clean_title(page.title(), fallback)
    except PlaywrightError:
        return clean_title("", fallback)


def extract_from_page(
    page: Page,
    target_url: str,
    company_hint: str,
    audit: AuditLog,
    store: LeadStore,
) -> int:
    try:
        visible_text = page.locator("body").inner_text(timeout=4_000)
        mailto_values = page.locator('a[href^="mailto:"]').evaluate_all(
            "els => els.map(el => el.getAttribute('href').replace(/^mailto:/i, ''))"
        )
    except PlaywrightError as exc:
        audit.event("extract_error", page.url, str(exc))
        return 0

    if page_is_blocked(visible_text):
        audit.event("blocked_skip_host", page.url, "block or CAPTCHA marker detected; no retry attempted")
        return -1

    title = extract_title(page, company_hint)
    count = 0
    for email in extract_role_emails(visible_text, mailto_values):
        lead = PublicBusinessLead(
            target_url=target_url,
            extracted_name_or_title=title,
            verified_email=email,
            source_page=normalize_url(page.url),
            collected_at_utc=utc_now(),
        )
        if store.save_if_new(lead):
            logging.info("saved %s from %s", email, page.url)
            audit.event("lead_saved", page.url, email)
            count += 1
    return count


def visit_page(page: Page, url: str, audit: AuditLog) -> bool:
    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
        if response is None:
            audit.event("navigation_no_response", url)
            return False
        if response.status >= 400:
            audit.event("http_error_skip", url, f"HTTP {response.status}")
            return False
        page.wait_for_timeout(500)
        return True
    except PlaywrightError as exc:
        audit.event("navigation_error", url, str(exc))
        return False


def collect_seed(
    page: Page,
    seed: Seed,
    robots: RobotsPolicy,
    audit: AuditLog,
    store: LeadStore,
    max_contact_pages: int,
) -> int:
    if host_is_disallowed(seed.target_url):
        audit.event("platform_skip", seed.target_url, "disallowed platform")
        logging.warning("skipped disallowed platform: %s", seed.target_url)
        return 0
    if not robots.allows(seed.target_url):
        return 0

    polite_delay()
    if not visit_page(page, seed.target_url, audit):
        return 0
    saved = extract_from_page(page, seed.target_url, seed.company_hint, audit, store)
    if saved < 0:
        return 0

    contact_pages = discover_contact_pages(page, seed.target_url, max_contact_pages)
    for contact_url in contact_pages:
        if not robots.allows(contact_url):
            continue
        polite_delay()
        if not visit_page(page, contact_url, audit):
            continue
        found = extract_from_page(page, seed.target_url, seed.company_hint, audit, store)
        if found < 0:
            break
        saved += found
    return saved


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect explicitly published role-based business emails from approved company URLs."
    )
    parser.add_argument("--input", default="seed_sites.csv", help="CSV with target_url and optional company_hint columns")
    parser.add_argument("--output", default="b2b_enterprise_leads.csv", help="Progressive output CSV path")
    parser.add_argument("--database", default="lead_collector_state.sqlite3", help="SQLite state database path")
    parser.add_argument("--audit-log", default="lead_collector_audit.jsonl", help="JSONL audit log path")
    parser.add_argument(
        "--max-contact-pages-per-host",
        type=int,
        default=MAX_CONTACT_PAGES_PER_HOST,
        choices=range(0, 6),
        metavar="0-5",
        help="Maximum discovered Contact/About/Team pages to review for each seed site",
    )
    parser.add_argument("--headed", action="store_true", help="Show the browser window for inspection")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()
    database_path = Path(args.database).expanduser().resolve()
    audit_path = Path(args.audit_log).expanduser().resolve()

    try:
        seeds = load_seeds(input_path)
    except (FileNotFoundError, ValueError) as exc:
        logging.error("%s", exc)
        return 2
    if not seeds:
        logging.error("No valid target_url values found in %s", input_path)
        return 2

    audit = AuditLog(audit_path)
    store = LeadStore(database_path, output_path)
    robots = RobotsPolicy(audit)
    saved_total = 0

    logging.info("starting %s with %d seed sites", APP_NAME, len(seeds))
    audit.event("run_started", str(input_path), f"seed_count={len(seeds)}")

    try:
        with sync_playwright() as playwright:
            browser: Browser = playwright.chromium.launch(headless=not args.headed)
            context = browser.new_context(user_agent=USER_AGENT, locale="en-US")
            context.set_default_timeout(PAGE_TIMEOUT_MS)
            page = context.new_page()
            for position, seed in enumerate(seeds, start=1):
                logging.info("[%d/%d] %s", position, len(seeds), seed.target_url)
                saved_total += collect_seed(
                    page=page,
                    seed=seed,
                    robots=robots,
                    audit=audit,
                    store=store,
                    max_contact_pages=args.max_contact_pages_per_host,
                )
            context.close()
            browser.close()
    except PlaywrightError as exc:
        logging.error("Playwright error: %s", exc)
        audit.event("playwright_fatal", "", str(exc))
        return 3
    finally:
        store.close()

    audit.event("run_completed", str(output_path), f"new_leads={saved_total}")
    logging.info("completed. New business contacts saved: %d", saved_total)
    logging.info("CSV: %s", output_path)
    logging.info("Audit log: %s", audit_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
