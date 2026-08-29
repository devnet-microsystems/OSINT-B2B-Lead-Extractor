# 🕵️‍♂️ OSINT B2B Lead Extractor

A privacy-first, highly controlled Python OSINT tool to extract corporate emails from public company websites using Playwright and DuckDuckGo Lite.

**Built by Antonio Michelotti** — Lead Architect at [DEV-NET Microsystems](https://devnet-microsystems.com/). 

> 🛡️ **Why did I build this?**
> I originally developed this internal OSINT script to find and connect with high-end Web Agencies that needed enterprise-grade security. We use it to reach agencies that need our flagship product: **[Sovereign AI Overseer](https://devnet-microsystems.com/auth/)** — the ultimate Zero-Trust security plugin that replaces WordPress passwords with native WebAuthn (Face ID / Touch ID) and an autonomous Gemini 1.5 Pro AI Sentinel. 
> I am now making the extraction engine open-source for the community.

## 🚀 Features

Unlike aggressive scraping bots, this tool is designed for ethical B2B market research:
- **Respects `robots.txt`**: Strictly adheres to crawling policies.
- **Anti-Bot Bypass (DDG Lite)**: Uses DuckDuckGo's Lite API via native Python POST requests to bypass Cloudflare and CAPTCHAs, getting perfectly clean international results.
- **Strict Business Emails Only**: Extracts any valid corporate email found on the website (including direct contacts like `ceo@` or `founders@`), but strictly filters out any personal or generic webmail domains (`gmail.com`, `yahoo.com`, `protonmail.com`, etc.) to ensure high-quality B2B leads.
- **Auto-Deduplication**: Automatically deduplicates URLs and handles redirects to ensure efficient crawling.

## 🛠️ Installation (macOS / Linux)

Requires Python 3 and Playwright.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

## 💻 Usage

### 1. Market Research via DuckDuckGo Lite
Create a `market_research_queries.csv` with a `query` column (e.g., "Top Web Agencies London").

```bash
python public_osint_market_research.py --queries market_research_queries.csv --output public_leads.csv
```

### 2. Direct Website Extraction
If you already have a list of target URLs, create a `seed_sites.csv` (columns: `target_url`, `company_hint`).

```bash
python public_business_lead_collector.py --input seed_sites.csv --output b2b_leads.csv
```

## ⚠️ Disclaimer
This tool is for ethical Open Source Intelligence (OSINT) and B2B market research only. Users are responsible for complying with all local privacy laws (GDPR, CAN-SPAM, etc.) regarding the collection and subsequent use of public business data.

---
**Author:** Antonio Michelotti  
🔗 **Connect with me / Secure your infrastructure:** [devnet-microsystems.com](https://devnet-microsystems.com/)
