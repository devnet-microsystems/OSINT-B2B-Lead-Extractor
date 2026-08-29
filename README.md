# 🕵️‍♂️ OSINT B2B Lead Extractor

A privacy-first, highly controlled Python OSINT tool to extract role-based corporate emails (e.g., `sales@`, `hello@`, `security@`) from public company websites using Playwright.

**Built by Antonio Michelotti** — Lead Architect at [DEV-NET Microsystems](https://devnet-microsystems.com/). 

> 🛡️ **Why did I build this?**
> I originally developed this internal OSINT script to find and connect with high-end Web Agencies that needed enterprise-grade security. We use it to reach agencies that need our flagship product: **[Sovereign AI Overseer](https://devnet-microsystems.com/auth/)** — the ultimate Zero-Trust security plugin that replaces WordPress passwords with native WebAuthn (Face ID / Touch ID) and an autonomous Gemini 1.5 Pro AI Sentinel. 
> I am now making the extraction engine open-source for the community.

## 🚀 Features

Unlike aggressive scraping bots, this tool is designed for ethical B2B market research:
- **Respects `robots.txt`**: Strictly adheres to crawling policies.
- **No CAPTCHA Bypassing**: If a site blocks the request, it gracefully skips it.
- **Role-Based Only**: Extracts ONLY corporate role emails (`info@`, `partners@`, etc.). It automatically filters out personal emails and generic webmail domains (gmail, yahoo, etc.).
- **DuckDuckGo HTML SERP**: Uses the lightweight HTML version of DuckDuckGo for querying without triggering aggressive rate limits.

## 🛠️ Installation (macOS / Linux)

Requires Python 3 and Playwright.

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    playwright install chromium

## 💻 Usage

### 1. Market Research via DuckDuckGo
Create a `market_research_queries.csv` with a `query` column (e.g., "Top Web Agencies London").
    
    python public_osint_market_research.py --queries market_research_queries.csv --output public_leads.csv

### 2. Direct Website Extraction
If you already have a list of target URLs, create a `seed_sites.csv` (columns: `target_url`, `company_hint`).
    
    python public_business_lead_collector.py --input seed_sites.csv --output b2b_leads.csv

## ⚠️ Disclaimer
This tool is for ethical Open Source Intelligence (OSINT) and B2B market research only. Users are responsible for complying with all local privacy laws (GDPR, CAN-SPAM, etc.) regarding the collection and subsequent use of public business data.

---
**Author:** Antonio Michelotti  
🔗 **Connect with me / Secure your infrastructure:** [devnet-microsystems.com](https://devnet-microsystems.com/)
