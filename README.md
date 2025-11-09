# 🌐 Digital Footprint Analyzer

> **Discover your online exposure — analyze emails, domains, or usernames to uncover publicly available data across the web, GitHub, dark web, and more.**

---

## 🚀 Overview

**Digital Footprint Analyzer** is a powerful open-source tool designed to **investigate the digital presence** of an individual or organization.  
It collects and correlates publicly available data from multiple sources — including **WHOIS**, **GitHub**, **Shodan**, **Hunter.io**, **HaveIBeenPwned**, and **Dark Web** — to help you understand your **online visibility and potential data leaks**.

---

## ✨ Features

- 🔍 **Email Intelligence**
  - Finds breaches and leaks from multiple sources (HIBP, XposedOrNot)
  - Searches GitHub commits, issues, and code leaks
  - Checks exposure on the dark web (IntelX API)

- 🌐 **Domain Intelligence**
  - Fetches WHOIS records and DNS details
  - SSL/TLS certificate info (validity, issuer, dates)
  - Checks domain reputation and IP information

- 💾 **Username & Social Scan**
  - Detects public profiles on social networks
  - Searches posts using `snscrape` and OSINT APIs

- 🧠 **Risk Scoring**
  - Automatic risk analysis based on the findings
  - Generates a clean, structured **JSON** and **CSV** report

- 🧰 **Modular Architecture**
  - Add or remove modules easily (e.g., GitHub, Shodan, Hunter)
  - Configurable API keys in one place

---

## 🛠️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/yourusername/digital-footprint-analyzer.git
cd digital-footprint-analyzer
