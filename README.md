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

## 🛠️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/yourusername/digital-footprint-analyzer.git
cd digital-footprint-analyzer

2️⃣ Create a Virtual Environment
python -m venv venv
venv\Scripts\activate   # For Windows
# OR
source venv/bin/activate   # For Linux/Mac

3️⃣ Install Dependencies
pip install -r requirements.txt

4️⃣ (Optional) Install snscrape for Twitter/Reddit Lookup
pip install snscrape

⚙️ Configuration

All API keys and tokens are stored in the config.py file.

CONFIG = {
    "HIBP_API_KEY": "your_key_here",
    "GITHUB_TOKEN": "your_token_here",
    "SHODAN_API_KEY": "your_key_here",
    "HUNTER_API_KEY": "your_key_here",
    "CLEARBIT_KEY": "your_key_here",
    "FULLCONTACT_KEY": "your_key_here",
    "URLSCAN_API_KEY": "your_key_here",
    "IPINFO_TOKEN": "your_key_here",
    "DARKWEB_KEY": "your_key_here"
}


💡 Tip: You can leave keys blank (None) for modules you’re not using — the analyzer will skip them automatically.

🔑 Free API Key Sources
Service	Description	Free Plan	Signup URL
🟩 XposedOrNot API	Email breach lookup	✅ Free	https://xposedornot.com/developer/

🟩 IntelX.io	Dark web data search	✅ Free (limited)	https://intelx.io/signup

🟩 Shodan.io	Device exposure data	✅ Free (limited queries)	https://account.shodan.io/register

🟩 Hunter.io	Email discovery	✅ Free (50 req/month)	https://hunter.io/api

🟩 IPinfo.io	IP and geolocation info	✅ Free	https://ipinfo.io/signup

🟩 HaveIBeenPwned	Breach database	✅ Free for personal	https://haveibeenpwned.com/API/v3
🧪 Usage
Analyze an Email
python main.py "nirajkumar11288@gmail.com"

Analyze a Domain
python main.py "devsupport.co.in"

Analyze a Username
python main.py "john_doe"

📁 Output Files

Reports are automatically saved in the outputs/ directory with the target name and timestamp:

outputs/report_nirajkumar11288_at_gmail_com_2025-11-08_20-25-10.json
outputs/summary_nirajkumar11288_at_gmail_com_2025-11-08_20-25-10.csv

🧩 Project Structure
digital-footprint-analyzer/
│
├── core/                # Main logic (network, email, domain)
├── output/              # Formatters and output saving tools
├── modules/             # API integrations
├── config.py            # API keys & configuration
├── main.py              # Entry point
├── requirements.txt     # Dependencies
└── README.md            # Documentation

🧠 Example Insights
Type	Example Finding	Source
Email Breach	Found in 3 breaches	XposedOrNot
Domain	SSL cert expires soon	Network Tools
GitHub	2 code leaks found	GitHub Search
Dark Web	1 match found	IntelX.io
🖼️ Screenshots (Optional)

Add terminal output or report screenshots here to showcase results.

💡 Future Enhancements

Add LinkedIn / Facebook OSINT module

Integrate VirusTotal domain & IP reputation

HTML report generation

Auto-risk visual dashboards

🤝 Contributing

Contributions, issues, and feature requests are welcome!
Feel free to fork this repo and submit a pull request.

git checkout -b feature/awesome-feature
git commit -m "Add new awesome feature"
git push origin feature/awesome-feature

📜 License

This project is licensed under the MIT License — free to use and modify with attribution.

🧑‍💻 Author

Niraj Kumar
📧 nirajkumar11288@gmail.com


⚠️ Disclaimer: This tool is for educational and cybersecurity awareness purposes only.
Do not use it for illegal activities or unauthorized data collection.

---

Would you like me to add **badges** (like Python version, License, Stars, etc.) and **emoji-based section headers** to make it even more eye-catching for GitHu
