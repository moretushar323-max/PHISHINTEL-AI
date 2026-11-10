# PHISHINTEL AI

**AI-Powered Phishing Intelligence & Investigation Platform**

PHISHINTEL AI is a local, AI-assisted phishing email investigation dashboard designed as a SOC Analyst learning and portfolio project.

## Features

- Raw email parsing: sender, recipient, subject, headers, body, URLs, domains and IP addresses.
- Rule-based phishing indicators: urgency, credential requests, account verification language, HTTP links and IP-based URL hosts.
- Header review: From / Reply-To / Return-Path comparisons and reported SPF, DKIM and DMARC results.
- URL and DNS indicator analysis. The application does **not** browse to suspicious URLs.
- Optional VirusTotal API v3 lookups for existing URL/domain reports.
- Local Ollama-assisted AI assessment (default model: `llama3.2:1b`).
- Evidence correlation with explainable observations and limitations.
- PDF investigation reports.
- SQLite investigation history.
- SOC case management: status, priority and analyst notes.
- IOC inventory with CSV export.
- Synthetic detection validation scenarios.
- Threat analytics and performance timings.

## Requirements

- Ubuntu 22.04+ recommended.
- Python 3.10 or newer.
- Internet access for dependency installation and optional VirusTotal queries.
- Ollama installed locally for local AI analysis.
- VirusTotal API key is optional.

## Install on Ubuntu

Extract this ZIP into your home directory. The extracted folder is `PhishIntelAI`. Then run:

```bash
cd ~/PhishIntelAI
chmod +x install.sh run.sh
./install.sh
```

Create/configure `.env` if you want VirusTotal integration:

```bash
cp .env.example .env
nano .env
```

Add your key after `VIRUSTOTAL_API_KEY=`. Never share `.env` or upload it to GitHub.

## Local AI setup

Install Ollama using its official installation instructions, then run:

```bash
ollama pull llama3.2:1b
ollama serve
```

If Ollama is already running as a service, do not start a second instance.

## Start PHISHINTEL AI

```bash
cd ~/PhishIntelAI
./run.sh
```

Open `http://localhost:8501`.

## Run tests

```bash
cd ~/PhishIntelAI
source .venv/bin/activate
python -m unittest discover -s tests -v
```

## Suggested SOC workflow

1. Analyze a synthetic or authorized raw email source.
2. Review the correlated verdict, risk score and evidence.
3. Validate sender and authentication details using trusted mail-system logs where available.
4. Review URLs and DNS indicators without opening suspicious links.
5. Treat VirusTotal and AI as supporting context, not definitive proof.
6. Download the PDF report.
7. Review the saved record in Investigation History.
8. Track actions, priority, status and notes in SOC Case Management.
9. Review extracted indicators in IOC Inventory and export CSV when needed.
10. Use Detection Lab to run synthetic examples.

## Data and privacy

- Investigation records are stored locally in `database/investigations.db`.
- The database may contain raw email text and analysis results. Treat it as sensitive.
- Back up the database before replacing or moving the project.
- VirusTotal lookups disclose submitted indicators to VirusTotal. Do not submit confidential URLs/domains without authorization.
- Local AI sends email text to the local Ollama service on your machine.
- Do not use real customer, employee or confidential corporate email in a personal lab without authorization.

## Important limitations

- This is an educational MVP, not a production secure email gateway or validated phishing classifier.
- Rule scores are heuristic signals, not calibrated probabilities.
- Pasted email headers can be forged.
- DNS resolution does not establish reputation or maliciousness.
- Zero VirusTotal detections do not prove an indicator is safe.
- AI output may be incomplete or incorrect and must be checked against evidence.
- Synthetic detection scenarios do not establish real-world precision, recall or false-positive rates.
- Attachments are not extracted, detonated or executed.

## Project structure

```text
PhishIntelAI/
├── app.py
├── modules/
├── reports/
├── database/
├── tests/
├── samples/
├── requirements.txt
├── .env.example
└── README.md
```

## Portfolio description

**PHISHINTEL AI — AI-Powered Phishing Intelligence & Investigation Platform**

Built a Python and Streamlit-based SOC investigation tool that parses suspicious email sources, identifies rule-based phishing indicators, reviews email authentication headers, analyzes URLs and DNS indicators, enriches IOCs with VirusTotal, and uses a local Ollama model for supporting analysis. Implemented evidence correlation, SQLite investigation history, SOC case tracking, IOC CSV export and PDF incident reports.

## Portfolio screenshots

Capture: dashboard, correlated verdict, headers, URL/DNS analysis, VirusTotal, AI assessment, investigation history, case management, IOC inventory, PDF report and synthetic Detection Lab. Hide API keys and personal/confidential data.
