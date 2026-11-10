# PHISHINTEL AI — Architecture and Data Flow

## High-level flow

```text
Raw email source
      |
      v
Email parser
      |
      +--> Rule-based detection
      +--> Header analyzer
      +--> URL / DNS analyzer
      +--> VirusTotal lookup (optional external service)
      +--> Local Ollama AI (optional local service)
                    |
                    v
             Evidence correlator
                    |
          +---------+----------+
          |         |          |
          v         v          v
      Dashboard   SQLite     PDF report
                  history
                    |
          +---------+----------+
          |         |          |
          v         v          v
       Case      IOC CSV    History review
    management    export
```

## Components

- `modules/email_parser.py`: extracts structured fields and indicators from a raw email.
- `modules/detection_engine.py`: applies deterministic keyword and URL heuristics.
- `modules/header_analyzer.py`: compares sender-related headers and parses reported authentication results.
- `modules/url_analyzer.py`: inspects URL structure and performs DNS lookups; it does not request URL pages.
- `modules/virustotal_analyzer.py`: retrieves existing VirusTotal reports using API v3.
- `modules/ai_analyzer.py`: calls the local Ollama HTTP API for advisory analysis.
- `modules/evidence_correlator.py`: consolidates independent signal categories into an explainable assessment.
- `reports/report_generator.py`: renders a PDF investigation report.
- `database/investigations.db`: stores raw email, structured results and case-management fields.
- `app.py`: Streamlit interface and orchestration layer.

## Trust boundaries

- User-supplied email is untrusted input.
- Pasted `Authentication-Results` headers are not authoritative evidence.
- VirusTotal is an external disclosure boundary.
- Ollama is local when bound to localhost; do not expose its API to untrusted networks.
- PDF/CSV exports may contain sensitive email content and IOCs.
- This application does not execute attachments or open extracted URLs.

## Assessment semantics

Risk scores are heuristic prioritization signals. Evidence coverage is not a statistical confidence probability. AI output and external reputation are supporting evidence and require analyst validation.
