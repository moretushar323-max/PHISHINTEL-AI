# Security and Operations Checklist

- Keep `.env` private; never commit it.
- Do not upload the SQLite database to a public repository if it contains real email.
- Use synthetic or explicitly authorized email samples.
- Treat URL/domain submissions to VirusTotal as external disclosure.
- Do not click/open suspicious URLs.
- Keep Ollama bound to localhost for a single-machine lab.
- Back up `database/investigations.db` before updates.
- Use synthetic data in screenshots and demonstrations.
- Do not describe heuristic risk scores as model confidence or detection accuracy.
- This project is a portfolio lab, not a production security control.
