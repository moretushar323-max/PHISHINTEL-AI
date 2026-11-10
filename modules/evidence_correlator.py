import re


def _text(value):
    """Convert different finding formats into searchable text."""
    if isinstance(value, dict):
        return " ".join(
            str(value.get(key, ""))
            for key in ("description", "message", "finding", "severity", "title")
        ).lower()
    return str(value or "").lower()


def _findings(items):
    if not isinstance(items, list):
        return [_text(items)] if items else []
    return [_text(item) for item in items]


def _add_signal(signals, category, title, description, points, severity, source):
    signals.append({
        "category": category,
        "title": title,
        "description": description,
        "points": points,
        "severity": severity,
        "source": source,
    })


def correlate_evidence(parsed, rules, headers, urls, vt, ai):
    """
    Correlate independent evidence sources into a transparent assessment.

    This is a heuristic decision-support engine, not a definitive
    determination that an email is malicious.
    """

    signals = []

    # --------------------------------------------------
    # 1. CONTENT / RULE-BASED EVIDENCE
    # --------------------------------------------------

    rule_findings = _findings(rules.get("findings", []))
    email_body = str(parsed.get("body", "")).lower()
    email_subject = str(parsed.get("subject", "")).lower()
    content = email_body + " " + email_subject

    credential_patterns = [
        "enter your password",
        "verify your password",
        "login credentials",
        "share your password",
        "enter your otp",
        "verify your otp",
        "credential harvesting",
    ]

    urgency_patterns = [
        "urgent",
        "immediately",
        "act now",
        "account suspended",
        "will be suspended",
        "within 24 hours",
        "limited time",
    ]

    if any(pattern in content for pattern in credential_patterns):
        _add_signal(
            signals, "content", "Credential request detected",
            "The email contains language requesting passwords, OTPs or login credentials.",
            20, "High", "Email content"
        )

    elif any("credential" in finding or "password" in finding or "otp" in finding
             for finding in rule_findings):
        _add_signal(
            signals, "content", "Credential-related indicator",
            "The rule engine identified credential-related language.",
            15, "High", "Rule-based detection"
        )

    if any(pattern in content for pattern in urgency_patterns):
        _add_signal(
            signals, "urgency", "Urgency or pressure detected",
            "The email uses urgency or account suspension language to influence the recipient.",
            8, "Medium", "Email content"
        )

    if any("verification" in finding or "verify your account" in finding
           for finding in rule_findings):
        _add_signal(
            signals, "account_verification", "Account verification language",
            "The rule engine detected account verification language.",
            10, "Medium", "Rule-based detection"
        )

    # --------------------------------------------------
    # 2. EMAIL HEADER EVIDENCE
    # --------------------------------------------------

    header_findings = _findings(headers.get("findings", []))

    mismatch_found = any(
        ("mismatch" in finding and ("reply" in finding or "return-path" in finding))
        for finding in header_findings
    )

    if mismatch_found:
        _add_signal(
            signals, "identity", "Email identity mismatch",
            "The supplied sender-related headers contain a domain mismatch.",
            15, "Medium", "Header analysis"
        )

    auth = headers.get("authentication_results", {}) or {}

    auth_failures = []
    for protocol in ("spf", "dkim", "dmarc"):
        status = str(auth.get(protocol, "")).lower().strip()

        if status == "fail":
            auth_failures.append(protocol.upper())

    if auth_failures:
        _add_signal(
            signals, "authentication", "Email authentication failure",
            "Reported authentication failures: " + ", ".join(auth_failures) +
            ". These results came from the supplied headers and are not independently verified.",
            15, "High", "Supplied Authentication-Results header"
        )

    # --------------------------------------------------
    # 3. URL ANALYSIS EVIDENCE
    # --------------------------------------------------

    url_findings = []

    for result in urls or []:
        if isinstance(result, dict):
            url_findings.extend(_findings(result.get("findings", [])))

    all_url_text = " ".join(url_findings)

    strong_url_indicators = [
        "embedded credentials",
        "punycode",
        "ip address used",
        "ip address in url",
    ]

    if any(indicator in all_url_text for indicator in strong_url_indicators):
        _add_signal(
            signals, "url", "Suspicious URL characteristic",
            "URL analysis identified an IP-based URL, punycode hostname or embedded credentials.",
            15, "High", "URL analysis"
        )

    elif "unencrypted http" in all_url_text or "http url" in all_url_text:
        _add_signal(
            signals, "url", "Unencrypted HTTP URL",
            "The email contains a URL using unencrypted HTTP.",
            8, "Low", "URL analysis"
        )

    # --------------------------------------------------
    # 4. VIRUSTOTAL EVIDENCE
    # --------------------------------------------------

    vt_reports = []

    if isinstance(vt, dict):
        vt_reports.extend(vt.get("url_reports", []) or [])
        vt_reports.extend(vt.get("domain_reports", []) or [])

    malicious_total = 0
    suspicious_total = 0
    valid_reports = 0

    for report in vt_reports:
        if not isinstance(report, dict):
            continue

        if "malicious" not in report:
            continue

        valid_reports += 1
        malicious_total += int(report.get("malicious", 0) or 0)
        suspicious_total += int(report.get("suspicious", 0) or 0)

    if malicious_total > 0:
        _add_signal(
            signals, "reputation", "Malicious reputation detections",
            f"VirusTotal reports {malicious_total} malicious detections across available reports.",
            45, "High", "VirusTotal"
        )

    elif suspicious_total > 0:
        _add_signal(
            signals, "reputation", "Suspicious reputation detections",
            f"VirusTotal reports {suspicious_total} suspicious detections.",
            20, "Medium", "VirusTotal"
        )

    # --------------------------------------------------
    # 5. AI SUPPORTING EVIDENCE
    # --------------------------------------------------

    ai_classification = str(ai.get("classification", "")).lower()

    if ai_classification in ("suspicious", "likely phishing"):
        _add_signal(
            signals, "ai", "AI identified suspicious content",
            "The local AI model classified the email as suspicious. This is supporting evidence only.",
            5, "Informational", "Local AI"
        )

    # --------------------------------------------------
    # 6. CORRELATION AND SCORING
    # --------------------------------------------------

    # Only the strongest signal from each category contributes.
    # This avoids counting the same underlying issue repeatedly.
    category_scores = {}

    for signal in signals:
        category = signal["category"]
        category_scores[category] = max(
            category_scores.get(category, 0),
            signal["points"]
        )

    risk_score = min(100, sum(category_scores.values()))
    independent_categories = len(category_scores)

    strong_evidence = (
        malicious_total > 0
        or any(
            signal["category"] == "content"
            and signal["points"] >= 20
            for signal in signals
        )
        or any(
            signal["category"] == "url"
            and signal["severity"] == "High"
            for signal in signals
        )
    )

    if risk_score >= 60 and independent_categories >= 3 and strong_evidence:
        verdict = "Likely Phishing"
        risk_level = "High"

    elif risk_score >= 25:
        verdict = "Suspicious"
        risk_level = "Medium" if risk_score < 60 else "High"

    elif risk_score > 0:
        verdict = "Low Risk Indicators"
        risk_level = "Low"

    elif valid_reports == 0 and not signals:
        verdict = "Inconclusive"
        risk_level = "Unknown"

    else:
        verdict = "No Strong Phishing Indicators"
        risk_level = "Low"

    # Confidence measures the breadth of available independent evidence.
    # It is not a statistical probability of phishing.
    confidence = min(95, independent_categories * 20)

    if valid_reports == 0:
        confidence = min(confidence, 65)

    if not signals:
        confidence = 0

    # --------------------------------------------------
    # 7. INVESTIGATION SUMMARY
    # --------------------------------------------------

    if signals:
        summary = (
            f"{len(signals)} evidence indicators were identified across "
            f"{independent_categories} independent evidence categories. "
            f"The correlated assessment is {verdict}."
        )
    else:
        summary = (
            "No strong phishing indicators were identified from the "
            "available analysis results. This does not guarantee that the email is safe."
        )

    return {
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "confidence_score": confidence,
        "confidence_note": (
            "Evidence coverage indicator, not a statistical probability."
        ),
        "evidence_count": len(signals),
        "independent_categories": independent_categories,
        "evidence": signals,
        "category_scores": category_scores,
        "virustotal_malicious": malicious_total,
        "virustotal_suspicious": suspicious_total,
        "summary": summary,
        "limitations": [
            "Authentication results are taken from supplied headers and may be forged.",
            "VirusTotal detection counts are not proof of safety or maliciousness.",
            "AI output is supporting evidence, not an authoritative verdict.",
            "A low score does not guarantee that an email is safe."
        ]
    }
