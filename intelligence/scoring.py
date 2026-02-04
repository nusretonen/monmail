from __future__ import annotations


def score_detection(rule: dict) -> tuple[int, str]:
    base = int(rule.get("base_score", 50))
    confidence = max(1, min(100, base))
    if confidence >= 85:
        severity = "critical"
    elif confidence >= 70:
        severity = "high"
    elif confidence >= 40:
        severity = "medium"
    else:
        severity = "low"
    return confidence, severity
