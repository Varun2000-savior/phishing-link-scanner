def score_threat(url: str) -> str:
    score = 0
    if "@" in url or "//" in url:
        score += 1
    if any(bad in url.lower() for bad in ["login", "verify", "update", "secure"]):
        score += 1
    if "tinyurl.com" in url or "bit.ly" in url:
        score += 1

    return "High" if score >= 3 else "Medium" if score == 2 else "Low"
