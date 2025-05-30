import tldextract

def check_domain_impersonation(url: str) -> str:
    suspicious_domains = ["paypa1.com", "micros0ft.com"]
    domain = tldextract.extract(url).registered_domain
    return "Suspicious" if domain in suspicious_domains else "Clean"
