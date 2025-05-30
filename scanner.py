from rich.console import Console
from rich.table import Table
import tldextract

console = Console()

def print_banner():
    console.print("[bold blue]🚨 Phishing Link Scanner 🚨[/bold blue]")

def print_result_table(results: dict):
    table = Table(title="Scan Results")
    table.add_column("Check", style="cyan")
    table.add_column("Result", style="magenta")
    for key, value in results.items():
        table.add_row(key, value)
    console.print(table)

def check_domain_impersonation(url):
    suspicious = ["paypa1.com", "micros0ft.com", "faceb00k.com"]
    domain = tldextract.extract(url).registered_domain
    return "Suspicious" if domain in suspicious else "Clean"

def analyze_keywords(url):
    bad_keywords = ["login", "secure", "update", "verify"]
    return "Suspicious" if any(word in url.lower() for word in bad_keywords) else "Clean"

def score_threat(url):
    score = 0
    if "@" in url or "//" in url: score += 1
    if any(k in url.lower() for k in ["login", "secure", "update"]): score += 1
    return "High" if score >= 2 else "Medium" if score == 1 else "Low"

def scan_url(url):
    print_banner()
    results = {
        "Domain Check": check_domain_impersonation(url),
        "Keyword Analysis": analyze_keywords(url),
        "Threat Score": score_threat(url),
    }
    print_result_table(results)

if __name__ == "__main__":
    url = input("Enter a URL to scan: ")
    scan_url(url)
