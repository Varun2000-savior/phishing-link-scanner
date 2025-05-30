from rich.console import Console
from rich.table import Table

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
