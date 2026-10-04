"""
utils/logger.py

Lightweight console logging helpers for VAPT-Engine, built on the `rich` library.
Provides simple colored status indicators and a startup banner.
"""

from rich.console import Console
from rich.panel import Panel

# Single shared Console instance used by every function in this module.
console = Console()


def log_info(msg: str) -> None:
    """Print a blue [+] status message for general information."""
    console.print(f"[bold blue][+][/bold blue] {msg}")


def log_success(msg: str) -> None:
    """Print a green [+] status message for successful operations."""
    console.print(f"[bold green][+][/bold green] {msg}")


def log_warn(msg: str) -> None:
    """Print a yellow [!] status message for warnings."""
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def log_error(msg: str) -> None:
    """Print a red [-] status message for errors or failures."""
    console.print(f"[bold red][-][/bold red] {msg}")


def print_banner() -> None:
    """Display the VAPT-Engine ASCII banner inside a Rich panel."""
    banner_text = r"""
____   _________ _____________________ ___________ _______    ________.___ _______  ___________
\   \ /   /  _  \\______   \__    ___/ \_   _____/ \      \  /  _____/|   |\      \ \_   _____/
 \   Y   /  /_\  \|     ___/ |    |     |    __)_  /   |   \/   \  ___|   |/   |   \ |    __)_ 
  \     /    |    \    |     |    |     |        \/    |    \    \_\  \   /    |    \|        \
   \___/\____|__  /____|     |____|    /_______  /\____|__  /\______  /___\____|__  /_______  /
                \/                             \/         \/        \/            \/        \/ 
"""
    console.print(
        Panel(
            banner_text,
            title="VAPT-Engine",
            subtitle="Vulnerability Assessment & Penetration Testing",
            border_style="bold cyan",
        )
    )
              