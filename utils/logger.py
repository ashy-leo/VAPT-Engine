"""
utils/logger.py

"""

from rich.console import Console
from rich.panel import Panel

console = Console()


def log_info(msg: str) -> None:
    
    console.print(f"[bold blue][+][/bold blue] {msg}")


def log_success(msg: str) -> None:
    
    console.print(f"[bold green][+][/bold green] {msg}")


def log_warn(msg: str) -> None:
    
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def log_error(msg: str) -> None:
    
    console.print(f"[bold red][-][/bold red] {msg}")


def print_banner() -> None:
    
    banner_text = r"""
 /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\ 
( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )
 > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ < 
 /\_/\        _   _  _____  ___   _____        ___                                          /\_/\ 
( o.o )      ( ) ( )(  _  )(  _`\(_   _)      (  _`\                _                      ( o.o )
 > ^ <       | | | || (_) || |_) ) | | ______ | (_(_)  ___     __  (_)  ___     __          > ^ < 
 /\_/\       | | | ||  _  || ,__/' | |(______)|  _)_ /' _ `\ /'_ `\| |/' _ `\ /'__`\        /\_/\ 
( o.o )      | \_/ || | | || |     | |        | (_( )| ( ) |( (_) || || ( ) |(  ___/       ( o.o )
 > ^ <       `\___/'(_) (_)(_)     (_)        (____/'(_) (_)`\__  |(_)(_) (_)`\____)        > ^ < 
 /\_/\                                                      ( )_) |                         /\_/\ 
( o.o )                                                      \___/'                        ( o.o )
 > ^ <                                                                                      > ^ < 
 /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\ 
( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )
 > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ < 
"""
    console.print(
        Panel(
            banner_text,
            title="VAPT-Engine",
            subtitle="Vulnerability Assessment & Penetration Testing",
            border_style="bold cyan",
        )
    )
              