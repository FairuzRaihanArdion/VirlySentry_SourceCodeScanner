import sys

from colorama import Fore, Style


def info(message: str) -> None:
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {message}", file=sys.stderr)


def success(message: str) -> None:
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}", file=sys.stderr)


def warn(message: str) -> None:
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}", file=sys.stderr)


def error(message: str) -> None:
    print(f"{Fore.RED}[x]{Style.RESET_ALL} {message}", file=sys.stderr)
