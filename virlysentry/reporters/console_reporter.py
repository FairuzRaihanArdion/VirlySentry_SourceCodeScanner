from colorama import Fore, Style, init as colorama_init

from virlysentry.core.models import ScanResult, Severity

colorama_init(autoreset=True)

SEVERITY_COLORS = {
    Severity.CRITICAL: Fore.MAGENTA + Style.BRIGHT,
    Severity.HIGH: Fore.RED + Style.BRIGHT,
    Severity.MEDIUM: Fore.YELLOW,
    Severity.LOW: Fore.CYAN,
    Severity.INFO: Fore.WHITE,
}


def _sev(text: str, severity: Severity) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{Style.RESET_ALL}"


def render_console_report(result: ScanResult, target: str) -> str:
    lines = []
    lines.append(f"{Style.BRIGHT}VirlySentry - Source Code Security Scan{Style.RESET_ALL}")
    lines.append(f"Target: {target}")
    lines.append(f"Files scanned: {result.files_scanned}  |  Duration: {result.duration_seconds:.2f}s")
    lines.append("-" * 72)

    if not result.findings:
        lines.append(Fore.GREEN + "No vulnerability findings above the configured severity threshold." + Style.RESET_ALL)
    else:
        for f in result.findings:
            header = f"[{f.rule_id}] {f.title}"
            lines.append(_sev(header, f.severity) + f"  ({_sev(f.severity.label(), f.severity)})")
            lines.append(f"  File     : {f.file_path}:{f.line_number}:{f.column}")
            if f.owasp:
                lines.append(f"  OWASP    : {f.owasp}" + (f"  |  {f.cwe}" if f.cwe else ""))
            lines.append(f"  Code     : {f.code_snippet}")
            lines.append(f"  Scenario : {f.scenario}")
            lines.append(f"  Fix      : {f.recommendation}")
            for i, line in enumerate(f.fixed_example.splitlines()):
                prefix = "  Example  : " if i == 0 else "             "
                lines.append(prefix + line)
            lines.append("")

    if result.dead_code:
        lines.append("-" * 72)
        lines.append(f"{Style.BRIGHT}Dead Code / Unused Definitions{Style.RESET_ALL}")
        for d in result.dead_code:
            lines.append(
                f"  {Fore.YELLOW}[UNUSED-{d.kind.upper()}]{Style.RESET_ALL} "
                f"{d.name}  --  {d.file_path}:{d.line_number}"
            )
            lines.append(f"    {d.reason}")

    lines.append("-" * 72)
    counts = result.severity_counts()
    summary = "  ".join(f"{_sev(k, Severity[k])}: {v}" for k, v in counts.items() if v > 0)
    lines.append(f"Summary: {summary}" if summary else "Summary: 0 findings")
    lines.append(f"Dead code items: {len(result.dead_code)}")
    return "\n".join(lines)
