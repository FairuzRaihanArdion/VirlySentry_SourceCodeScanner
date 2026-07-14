import argparse
import sys

from virlysentry import __version__
from virlysentry.config.loader import ConfigError, load_rule_database
from virlysentry.core.models import Severity
from virlysentry.core.scanner import Scanner
from virlysentry.reporters.console_reporter import render_console_report
from virlysentry.reporters.html_reporter import render_html_report
from virlysentry.reporters.json_reporter import render_json_report
from virlysentry.utils import logger

BANNER = r"""
        _      _         __            _              
 /\   /(_)_ __| |_   _  / _\ ___ _ __ | |_ _ __ _   _ 
 \ \ / / | '__| | | | | \ \ / _ \ '_ \| __| '__| | | |
  \ V /| | |  | | |_| | _\ \  __/ | | | |_| |  | |_| |
   \_/ |_|_|  |_|\__, | \__/\___|_| |_|\__|_|   \__, |
                 |___/                          |___/ 
        Devs : KaguraV01d 
                 Github : https://github.com/FairuzRaihanArdion
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="virlysentry",
        description="VirlySentry - Static source code security scanner (OWASP Top 10 / CVE-pattern / dead-code)",
    )
    parser.add_argument("--version", action="version", version=f"VirlySentry {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory for vulnerabilities and dead code")
    scan_parser.add_argument("path", help="Path to the source code folder or file to scan")
    scan_parser.add_argument("--config", "-c", dest="config_path", default=None,
                              help="Path to a custom YAML rule file to extend/override the default rule set")
    scan_parser.add_argument("--replace-rules", action="store_true",
                              help="Use ONLY the rules from --config instead of extending the defaults")
    scan_parser.add_argument("--format", "-f", choices=["console", "json", "html"], default="console",
                              help="Output report format")
    scan_parser.add_argument("--output", "-o", default=None, help="Write the report to a file instead of stdout")
    scan_parser.add_argument("--severity", choices=[s.name for s in Severity], default=None,
                              help="Minimum severity to report (overrides the config default)")
    scan_parser.add_argument("--fail-on", choices=[s.name for s in Severity], default="HIGH",
                              help="Exit with a non-zero status if any finding reaches this severity or higher "
                                   "(useful for CI/CD gating). Default: HIGH")
    scan_parser.add_argument("--include", action="append", default=[],
                              help="Glob pattern (relative to scan root) to include; can be passed multiple times")
    scan_parser.add_argument("--exclude", action="append", default=[],
                              help="Glob pattern (relative to scan root) to exclude; can be passed multiple times")
    scan_parser.add_argument("--no-dead-code", action="store_true", help="Disable unused function/class detection")
    scan_parser.add_argument("--quiet", "-q", action="store_true", help="Suppress the banner and status logs")

    rules_parser = subparsers.add_parser("rules", help="List all loaded detection rules")
    rules_parser.add_argument("--config", "-c", dest="config_path", default=None,
                               help="Path to a custom YAML rule file to include when listing")

    init_parser = subparsers.add_parser("init", help="Generate a starter custom-rules.yaml template")
    init_parser.add_argument("--output", "-o", default="virlysentry-custom-rules.yaml",
                              help="Path for the generated template file")

    return parser


def _cmd_scan(args) -> int:
    if not args.quiet and args.format == "console":
        print(BANNER, file=sys.stderr)

    try:
        rule_db = load_rule_database(custom_path=args.config_path, extend=not args.replace_rules)
    except ConfigError as exc:
        logger.error(str(exc))
        return 2

    if not args.quiet:
        logger.info(f"Loaded {len(rule_db.enabled_rules())} active rules (v{rule_db.version})")
        logger.info(f"Scanning target: {args.path}")

    min_severity = Severity.from_str(args.severity) if args.severity else None
    scanner = Scanner(rule_db, detect_dead_code=not args.no_dead_code)

    try:
        result = scanner.scan(
            args.path,
            include_globs=args.include,
            exclude_globs=args.exclude,
            min_severity=min_severity,
        )
    except FileNotFoundError:
        logger.error(f"Path not found: {args.path}")
        return 2

    if args.format == "console":
        report_text = render_console_report(result, args.path)
    elif args.format == "json":
        report_text = render_json_report(result, args.path)
    else:
        report_text = render_html_report(result, args.path)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report_text)
        if not args.quiet:
            logger.success(f"Report written to {args.output}")
    else:
        print(report_text)

    fail_threshold = Severity.from_str(args.fail_on)
    highest = result.highest_severity()
    if highest is not None and highest >= fail_threshold:
        if not args.quiet:
            logger.warn(
                f"Scan gate failed: highest severity found is {highest.label()}, "
                f"threshold is {fail_threshold.label()}"
            )
        return 1
    return 0


def _cmd_rules(args) -> int:
    try:
        rule_db = load_rule_database(custom_path=args.config_path, extend=True)
    except ConfigError as exc:
        logger.error(str(exc))
        return 2

    for rule in rule_db.rules:
        status = "enabled" if rule.enabled else "disabled"
        print(f"[{rule.id}] {rule.name}")
        print(f"    severity={rule.severity.label()}  category={rule.category}  status={status}")
        if rule.owasp:
            print(f"    owasp={rule.owasp}  cwe={rule.cwe or '-'}")
        print(f"    extensions={rule.extensions}")
        print("")
    print(f"Total rules: {len(rule_db.rules)}")
    return 0


TEMPLATE_YAML = """version: "1.0.0"
meta:
  description: "Custom organization-specific rule extensions for VirlySentry"

settings:
  default_severity_threshold: LOW

rules:
  - id: CUSTOM-001
    name: "Example custom rule: forbidden internal debug flag"
    category: "Security Misconfiguration"
    owasp: "A05:2021-Security Misconfiguration"
    cwe: "CWE-489"
    severity: MEDIUM
    languages: [python]
    extensions: [".py"]
    pattern: "(?i)INTERNAL_DEBUG\\\\s*=\\\\s*True"
    scenario: "Describe the concrete attack scenario this pattern enables (//custom)."
    recommendation: "Describe the safe remediation."
    fixed_example: |
      INTERNAL_DEBUG = False
"""


def _cmd_init(args) -> int:
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(TEMPLATE_YAML)
    logger.success(f"Template written to {args.output}")
    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        exit_code = _cmd_scan(args)
    elif args.command == "rules":
        exit_code = _cmd_rules(args)
    elif args.command == "init":
        exit_code = _cmd_init(args)
    else:
        parser.print_help()
        exit_code = 2

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
