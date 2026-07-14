import os
import re
from typing import List

from virlysentry.config.loader import Rule, ScanSettings
from virlysentry.core.models import Finding


class RuleEngine:
    def __init__(self, rules: List[Rule], settings: ScanSettings):
        self._settings = settings
        self._compiled = []
        for rule in rules:
            try:
                flags = re.MULTILINE
                compiled = re.compile(rule.pattern, flags)
            except re.error as exc:
                raise ValueError(f"Invalid regex in rule '{rule.id}': {exc}") from exc
            self._compiled.append((rule, compiled))

    def _rules_for_extension(self, ext: str):
        return [(r, c) for r, c in self._compiled if ext in r.extensions]

    def scan_file(self, file_path: str) -> List[Finding]:
        ext = os.path.splitext(file_path)[1].lower()
        applicable = self._rules_for_extension(ext)
        if not applicable:
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except (OSError, UnicodeDecodeError):
            return []

        lines = content.splitlines()
        findings: List[Finding] = []
        marker = self._settings.ignore_inline_marker

        for rule, compiled in applicable:
            for match in compiled.finditer(content):
                line_number = content.count("\n", 0, match.start()) + 1
                line_text = lines[line_number - 1] if 0 <= line_number - 1 < len(lines) else match.group(0)

                if marker in line_text:
                    continue

                column = match.start() - (content.rfind("\n", 0, match.start()) + 1) + 1
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.name,
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=line_number,
                        column=column,
                        code_snippet=line_text.strip()[:300],
                        scenario=rule.scenario,
                        recommendation=rule.recommendation,
                        fixed_example=rule.fixed_example.strip(),
                        category=rule.category,
                        cwe=rule.cwe,
                        owasp=rule.owasp,
                    )
                )
        return findings
