import os
from dataclasses import dataclass, field
from typing import List, Optional

import yaml

from virlysentry.core.models import Severity

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(__file__), "default_rules.yaml")

REQUIRED_RULE_FIELDS = [
    "id", "name", "category", "severity", "extensions", "pattern",
    "scenario", "recommendation", "fixed_example",
]


class ConfigError(Exception):
    pass


@dataclass
class Rule:
    id: str
    name: str
    category: str
    severity: Severity
    extensions: List[str]
    pattern: str
    scenario: str
    recommendation: str
    fixed_example: str
    languages: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    enabled: bool = True


@dataclass
class ScanSettings:
    default_severity_threshold: Severity = Severity.LOW
    max_file_size_kb: int = 2048
    binary_extensions: List[str] = field(default_factory=list)
    excluded_dirs: List[str] = field(default_factory=list)
    ignore_inline_marker: str = "virlysentry:ignore"


@dataclass
class RuleDatabase:
    rules: List[Rule]
    settings: ScanSettings
    version: str = "1.0.0"

    def enabled_rules(self):
        return [r for r in self.rules if r.enabled]


def _parse_rule(raw: dict) -> Rule:
    missing = [f for f in REQUIRED_RULE_FIELDS if f not in raw]
    if missing:
        raise ConfigError(f"Rule '{raw.get('id', '?')}' is missing required fields: {missing}")
    return Rule(
        id=raw["id"],
        name=raw["name"],
        category=raw["category"],
        severity=Severity.from_str(raw["severity"]),
        extensions=raw["extensions"],
        pattern=raw["pattern"],
        scenario=raw["scenario"],
        recommendation=raw["recommendation"],
        fixed_example=raw["fixed_example"],
        languages=raw.get("languages", []),
        cwe=raw.get("cwe"),
        owasp=raw.get("owasp"),
        enabled=raw.get("enabled", True),
    )


def load_rule_database(custom_path: Optional[str] = None, extend: bool = True) -> RuleDatabase:
    with open(DEFAULT_RULES_PATH, "r", encoding="utf-8") as fh:
        base_doc = yaml.safe_load(fh) or {}

    rules_raw = list(base_doc.get("rules", []))
    settings_raw = dict(base_doc.get("settings", {}))
    version = base_doc.get("version", "1.0.0")

    if custom_path:
        if not os.path.isfile(custom_path):
            raise ConfigError(f"Custom rule file not found: {custom_path}")
        with open(custom_path, "r", encoding="utf-8") as fh:
            custom_doc = yaml.safe_load(fh) or {}

        custom_rules = custom_doc.get("rules", [])
        if extend:
            existing_ids = {r["id"] for r in rules_raw}
            for cr in custom_rules:
                if cr.get("id") in existing_ids:
                    rules_raw = [r if r["id"] != cr["id"] else cr for r in rules_raw]
                else:
                    rules_raw.append(cr)
        else:
            rules_raw = custom_rules

        settings_raw.update(custom_doc.get("settings", {}))
        version = custom_doc.get("version", version)

    rules = [_parse_rule(r) for r in rules_raw]

    settings = ScanSettings(
        default_severity_threshold=Severity.from_str(settings_raw.get("default_severity_threshold", "LOW")),
        max_file_size_kb=int(settings_raw.get("max_file_size_kb", 2048)),
        binary_extensions=settings_raw.get("binary_extensions", []),
        excluded_dirs=settings_raw.get("excluded_dirs", []),
        ignore_inline_marker=settings_raw.get("ignore_inline_marker", "virlysentry:ignore"),
    )

    return RuleDatabase(rules=rules, settings=settings, version=version)
