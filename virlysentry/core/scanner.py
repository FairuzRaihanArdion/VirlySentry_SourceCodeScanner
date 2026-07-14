import time
from typing import List, Optional

from virlysentry.config.loader import RuleDatabase
from virlysentry.core.engine import RuleEngine
from virlysentry.core.file_walker import walk_source_files
from virlysentry.core.models import ScanResult, Severity
from virlysentry.rules.dead_code import analyze_python_dead_code


class Scanner:
    def __init__(self, rule_db: RuleDatabase, detect_dead_code: bool = True):
        self._rule_db = rule_db
        self._engine = RuleEngine(rule_db.enabled_rules(), rule_db.settings)
        self._detect_dead_code = detect_dead_code

    def scan(
        self,
        target_path: str,
        include_globs: Optional[List[str]] = None,
        exclude_globs: Optional[List[str]] = None,
        min_severity: Optional[Severity] = None,
    ) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()
        threshold = min_severity if min_severity is not None else self._rule_db.settings.default_severity_threshold

        scanned_files: List[str] = []
        for file_path in walk_source_files(target_path, self._rule_db.settings, include_globs, exclude_globs):
            scanned_files.append(file_path)
            result.files_scanned += 1
            findings = self._engine.scan_file(file_path)
            result.findings.extend(f for f in findings if f.severity >= threshold)

        if self._detect_dead_code:
            result.dead_code = analyze_python_dead_code(scanned_files)

        result.findings.sort(key=lambda f: (-f.severity.value, f.file_path, f.line_number))
        result.duration_seconds = time.perf_counter() - start
        return result
