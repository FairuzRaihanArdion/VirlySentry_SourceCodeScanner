import ast
import os
from typing import Dict, List, Tuple

from virlysentry.core.models import DeadCodeFinding

DUNDER_NAMES = {
    "__init__", "__new__", "__str__", "__repr__", "__eq__", "__hash__",
    "__len__", "__call__", "__enter__", "__exit__", "__iter__", "__next__",
    "__getitem__", "__setitem__", "__contains__", "__del__",
}
FRAMEWORK_DECORATOR_HINTS = {
    "app.route", "router.get", "router.post", "app.get", "app.post",
    "pytest.fixture", "property", "staticmethod", "classmethod",
    "app.errorhandler", "click.command", "app.before_request", "app.after_request",
}


class _DefinitionCollector(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.definitions: List[Tuple[str, str, int, bool]] = []
        self._class_stack: List[str] = []

    def _decorator_names(self, node) -> List[str]:
        names = []
        for dec in getattr(node, "decorator_list", []):
            names.append(ast.unparse(dec) if hasattr(ast, "unparse") else "")
        return names

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._register_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._register_function(node)
        self.generic_visit(node)

    def _register_function(self, node):
        in_class = bool(self._class_stack)
        is_dunder = node.name in DUNDER_NAMES
        is_private_entry = node.name.startswith("_") and not node.name.startswith("__")
        decorators = self._decorator_names(node)
        has_framework_decorator = any(
            any(hint in dec for hint in FRAMEWORK_DECORATOR_HINTS) for dec in decorators
        )
        skip = is_dunder or has_framework_decorator or node.name == "main"
        if not skip:
            kind = "method" if in_class else "function"
            self.definitions.append((node.name, kind, node.lineno, is_private_entry))

    def visit_ClassDef(self, node: ast.ClassDef):
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()


class _UsageCollector(ast.NodeVisitor):
    def __init__(self):
        self.used_names: set = set()

    def visit_Name(self, node: ast.Name):
        self.used_names.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        self.used_names.add(node.attr)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)


def analyze_python_dead_code(file_paths: List[str]) -> List[DeadCodeFinding]:
    all_definitions: Dict[str, List[Tuple[str, str, int, str]]] = {}
    global_usage: set = set()

    for path in file_paths:
        if not path.endswith(".py"):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
            tree = ast.parse(source, filename=path)
        except (SyntaxError, OSError, ValueError):
            continue

        defcol = _DefinitionCollector(path)
        defcol.visit(tree)
        for name, kind, lineno, is_private_entry in defcol.definitions:
            all_definitions.setdefault(name, []).append((kind, lineno, path, is_private_entry))

        usecol = _UsageCollector()
        usecol.visit(tree)
        global_usage.update(usecol.used_names)

    findings: List[DeadCodeFinding] = []
    for name, occurrences in all_definitions.items():
        referenced = name in global_usage
        if referenced:
            continue
        for kind, lineno, path, _is_private_entry in occurrences:
            findings.append(
                DeadCodeFinding(
                    kind=kind,
                    name=name,
                    file_path=path,
                    line_number=lineno,
                    reason=f"'{name}' is defined but never referenced anywhere else in the scanned source tree.",
                )
            )
    return findings
