"""AST-based Python scanner for unguarded AI agent tools and side-effect functions."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from ..core._textio import TextDecodeError, read_text

TOOL_DECORATOR_NAMES = {
    "tool",
    "function_tool",
    "agent_tool",
    "mcp_tool",
    "action",
}

GUARD_DECORATOR_NAMES = {
    "guard",
    "policy_gate",
    "require_receipt",
}

SIDE_EFFECT_CALLS: dict[str, tuple[str, str, str]] = {
    "subprocess.run": ("CRITICAL", "TOOL-001", "Shell/process execution via subprocess.run"),
    "subprocess.Popen": ("CRITICAL", "TOOL-001", "Shell/process execution via subprocess.Popen"),
    "subprocess.call": ("CRITICAL", "TOOL-001", "Shell/process execution via subprocess.call"),
    "subprocess.check_output": ("CRITICAL", "TOOL-001", "Shell/process execution via subprocess.check_output"),
    "os.system": ("CRITICAL", "TOOL-001", "Unrestricted shell command execution via os.system"),
    "os.remove": ("HIGH", "TOOL-002", "Destructive file deletion via os.remove"),
    "os.unlink": ("HIGH", "TOOL-002", "Destructive file deletion via os.unlink"),
    "shutil.rmtree": ("CRITICAL", "TOOL-002", "Recursive directory deletion via shutil.rmtree"),
    "requests.post": ("MEDIUM", "TOOL-003", "External HTTP POST mutation via requests.post"),
    "requests.delete": ("HIGH", "TOOL-003", "External HTTP DELETE mutation via requests.delete"),
    "requests.put": ("MEDIUM", "TOOL-003", "External HTTP PUT mutation via requests.put"),
    "httpx.post": ("MEDIUM", "TOOL-003", "External HTTP POST mutation via httpx.post"),
    "httpx.delete": ("HIGH", "TOOL-003", "External HTTP DELETE mutation via httpx.delete"),
}

SQL_MUTATION_RE = re.compile(
    r"\b(DELETE\s+FROM|DROP\s+TABLE|TRUNCATE\s+TABLE|UPDATE\s+\w+\s+SET|INSERT\s+INTO)\b",
    re.IGNORECASE,
)


def scan_python_files(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Scan Python files under ``root`` for unguarded agent tools and side effects."""
    findings: list[dict[str, Any]] = []
    discovered_tools: list[dict[str, Any]] = []

    if root.is_file():
        py_files = [root] if root.suffix == ".py" else []
    else:
        py_files = [
            p
            for p in root.rglob("*.py")
            if not any(
                part in (".git", "node_modules", ".venv", "venv", "__pycache__", "tests")
                for part in p.parts
            )
        ]

    for py_path in sorted(py_files):
        try:
            source = read_text(py_path, kind="Python source")
            tree = ast.parse(source, filename=str(py_path))
        except (TextDecodeError, SyntaxError, OSError):
            continue

        file_imports_agentproof = "agentproof" in source
        rel_path = _rel(py_path, root)

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            decorators = [_decorator_name(d) for d in node.decorator_list]
            is_guarded = any(
                d.split(".")[-1] in GUARD_DECORATOR_NAMES for d in decorators if d
            )
            is_explicit_tool = any(
                d.split(".")[-1] in TOOL_DECORATOR_NAMES for d in decorators if d
            )

            side_effects = _find_side_effects(node)
            sql_mutations = _find_sql_mutations(node)

            if not is_explicit_tool and not side_effects and not sql_mutations:
                continue

            action_name = _infer_action_name(node.name)
            risk_level = "low"
            if side_effects or sql_mutations:
                risk_level = (
                    "critical"
                    if any(se[0] == "CRITICAL" for se in side_effects) or sql_mutations
                    else "high"
                )

            discovered_tools.append(
                {
                    "name": action_name,
                    "function": node.name,
                    "source": f"{rel_path}:{node.lineno}",
                    "kind": "agent_tool" if is_explicit_tool else "side_effect_fn",
                    "guarded": is_guarded or file_imports_agentproof,
                    "risk": risk_level,
                    "description": (ast.get_docstring(node) or f"Function {node.name}").splitlines()[0],
                }
            )

            if is_guarded:
                continue

            # Report unguarded explicit agent tools
            if is_explicit_tool and not file_imports_agentproof:
                sev = "HIGH" if (side_effects or sql_mutations) else "MEDIUM"
                findings.append(
                    {
                        "rule_id": "TOOL-000",
                        "severity": sev,
                        "category": "unguarded_tool",
                        "location": f"{rel_path}:{node.lineno}",
                        "title": f"Unguarded agent tool `{node.name}`",
                        "detail": (
                            f"Function `{node.name}` is decorated as an agent tool "
                            "but has no pre-execution ` @gate.guard()` or `agentproof` receipt check."
                        ),
                        "remediation": (
                            f"Decorate `{node.name}` with `@gate.guard({action_name!r})` "
                            f"and declare `{action_name}` in policy.yaml."
                        ),
                        "action_name": action_name,
                    }
                )

            # Report specific dangerous side effects inside unguarded functions
            for sev, rule_id, desc in side_effects:
                if file_imports_agentproof and not is_explicit_tool:
                    continue
                findings.append(
                    {
                        "rule_id": rule_id,
                        "severity": sev,
                        "category": "side_effect",
                        "location": f"{rel_path}:{node.lineno}",
                        "title": f"{desc} in `{node.name}()`",
                        "detail": (
                            f"Function `{node.name}` performs {desc.lower()} without a "
                            "signed pre-execution policy receipt."
                        ),
                        "remediation": (
                            f"Wrap `{node.name}` with `@gate.guard({action_name!r})` and "
                            "require explicit scope approval in policy.yaml."
                        ),
                        "action_name": action_name,
                    }
                )

            for sql_snippet in sql_mutations:
                if file_imports_agentproof and not is_explicit_tool:
                    continue
                findings.append(
                    {
                        "rule_id": "TOOL-004",
                        "severity": "HIGH",
                        "category": "sql_mutation",
                        "location": f"{rel_path}:{node.lineno}",
                        "title": f"Unguarded SQL mutation ({sql_snippet}) in `{node.name}()`",
                        "detail": (
                            f"Function `{node.name}` executes a destructive/mutating SQL statement "
                            f"(`{sql_snippet}`) without a pre-execution policy gate."
                        ),
                        "remediation": (
                            f"Gate `{action_name}` with `@gate.guard({action_name!r})` "
                            "or set `effect: deny` / `effect: halt` for write operations."
                        ),
                        "action_name": action_name,
                    }
                )

    return findings, discovered_tools


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _decorator_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        return func.attr
    return ""


def _find_side_effects(fn_node: ast.AST) -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for sub in ast.walk(fn_node):
        if isinstance(sub, ast.Call):
            cname = _call_name(sub)
            if cname in SIDE_EFFECT_CALLS and cname not in seen:
                seen.add(cname)
                found.append(SIDE_EFFECT_CALLS[cname])
    return found


def _find_sql_mutations(fn_node: ast.AST) -> list[str]:
    found: list[str] = []
    for sub in ast.walk(fn_node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            match = SQL_MUTATION_RE.search(sub.value)
            if match:
                verb = " ".join(match.group(1).upper().split())
                if verb not in found:
                    found.append(verb)
    return found


def _infer_action_name(fn_name: str) -> str:
    parts = [p for p in fn_name.strip("_").split("_") if p]
    if len(parts) >= 2:
        return f"{parts[0]}.{'_'.join(parts[1:])}"
    return fn_name.strip("_") or "agent.action"


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")
