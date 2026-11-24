import ast
from .models import Analysis, Decision

# These weights are policy heuristics for a demo, not calibrated security measurements.
RULES = {
    "eval": (60, "Dynamic evaluation"),
    "exec": (60, "Dynamic code execution"),
    "compile": (35, "Runtime code compilation"),
    "subprocess": (40, "Subprocess creation"),
    "os.system": (60, "Shell command execution"),
    "socket": (80, "Raw network socket"),
    "requests": (70, "HTTP client/network access"),
    "urllib": (60, "URL/network access"),
    "ctypes": (70, "Native memory/interface access"),
    "shutil.rmtree": (35, "Recursive deletion"),
}

class ScriptAnalyzer:
    def analyze_text(self, source: str) -> Analysis:
        findings, reasons = [], []
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return Analysis([{"rule": "syntax_error", "line": exc.lineno,
                              "detail": str(exc)}], 100, Decision.DENY,
                            ["Script has a syntax error and will not be executed."])
        for node in ast.walk(tree):
            name = None
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    parts, current = [], node.func
                    while isinstance(current, ast.Attribute):
                        parts.append(current.attr)
                        current = current.value
                    if isinstance(current, ast.Name):
                        parts.append(current.id)
                    name = ".".join(reversed(parts))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name.split(".")[0]
                    if name in {"socket", "subprocess", "requests", "urllib", "ctypes"}:
                        self._add(findings, reasons, name, node.lineno)
            elif isinstance(node, ast.ImportFrom) and node.module:
                name = node.module.split(".")[0]
            if name:
                for rule, (weight, detail) in RULES.items():
                    if name == rule or name.startswith(rule + "."):
                        self._add(findings, reasons, rule, getattr(node, "lineno", None))
                        break
                if isinstance(node, (ast.ImportFrom, ast.Import)) and name in {
                    "socket", "subprocess", "requests", "urllib", "ctypes"
                }:
                    self._add(findings, reasons, name, getattr(node, "lineno", None))
        # Deduplicate identical rule/line pairs.
        unique = {(f["rule"], f["line"]): f for f in findings}
        findings = list(unique.values())
        score = min(100, sum(RULES.get(f["rule"], (25, ""))[0] for f in findings))
        if score >= 80:
            decision = Decision.DENY
            reasons.append("Risk score meets or exceeds the default deny threshold (80).")
        elif score >= 35:
            decision = Decision.APPROVAL_REQUIRED
            reasons.append("Risk score requires explicit interactive approval.")
        else:
            decision = Decision.ALLOW
            reasons.append("No high-risk pattern matched the default static rules.")
        return Analysis(findings, score, decision, reasons)

    @staticmethod
    def _add(findings, reasons, rule, line):
        if rule in RULES:
            findings.append({"rule": rule, "line": line, "detail": RULES[rule][1]})
