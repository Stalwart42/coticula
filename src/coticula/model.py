from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass
class Finding:
    check: str  # secrets | deps | ai | manifest | quality
    rule: str
    severity: str
    message: str
    path: str = ""
    line: int = 0
    snippet: str = ""
    fix: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Report:
    root: str
    version: str
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    quality_score: int = 100
    capabilities: Dict[str, List[str]] = field(default_factory=dict)
    checks_run: List[str] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def worst(self) -> str:
        if not self.findings:
            return "info"
        return max((f.severity for f in self.findings), key=sev_rank)

    def passed(self, fail_on: str) -> bool:
        threshold = sev_rank(fail_on)
        return not any(sev_rank(f.severity) >= threshold for f in self.findings)

    def tier(self) -> str:
        """Trust tier earned by an automated scan: 'scanned' when nothing high or critical."""
        c = self.counts()
        return "scanned" if c["high"] == 0 and c["critical"] == 0 else "issues"

    def to_dict(self, fail_on: str = "high") -> Dict:
        return {
            "tool": "coticula",
            "version": self.version,
            "root": self.root,
            "files_scanned": self.files_scanned,
            "checks_run": self.checks_run,
            "passed": self.passed(fail_on),
            "fail_on": fail_on,
            "tier": self.tier(),
            "quality_score": self.quality_score,
            "counts": self.counts(),
            "capabilities": self.capabilities,
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda f: (-sev_rank(f.severity), f.path, f.line))],
        }
