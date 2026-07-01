"""
Aggregates per-control CheckResults into per-device and fleet-wide summaries.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone

from app.checks.cis_v8_rules import run_all_checks, control_count, CheckResult

SEVERITY_WEIGHT = {"high": 5, "medium": 3, "low": 1}


@dataclass
class DeviceReport:
    host: str
    name: str
    site: str
    generated_at: str
    results: list
    total_controls: int
    passed: int
    failed: int
    score_pct: float
    weighted_score_pct: float
    error: str = ""

    def to_dict(self):
        d = asdict(self)
        return d


def score_device(host: str, name: str, site: str, config_text: str) -> DeviceReport:
    results: list[CheckResult] = run_all_checks(config_text)
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed

    max_weight = sum(SEVERITY_WEIGHT[r.severity] for r in results)
    earned_weight = sum(SEVERITY_WEIGHT[r.severity] for r in results if r.passed)
    weighted_pct = round(100 * earned_weight / max_weight, 1) if max_weight else 100.0

    return DeviceReport(
        host=host,
        name=name,
        site=site,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        results=[r.__dict__ for r in results],
        total_controls=total,
        passed=passed,
        failed=failed,
        score_pct=round(100 * passed / total, 1) if total else 100.0,
        weighted_score_pct=weighted_pct,
    )


def error_device_report(host: str, name: str, site: str, error_message: str) -> DeviceReport:
    return DeviceReport(
        host=host,
        name=name,
        site=site,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        results=[],
        total_controls=control_count(),
        passed=0,
        failed=0,
        score_pct=0.0,
        weighted_score_pct=0.0,
        error=error_message,
    )


def fleet_summary(device_reports: list[DeviceReport]) -> dict:
    reachable = [d for d in device_reports if not d.error]
    if not reachable:
        return {
            "device_count": len(device_reports),
            "reachable_count": 0,
            "avg_score_pct": 0.0,
            "avg_weighted_score_pct": 0.0,
            "total_failed_controls": 0,
            "high_severity_failures": 0,
            "worst_device": None,
            "best_device": None,
        }

    avg_score = round(sum(d.score_pct for d in reachable) / len(reachable), 1)
    avg_weighted = round(sum(d.weighted_score_pct for d in reachable) / len(reachable), 1)
    total_failed = sum(d.failed for d in reachable)

    high_sev_failures = 0
    for d in reachable:
        for r in d.results:
            if not r["passed"] and r["severity"] == "high":
                high_sev_failures += 1

    sorted_by_score = sorted(reachable, key=lambda d: d.weighted_score_pct)

    return {
        "device_count": len(device_reports),
        "reachable_count": len(reachable),
        "avg_score_pct": avg_score,
        "avg_weighted_score_pct": avg_weighted,
        "total_failed_controls": total_failed,
        "high_severity_failures": high_sev_failures,
        "worst_device": sorted_by_score[0].name if sorted_by_score else None,
        "best_device": sorted_by_score[-1].name if sorted_by_score else None,
    }
