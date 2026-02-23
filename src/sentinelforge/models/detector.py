"""
Detection models — rule-based detection engine and NumPy-based anomaly detector.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from sentinelforge.schemas import OCSFAlert, Severity

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


@dataclass
class DetectionRule:
    """A detection rule with conditions and metadata."""
    rule_id: str
    name: str
    description: str
    severity: Severity
    conditions: dict[str, Any]
    mitre_technique_id: str = ""
    tags: list[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class Detection:
    """A detection (rule match) result."""
    rule_id: str
    rule_name: str
    alert_id: str
    severity: Severity
    description: str
    matched_fields: dict[str, Any] = field(default_factory=dict)


# Built-in detection rules
BUILTIN_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="SF-001",
        name="Multiple Failed Logins",
        description="More than 5 failed login attempts from same source within analysis window",
        severity=Severity.HIGH,
        conditions={"category": "Authentication", "activity_pattern": r"fail|denied|invalid", "threshold": 5},
        mitre_technique_id="T1110",
        tags=["brute-force"],
    ),
    DetectionRule(
        rule_id="SF-002",
        name="Suspicious PowerShell",
        description="Encoded or obfuscated PowerShell command detected",
        severity=Severity.HIGH,
        conditions={"activity_pattern": r"powershell.*(-enc|-nop|-w\s+hidden|iex|invoke-expression|downloadstring)"},
        mitre_technique_id="T1059.001",
        tags=["execution", "powershell"],
    ),
    DetectionRule(
        rule_id="SF-003",
        name="Credential Dumping Tool",
        description="Known credential dumping tool detected (mimikatz, procdump, etc.)",
        severity=Severity.CRITICAL,
        conditions={"activity_pattern": r"mimikatz|procdump.*lsass|sekurlsa|hashdump|gsecdump"},
        mitre_technique_id="T1003",
        tags=["credential-access"],
    ),
    DetectionRule(
        rule_id="SF-004",
        name="Outbound Connection to Known C2",
        description="Connection to IP/domain flagged in threat intelligence",
        severity=Severity.CRITICAL,
        conditions={"threat_intel_match": True},
        mitre_technique_id="T1071",
        tags=["c2"],
    ),
    DetectionRule(
        rule_id="SF-005",
        name="Log Clearing Detected",
        description="Event log clearing or deletion activity detected",
        severity=Severity.HIGH,
        conditions={"activity_pattern": r"wevtutil\s+cl|clear-eventlog|rm\s+-rf.*/var/log|shred.*log"},
        mitre_technique_id="T1070.001",
        tags=["defense-evasion"],
    ),
    DetectionRule(
        rule_id="SF-006",
        name="Port Scan Detected",
        description="Network scanning activity from a single source",
        severity=Severity.MEDIUM,
        conditions={"activity_pattern": r"port\s*scan|nmap|masscan|zmap", "unique_dst_ports_threshold": 10},
        mitre_technique_id="T1046",
        tags=["discovery"],
    ),
    DetectionRule(
        rule_id="SF-007",
        name="Ransomware Indicator",
        description="Ransomware-related activity detected",
        severity=Severity.CRITICAL,
        conditions={"activity_pattern": r"ransom|encrypt.*files|\.locked|bitcoin.*wallet|your\s+files\s+have\s+been"},
        mitre_technique_id="T1486",
        tags=["impact", "ransomware"],
    ),
    DetectionRule(
        rule_id="SF-008",
        name="Suspicious DNS Query",
        description="DNS query to high-entropy or known-bad domain",
        severity=Severity.MEDIUM,
        conditions={"category": "DNS Activity", "activity_pattern": r"nxdomain|\.tk$|\.xyz$|[a-z0-9]{25,}\."},
        mitre_technique_id="T1071.004",
        tags=["dns", "c2"],
    ),
    DetectionRule(
        rule_id="SF-009",
        name="Privilege Escalation Attempt",
        description="Attempt to escalate privileges detected",
        severity=Severity.HIGH,
        conditions={"activity_pattern": r"CVE-\d{4}-\d+|exploit|privilege.*escalat|setuid|capability"},
        mitre_technique_id="T1068",
        tags=["privesc"],
    ),
    DetectionRule(
        rule_id="SF-010",
        name="Data Exfiltration Indicator",
        description="Large data transfer or unusual exfiltration channel detected",
        severity=Severity.HIGH,
        conditions={"activity_pattern": r"exfiltrat|upload.*\d+[MGT]B|dns.*tunnel|\.onion|base64.*large"},
        mitre_technique_id="T1041",
        tags=["exfiltration"],
    ),
]


class RuleEngine:
    """
    Rule-based detection engine.

    Evaluates alerts against a set of detection rules and returns matches.
    """

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self.rules = rules if rules is not None else list(BUILTIN_RULES)

    def evaluate(self, alert: OCSFAlert) -> list[Detection]:
        """Evaluate an alert against all rules."""
        detections = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if self._matches(alert, rule):
                detections.append(Detection(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    alert_id=alert.alert_id,
                    severity=rule.severity,
                    description=rule.description,
                    matched_fields={"conditions": rule.conditions},
                ))
        return detections

    def evaluate_batch(self, alerts: list[OCSFAlert]) -> list[Detection]:
        """Evaluate multiple alerts, including threshold-based rules."""
        all_detections = []
        # Individual rule evaluation
        for alert in alerts:
            all_detections.extend(self.evaluate(alert))

        # Threshold-based rules (e.g., "more than N events from same source")
        for rule in self.rules:
            threshold = rule.conditions.get("threshold")
            if threshold and rule.enabled:
                # Group alerts by source
                groups: dict[str, list[OCSFAlert]] = defaultdict(list)
                for alert in alerts:
                    if self._matches_pattern(alert, rule):
                        key = alert.src_ip or alert.username or alert.hostname
                        if key:
                            groups[key].append(alert)
                for key, group in groups.items():
                    if len(group) >= threshold:
                        all_detections.append(Detection(
                            rule_id=rule.rule_id,
                            rule_name=f"{rule.name} (threshold: {len(group)}/{threshold})",
                            alert_id=group[0].alert_id,
                            severity=rule.severity,
                            description=f"{rule.description} — {len(group)} events from {key}",
                            matched_fields={"source": key, "count": len(group), "threshold": threshold},
                        ))

        return all_detections

    def _matches(self, alert: OCSFAlert, rule: DetectionRule) -> bool:
        """Check if an alert matches a rule's conditions."""
        conditions = rule.conditions

        # Category match
        if conditions.get("category") and alert.category != conditions["category"]:
            return False

        # Threat intel match
        if conditions.get("threat_intel_match"):
            if not alert.threat_intel.get("max_confidence", 0) > 0.7:
                return False

        # Activity pattern
        return self._matches_pattern(alert, rule)

    def _matches_pattern(self, alert: OCSFAlert, rule: DetectionRule) -> bool:
        """Check if alert text matches rule's activity pattern."""
        pattern = rule.conditions.get("activity_pattern")
        if not pattern:
            return True
        text = f"{alert.activity} {alert.class_name} {alert.raw_log} {alert.process_name}"
        return bool(re.search(pattern, text, re.IGNORECASE))

    def add_rule(self, rule: DetectionRule) -> None:
        self.rules.append(rule)

    def disable_rule(self, rule_id: str) -> bool:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = False
                return True
        return False


class AnomalyDetector:
    """
    Statistical anomaly detector using NumPy (or pure Python fallback).

    Detects anomalies in numeric features like connection counts, bytes
    transferred, and timing patterns using z-score analysis.
    """

    def __init__(self, z_threshold: float = 2.5) -> None:
        self.z_threshold = z_threshold
        self._baselines: dict[str, dict[str, float]] = {}

    def build_baseline(self, alerts: list[OCSFAlert]) -> dict[str, dict[str, float]]:
        """Build behavioral baseline from historical alerts."""
        # Feature extraction
        features: dict[str, list[float]] = defaultdict(list)

        # Count events per source IP
        src_counts = Counter(a.src_ip for a in alerts if a.src_ip)
        features["events_per_source"] = list(src_counts.values())

        # Count unique destinations per source
        dst_per_src: dict[str, set[str]] = defaultdict(set)
        for alert in alerts:
            if alert.src_ip and alert.dst_ip:
                dst_per_src[alert.src_ip].add(alert.dst_ip)
        features["unique_dsts_per_source"] = [len(v) for v in dst_per_src.values()]

        # Port diversity
        port_per_src: dict[str, set[int]] = defaultdict(set)
        for alert in alerts:
            if alert.src_ip and alert.dst_port:
                port_per_src[alert.src_ip].add(alert.dst_port)
        features["unique_ports_per_source"] = [len(v) for v in port_per_src.values()]

        # Severity distribution
        features["severity_values"] = [float(a.severity.value) for a in alerts]

        # Compute statistics
        baselines: dict[str, dict[str, float]] = {}
        for name, values in features.items():
            if not values:
                continue
            if HAS_NUMPY:
                arr = np.array(values, dtype=float)
                baselines[name] = {
                    "mean": float(np.mean(arr)),
                    "std": float(np.std(arr)),
                    "median": float(np.median(arr)),
                    "min": float(np.min(arr)),
                    "max": float(np.max(arr)),
                    "count": len(values),
                }
            else:
                mean = sum(values) / len(values)
                variance = sum((x - mean) ** 2 for x in values) / len(values)
                std = math.sqrt(variance)
                sorted_vals = sorted(values)
                mid = len(sorted_vals) // 2
                median = sorted_vals[mid] if len(sorted_vals) % 2 else (sorted_vals[mid - 1] + sorted_vals[mid]) / 2
                baselines[name] = {
                    "mean": mean,
                    "std": std,
                    "median": median,
                    "min": min(values),
                    "max": max(values),
                    "count": len(values),
                }

        self._baselines = baselines
        return baselines

    def detect_anomalies(self, alerts: list[OCSFAlert]) -> list[dict[str, Any]]:
        """Detect anomalies in alerts compared to baseline."""
        if not self._baselines:
            self.build_baseline(alerts)

        anomalies: list[dict[str, Any]] = []

        # Check per-source event counts
        src_counts = Counter(a.src_ip for a in alerts if a.src_ip)
        baseline = self._baselines.get("events_per_source", {})
        if baseline:
            std = baseline.get("std", 0)
            mean = baseline.get("mean", 0)
            for ip, count in src_counts.items():
                if std > 0:
                    z_score = (count - mean) / std
                elif mean > 0 and count > mean * 3:
                    # If std is 0 (uniform baseline), flag anything significantly above mean
                    z_score = (count - mean) / max(mean, 1)
                else:
                    continue
                if z_score > self.z_threshold:
                    anomalies.append({
                        "type": "frequency_anomaly",
                        "entity": ip,
                        "metric": "events_per_source",
                        "value": count,
                        "baseline_mean": round(mean, 2),
                        "z_score": round(z_score, 2),
                        "severity": "high" if z_score > 4 else "medium",
                    })

        # Check destination diversity
        dst_per_src: dict[str, set[str]] = defaultdict(set)
        for alert in alerts:
            if alert.src_ip and alert.dst_ip:
                dst_per_src[alert.src_ip].add(alert.dst_ip)
        baseline = self._baselines.get("unique_dsts_per_source", {})
        if baseline:
            std = baseline.get("std", 0)
            mean = baseline.get("mean", 0)
            for ip, dsts in dst_per_src.items():
                if std > 0:
                    z_score = (len(dsts) - mean) / std
                elif mean > 0 and len(dsts) > mean * 3:
                    z_score = (len(dsts) - mean) / max(mean, 1)
                else:
                    continue
                if z_score > self.z_threshold:
                    anomalies.append({
                        "type": "fan_out_anomaly",
                        "entity": ip,
                        "metric": "unique_destinations",
                        "value": len(dsts),
                        "baseline_mean": round(baseline["mean"], 2),
                        "z_score": round(z_score, 2),
                        "severity": "high",
                    })

        return anomalies

    @property
    def baselines(self) -> dict[str, dict[str, float]]:
        return dict(self._baselines)
