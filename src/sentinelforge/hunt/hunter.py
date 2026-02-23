"""
Threat Hunter — query builder for hunt hypotheses, behavioral baseline
comparison, and anomaly scoring.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sentinelforge.schemas import OCSFAlert, Severity
from sentinelforge.store import alert_store


@dataclass
class HuntHypothesis:
    """A threat hunting hypothesis with search criteria."""
    name: str
    description: str
    mitre_technique_id: str = ""
    query: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)


@dataclass
class HuntResult:
    """Results of a hunt execution."""
    hypothesis: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    matches: list[dict[str, Any]] = field(default_factory=list)
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    match_count: int = 0
    anomaly_score: float = 0.0
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis": self.hypothesis,
            "timestamp": self.timestamp,
            "match_count": self.match_count,
            "anomaly_score": self.anomaly_score,
            "matches": self.matches[:20],
            "anomalies": self.anomalies[:10],
            "summary": self.summary,
        }


# Built-in hunt hypotheses
HUNT_HYPOTHESES: list[HuntHypothesis] = [
    HuntHypothesis(
        name="brute_force_detection",
        description="Detect brute force attacks — multiple failed logins from same source",
        mitre_technique_id="T1110",
        query={"category": "Authentication", "activity_pattern": r"fail|denied|invalid"},
        tags=["brute-force", "credential-access"],
    ),
    HuntHypothesis(
        name="lateral_movement_smb",
        description="Detect lateral movement via SMB/admin shares",
        mitre_technique_id="T1021.002",
        query={"dst_port": 445, "activity_pattern": r"smb|admin\$|ipc\$|c\$"},
        tags=["lateral-movement", "smb"],
    ),
    HuntHypothesis(
        name="data_exfiltration",
        description="Detect potential data exfiltration — large outbound transfers or unusual protocols",
        mitre_technique_id="T1041",
        query={"activity_pattern": r"exfil|upload|transfer|dns.*tunnel|large.*transfer"},
        tags=["exfiltration", "data-loss"],
    ),
    HuntHypothesis(
        name="command_and_control_beaconing",
        description="Detect C2 beaconing — regular interval connections to external hosts",
        mitre_technique_id="T1071",
        query={"activity_pattern": r"beacon|C2|callback|command.*control"},
        tags=["c2", "beaconing"],
    ),
    HuntHypothesis(
        name="privilege_escalation",
        description="Detect privilege escalation attempts",
        mitre_technique_id="T1068",
        query={"category": "Privilege Escalation", "activity_pattern": r"sudo|su\s|setuid|privilege|escalat|CVE-"},
        tags=["privesc"],
    ),
    HuntHypothesis(
        name="defense_evasion_log_clearing",
        description="Detect log clearing or timestomping",
        mitre_technique_id="T1070",
        query={"activity_pattern": r"clear.*log|rm.*log|wevtutil.*cl|shred|timestomp"},
        tags=["defense-evasion", "anti-forensics"],
    ),
    HuntHypothesis(
        name="suspicious_dns",
        description="Detect suspicious DNS queries — DGA domains, high-entropy names",
        mitre_technique_id="T1071.004",
        query={"category": "DNS Activity", "activity_pattern": r"nxdomain|dga|\.tk$|\.xyz$|[a-z0-9]{20,}\."},
        tags=["dns", "dga"],
    ),
    HuntHypothesis(
        name="unusual_process_execution",
        description="Detect unusual process execution — encoded commands, living off the land",
        mitre_technique_id="T1059",
        query={"activity_pattern": r"powershell.*-enc|certutil.*decode|mshta|regsvr32|rundll32"},
        tags=["execution", "lolbin"],
    ),
]


class ThreatHunter:
    """
    Proactive threat hunting engine.

    Executes hunt hypotheses against stored alerts, performs behavioral
    baseline analysis, and scores anomalies.
    """

    def __init__(self) -> None:
        self.hypotheses = list(HUNT_HYPOTHESES)
        self._hunt_count = 0

    def add_hypothesis(self, hypothesis: HuntHypothesis) -> None:
        """Add a custom hunt hypothesis."""
        self.hypotheses.append(hypothesis)

    def hunt_all(self) -> list[HuntResult]:
        """Execute all hunt hypotheses."""
        results = []
        for hyp in self.hypotheses:
            result = self.execute_hunt(hyp)
            if result.match_count > 0:
                results.append(result)
        return results

    def execute_hunt(self, hypothesis: HuntHypothesis) -> HuntResult:
        """Execute a single hunt hypothesis against stored alerts."""
        self._hunt_count += 1
        alerts = alert_store.list_all(limit=1000)
        result = HuntResult(hypothesis=hypothesis.name)

        query = hypothesis.query
        activity_pattern = query.get("activity_pattern", "")
        matches: list[OCSFAlert] = []

        for alert in alerts:
            match = True
            # Check category
            if query.get("category") and alert.category != query["category"]:
                match = False
            # Check dst_port
            if query.get("dst_port") and alert.dst_port != query["dst_port"]:
                match = False
            # Check activity pattern
            if activity_pattern:
                text = f"{alert.activity} {alert.class_name} {alert.raw_log}"
                if not re.search(activity_pattern, text, re.IGNORECASE):
                    match = False
            if match:
                matches.append(alert)

        result.match_count = len(matches)
        result.matches = [
            {
                "alert_id": a.alert_id,
                "timestamp": a.timestamp,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "username": a.username,
                "severity": a.severity.name,
                "activity": a.activity[:100],
            }
            for a in matches
        ]

        # Anomaly detection
        if matches:
            result.anomalies = self._detect_anomalies(matches, hypothesis)
            result.anomaly_score = self._calculate_anomaly_score(matches, result.anomalies)

        # Build summary
        result.summary = self._build_summary(hypothesis, result)

        return result

    def _detect_anomalies(self, alerts: list[OCSFAlert], hypothesis: HuntHypothesis) -> list[dict[str, Any]]:
        """Detect anomalies within matched alerts."""
        anomalies: list[dict[str, Any]] = []

        # Anomaly 1: Frequency spike — too many events from one source
        src_counts = Counter(a.src_ip for a in alerts if a.src_ip)
        for ip, count in src_counts.most_common(5):
            if count >= 5:
                anomalies.append({
                    "type": "frequency_spike",
                    "description": f"Source IP {ip} generated {count} matching alerts",
                    "entity": ip,
                    "count": count,
                    "severity": "high" if count >= 10 else "medium",
                })

        # Anomaly 2: Off-hours activity
        for alert in alerts:
            try:
                if "T" in alert.timestamp:
                    hour = int(alert.timestamp.split("T")[1][:2])
                    if hour < 6 or hour > 22:
                        anomalies.append({
                            "type": "off_hours",
                            "description": f"Activity at unusual hour ({hour}:00 UTC)",
                            "entity": alert.src_ip or alert.username,
                            "alert_id": alert.alert_id,
                            "severity": "medium",
                        })
            except (IndexError, ValueError):
                pass

        # Anomaly 3: Multi-host targeting (lateral movement indicator)
        if hypothesis.name in ("lateral_movement_smb", "brute_force_detection"):
            dst_per_src: dict[str, set[str]] = defaultdict(set)
            for alert in alerts:
                if alert.src_ip and alert.dst_ip:
                    dst_per_src[alert.src_ip].add(alert.dst_ip)
            for src_ip, destinations in dst_per_src.items():
                if len(destinations) >= 3:
                    anomalies.append({
                        "type": "multi_target",
                        "description": f"Source {src_ip} targeting {len(destinations)} unique destinations",
                        "entity": src_ip,
                        "targets": list(destinations)[:10],
                        "severity": "high",
                    })

        return anomalies

    def _calculate_anomaly_score(self, alerts: list[OCSFAlert], anomalies: list[dict[str, Any]]) -> float:
        """Calculate anomaly score (0.0-10.0)."""
        score = 0.0

        # Base from match count
        score += min(len(alerts) * 0.5, 3.0)

        # From anomalies
        for anomaly in anomalies:
            if anomaly["severity"] == "high":
                score += 2.0
            elif anomaly["severity"] == "medium":
                score += 1.0
            else:
                score += 0.5

        return min(round(score, 1), 10.0)

    def _build_summary(self, hypothesis: HuntHypothesis, result: HuntResult) -> str:
        """Build human-readable hunt summary."""
        if result.match_count == 0:
            return f"Hunt '{hypothesis.name}' — No matches found. Hypothesis not confirmed."

        severity_word = "LOW"
        if result.anomaly_score >= 7:
            severity_word = "CRITICAL"
        elif result.anomaly_score >= 5:
            severity_word = "HIGH"
        elif result.anomaly_score >= 3:
            severity_word = "MEDIUM"

        summary = (
            f"Hunt '{hypothesis.name}' — {result.match_count} matches, "
            f"{len(result.anomalies)} anomalies detected. "
            f"Risk level: {severity_word} (score: {result.anomaly_score}/10). "
            f"Description: {hypothesis.description}"
        )
        return summary

    @property
    def hunt_count(self) -> int:
        return self._hunt_count


# Module-level convenience
_default_hunter = ThreatHunter()


def hunt(hypothesis_name: str | None = None) -> list[HuntResult]:
    """Run threat hunts. If name provided, run only that hypothesis."""
    if hypothesis_name:
        for hyp in _default_hunter.hypotheses:
            if hyp.name == hypothesis_name:
                result = _default_hunter.execute_hunt(hyp)
                return [result] if result.match_count > 0 else []
        return []
    return _default_hunter.hunt_all()
