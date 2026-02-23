"""
Triage Agent — pattern-based alert classification simulating LLM reasoning.

In production, this would call an LLM (GPT-4, Claude, Gemini) for nuanced
triage decisions. The mock implementation uses rule-based pattern matching
that demonstrates the same decision logic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sentinelforge.schemas import AlertStatus, OCSFAlert, Severity, Verdict


@dataclass
class TriageResult:
    """Result of triage analysis."""
    severity: Severity
    verdict: Verdict
    confidence: float
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_id: str
    reason: str
    auto_close: bool = False
    tags: list[str] | None = None


# Known benign patterns that should be auto-closed
_BENIGN_PATTERNS = [
    (r"Accepted\s+publickey\s+for\s+\S+\s+from\s+10\.", "Routine SSH login from internal host"),
    (r"session\s+opened\s+for\s+user\s+root\s+by\s+\(uid=0\)", "Expected root session from cron/systemd"),
    (r"New\s+session\s+\d+\s+of\s+user\s+\w+", "Standard session creation"),
    (r"CRON\[\d+\]", "Scheduled cron job execution"),
    (r"systemd.*Started\s+", "Standard systemd service start"),
    (r"dhclient.*bound\s+to\s+", "Normal DHCP lease renewal"),
    (r"kernel.*\[UFW\s+BLOCK\].*DST=224\.", "Multicast traffic blocked by firewall"),
    (r"nagios.*OK\s+-\s+", "Health check passing"),
    (r"zabbix.*agent", "Monitoring agent activity"),
]

# MITRE ATT&CK mapping rules
_ATTACK_RULES: list[dict[str, Any]] = [
    {
        "patterns": [r"Failed\s+password", r"authentication\s+fail", r"login\s+fail", r"invalid\s+user", r"Access\s+denied"],
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "severity_boost": True,
    },
    {
        "patterns": [r"Accepted\s+password\s+for.*from\s+(?!10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)"],
        "tactic": "Initial Access",
        "technique": "Valid Accounts",
        "technique_id": "T1078",
        "severity_boost": False,
    },
    {
        "patterns": [r"powershell.*-enc", r"cmd\.exe.*/c", r"bash\s+-c", r"python\s+-c", r"wget\s+http", r"curl\s+http.*\|\s*sh"],
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter",
        "technique_id": "T1059",
        "severity_boost": True,
    },
    {
        "patterns": [r"scheduled\s+task", r"crontab.*-e", r"at\s+\d{2}:\d{2}", r"systemd.*enable"],
        "tactic": "Persistence",
        "technique": "Scheduled Task/Job",
        "technique_id": "T1053",
        "severity_boost": False,
    },
    {
        "patterns": [r"sudo\s+", r"su\s+-\s+root", r"privilege.*escalat", r"setuid", r"CVE-\d{4}-\d+"],
        "tactic": "Privilege Escalation",
        "technique": "Exploitation for Privilege Escalation",
        "technique_id": "T1068",
        "severity_boost": True,
    },
    {
        "patterns": [r"clear.*history", r"rm\s+-rf.*/var/log", r"shred", r"wevtutil.*cl"],
        "tactic": "Defense Evasion",
        "technique": "Indicator Removal",
        "technique_id": "T1070",
        "severity_boost": True,
    },
    {
        "patterns": [r"mimikatz", r"lsass", r"hashdump", r"credential.*dump", r"SAM\s+database"],
        "tactic": "Credential Access",
        "technique": "OS Credential Dumping",
        "technique_id": "T1003",
        "severity_boost": True,
    },
    {
        "patterns": [r"nmap\s+", r"port\s*scan", r"net\s+view", r"arp\s+-a", r"enum4linux", r"ldapsearch"],
        "tactic": "Discovery",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
        "severity_boost": False,
    },
    {
        "patterns": [r"psexec", r"wmic\s+/node", r"smbclient", r"lateral.*move", r"pass.the.hash"],
        "tactic": "Lateral Movement",
        "technique": "Remote Services",
        "technique_id": "T1021",
        "severity_boost": True,
    },
    {
        "patterns": [r"exfiltrat", r"upload.*\d+[MG]B", r"base64.*encode", r"dns.*tunnel", r"\.onion"],
        "tactic": "Exfiltration",
        "technique": "Exfiltration Over C2 Channel",
        "technique_id": "T1041",
        "severity_boost": True,
    },
    {
        "patterns": [r"encrypt", r"ransom", r"\.locked", r"bitcoin.*wallet", r"your\s+files"],
        "tactic": "Impact",
        "technique": "Data Encrypted for Impact",
        "technique_id": "T1486",
        "severity_boost": True,
    },
    {
        "patterns": [r"C2\s+", r"beacon", r"cobalt.*strike", r"command.*control", r"callback"],
        "tactic": "Command and Control",
        "technique": "Application Layer Protocol",
        "technique_id": "T1071",
        "severity_boost": True,
    },
    {
        "patterns": [r"phish", r"spear.*phish", r"malicious.*link", r"suspicious.*attachment"],
        "tactic": "Initial Access",
        "technique": "Phishing",
        "technique_id": "T1566",
        "severity_boost": True,
    },
    {
        "patterns": [r"dns.*query.*\b[a-z0-9]{30,}\.", r"nxdomain", r"dga", r"domain.*generat"],
        "tactic": "Command and Control",
        "technique": "DNS",
        "technique_id": "T1071.004",
        "severity_boost": True,
    },
]


class TriageAgent:
    """
    AI-driven alert triage agent.

    Analyzes normalized alerts and produces severity classification,
    MITRE ATT&CK mapping, confidence scores, and auto-close decisions.
    """

    def __init__(self) -> None:
        self.benign_patterns = [(re.compile(p, re.IGNORECASE), reason) for p, reason in _BENIGN_PATTERNS]
        self.attack_rules = _ATTACK_RULES
        self._triage_count = 0

    def triage(self, alert: OCSFAlert) -> TriageResult:
        """
        Perform triage analysis on an alert.

        Returns a TriageResult with severity, verdict, ATT&CK mapping,
        and auto-close recommendation.
        """
        self._triage_count += 1
        text = f"{alert.activity} {alert.class_name} {alert.raw_log}"

        # Step 1: Check for known benign patterns
        for pattern, reason in self.benign_patterns:
            if pattern.search(text):
                return TriageResult(
                    severity=Severity.INFO,
                    verdict=Verdict.BENIGN,
                    confidence=0.95,
                    mitre_tactic="",
                    mitre_technique="",
                    mitre_technique_id="",
                    reason=f"Auto-close: {reason}",
                    auto_close=True,
                    tags=["auto-closed", "benign"],
                )

        # Step 2: MITRE ATT&CK matching
        best_match = None
        best_match_count = 0
        for rule in self.attack_rules:
            match_count = 0
            for pattern_str in rule["patterns"]:
                if re.search(pattern_str, text, re.IGNORECASE):
                    match_count += 1
            if match_count > best_match_count:
                best_match = rule
                best_match_count = match_count

        # Step 3: Calculate severity and confidence
        severity = alert.severity
        confidence = 0.5
        tags = []

        if best_match and best_match_count > 0:
            confidence = min(0.95, 0.5 + (best_match_count * 0.15))
            if best_match.get("severity_boost") and severity < Severity.HIGH:
                severity = Severity(min(severity.value + 1, Severity.CRITICAL.value))

        # Boost from threat intel
        if alert.threat_intel.get("max_confidence", 0) > 0.7:
            confidence = min(0.98, confidence + 0.2)
            if severity < Severity.HIGH:
                severity = Severity.HIGH
            tags.append("threat-intel-match")

        # Boost for critical assets
        if "critical-asset" in alert.tags:
            if severity < Severity.HIGH:
                severity = Severity(min(severity.value + 1, Severity.CRITICAL.value))
            tags.append("critical-asset-involved")

        # Step 4: Determine verdict
        if severity >= Severity.HIGH:
            verdict = Verdict.MALICIOUS
        elif severity == Severity.MEDIUM:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.BENIGN if confidence > 0.8 else Verdict.UNKNOWN

        # Build reason
        reason_parts = []
        if best_match:
            reason_parts.append(f"ATT&CK match: {best_match['tactic']} / {best_match['technique']}")
        if alert.threat_intel.get("matches"):
            reason_parts.append(f"Threat intel hit: {alert.threat_intel['threat_types']}")
        if "critical-asset" in alert.tags:
            reason_parts.append("Critical asset involved")
        if not reason_parts:
            reason_parts.append(f"Pattern analysis: severity={severity.name}")

        return TriageResult(
            severity=severity,
            verdict=verdict,
            confidence=round(confidence, 3),
            mitre_tactic=best_match["tactic"] if best_match else "",
            mitre_technique=best_match["technique"] if best_match else "",
            mitre_technique_id=best_match["technique_id"] if best_match else "",
            reason="; ".join(reason_parts),
            auto_close=False,
            tags=tags,
        )

    def apply_triage(self, alert: OCSFAlert) -> OCSFAlert:
        """Triage an alert and update it in-place with results."""
        result = self.triage(alert)
        alert.severity = result.severity
        alert.verdict = result.verdict
        alert.confidence = result.confidence
        alert.mitre_tactic = result.mitre_tactic
        alert.mitre_technique = result.mitre_technique
        alert.mitre_technique_id = result.mitre_technique_id
        alert.triage_reason = result.reason
        alert.tags.extend(result.tags or [])

        if result.auto_close:
            alert.status = AlertStatus.AUTO_CLOSED
        else:
            alert.status = AlertStatus.TRIAGED

        return alert

    @property
    def triage_count(self) -> int:
        return self._triage_count


# Module-level convenience
_default_agent = TriageAgent()


def triage_alert(alert: OCSFAlert) -> OCSFAlert:
    """Triage an alert using the default agent."""
    return _default_agent.apply_triage(alert)
