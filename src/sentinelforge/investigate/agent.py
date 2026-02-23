"""
Investigation Agent — collects evidence, extracts IOCs, detects lateral movement,
and reconstructs attack timelines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sentinelforge.schemas import OCSFAlert, Severity
from sentinelforge.store import alert_store


@dataclass
class IOC:
    """Indicator of Compromise."""
    ioc_type: str  # ip, domain, hash, url, email, filename
    value: str
    context: str = ""
    confidence: float = 0.0
    source_alert_id: str = ""


@dataclass
class InvestigationReport:
    """Complete investigation report for an alert or incident."""
    alert_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    iocs: list[IOC] = field(default_factory=list)
    related_alerts: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    lateral_movement_detected: bool = False
    lateral_movement_evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "iocs": [{"type": i.ioc_type, "value": i.value, "context": i.context, "confidence": i.confidence} for i in self.iocs],
            "related_alerts": self.related_alerts,
            "timeline": self.timeline,
            "lateral_movement_detected": self.lateral_movement_detected,
            "lateral_movement_evidence": self.lateral_movement_evidence,
            "recommendations": self.recommendations,
            "risk_score": self.risk_score,
        }


class InvestigationAgent:
    """
    Automated investigation agent.

    Performs evidence collection, IOC extraction, lateral movement detection,
    and timeline reconstruction for triaged alerts.
    """

    # Regex patterns for IOC extraction
    _IP_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
    _DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|onion|tk)\b")
    _MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
    _SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
    _SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
    _URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")
    _EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

    # Known internal/safe patterns to exclude
    _SAFE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
    _SAFE_DOMAINS = {"localhost", "example.com", "example.org", "example.net"}

    def investigate(self, alert: OCSFAlert) -> InvestigationReport:
        """Run full investigation on an alert."""
        report = InvestigationReport(alert_id=alert.alert_id)

        # Step 1: Extract IOCs from all text fields
        text_sources = [alert.raw_log, alert.activity, alert.class_name]
        for text in text_sources:
            if text:
                report.iocs.extend(self._extract_iocs(text, alert.alert_id))

        # Add known IPs from alert fields
        for ip in [alert.src_ip, alert.dst_ip]:
            if ip and ip not in self._SAFE_IPS:
                report.iocs.append(IOC(
                    ioc_type="ip",
                    value=ip,
                    context="Alert source/destination",
                    confidence=0.7,
                    source_alert_id=alert.alert_id,
                ))

        # Deduplicate IOCs
        seen = set()
        unique_iocs = []
        for ioc in report.iocs:
            key = (ioc.ioc_type, ioc.value)
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        report.iocs = unique_iocs

        # Step 2: Find related alerts
        report.related_alerts = self._find_related(alert)

        # Step 3: Build timeline
        report.timeline = self._build_timeline(alert, report.related_alerts)

        # Step 4: Detect lateral movement
        lm_detected, lm_evidence = self._detect_lateral_movement(alert, report.related_alerts)
        report.lateral_movement_detected = lm_detected
        report.lateral_movement_evidence = lm_evidence

        # Step 5: Calculate risk score
        report.risk_score = self._calculate_risk(alert, report)

        # Step 6: Generate recommendations
        report.recommendations = self._generate_recommendations(alert, report)

        return report

    def _extract_iocs(self, text: str, alert_id: str) -> list[IOC]:
        """Extract all IOCs from text."""
        iocs: list[IOC] = []

        for match in self._IP_PATTERN.finditer(text):
            ip = match.group()
            if ip not in self._SAFE_IPS:
                iocs.append(IOC("ip", ip, "Extracted from log", 0.6, alert_id))

        for match in self._DOMAIN_PATTERN.finditer(text):
            domain = match.group().lower()
            if domain not in self._SAFE_DOMAINS:
                iocs.append(IOC("domain", domain, "Extracted from log", 0.5, alert_id))

        for match in self._SHA256_PATTERN.finditer(text):
            iocs.append(IOC("sha256", match.group(), "Hash found in log", 0.8, alert_id))

        for match in self._SHA1_PATTERN.finditer(text):
            if not self._SHA256_PATTERN.search(text):
                iocs.append(IOC("sha1", match.group(), "Hash found in log", 0.7, alert_id))

        for match in self._MD5_PATTERN.finditer(text):
            if not self._SHA1_PATTERN.search(text) and not self._SHA256_PATTERN.search(text):
                iocs.append(IOC("md5", match.group(), "Hash found in log", 0.6, alert_id))

        for match in self._URL_PATTERN.finditer(text):
            iocs.append(IOC("url", match.group(), "URL found in log", 0.7, alert_id))

        for match in self._EMAIL_PATTERN.finditer(text):
            iocs.append(IOC("email", match.group(), "Email found in log", 0.5, alert_id))

        return iocs

    def _find_related(self, alert: OCSFAlert) -> list[str]:
        """Find related alerts by shared attributes."""
        related = []
        all_alerts = alert_store.list_all(limit=500)

        for other in all_alerts:
            if other.alert_id == alert.alert_id:
                continue
            # Related if sharing IPs, usernames, or hostnames
            shared = False
            if alert.src_ip and alert.src_ip == other.src_ip:
                shared = True
            if alert.dst_ip and alert.dst_ip == other.dst_ip:
                shared = True
            if alert.username and alert.username == other.username:
                shared = True
            if alert.hostname and alert.hostname == other.hostname:
                shared = True
            if shared:
                related.append(other.alert_id)

        return related[:20]  # Cap at 20

    def _build_timeline(self, alert: OCSFAlert, related_ids: list[str]) -> list[dict[str, Any]]:
        """Build chronological timeline of the alert and related events."""
        events = [{"timestamp": alert.timestamp, "alert_id": alert.alert_id, "activity": alert.activity, "severity": alert.severity.name}]
        for rid in related_ids:
            related = alert_store.get(rid)
            if related:
                events.append({
                    "timestamp": related.timestamp,
                    "alert_id": related.alert_id,
                    "activity": related.activity,
                    "severity": related.severity.name,
                })
        return sorted(events, key=lambda e: e["timestamp"])

    def _detect_lateral_movement(self, alert: OCSFAlert, related_ids: list[str]) -> tuple[bool, list[str]]:
        """Detect signs of lateral movement across related alerts."""
        evidence = []
        all_src_ips = {alert.src_ip} if alert.src_ip else set()
        all_dst_ips = {alert.dst_ip} if alert.dst_ip else set()

        for rid in related_ids:
            related = alert_store.get(rid)
            if related:
                if related.src_ip:
                    all_src_ips.add(related.src_ip)
                if related.dst_ip:
                    all_dst_ips.add(related.dst_ip)

        # Lateral movement indicator: same source hitting multiple destinations
        internal_dsts = {ip for ip in all_dst_ips if ip and _is_internal(ip)}
        if len(internal_dsts) > 2:
            evidence.append(f"Single source contacting {len(internal_dsts)} internal hosts: {', '.join(list(internal_dsts)[:5])}")

        # Source IP appearing as destination in later alerts
        pivot_ips = all_src_ips & all_dst_ips
        if pivot_ips:
            evidence.append(f"Potential pivot points (src/dst overlap): {', '.join(pivot_ips)}")

        # Check for lateral movement techniques in activity text
        lm_keywords = ["psexec", "wmic", "lateral", "smbclient", "remote exec", "pass the hash", "rdp"]
        text = f"{alert.activity} {alert.raw_log}".lower()
        for kw in lm_keywords:
            if kw in text:
                evidence.append(f"Lateral movement keyword detected: '{kw}'")

        return bool(evidence), evidence

    def _calculate_risk(self, alert: OCSFAlert, report: InvestigationReport) -> float:
        """Calculate composite risk score (0.0-10.0)."""
        score = 0.0

        # Base severity
        severity_scores = {Severity.INFO: 1, Severity.LOW: 2, Severity.MEDIUM: 4, Severity.HIGH: 6, Severity.CRITICAL: 8}
        score += severity_scores.get(alert.severity, 4)

        # IOC count bonus
        score += min(len(report.iocs) * 0.2, 1.0)

        # Lateral movement
        if report.lateral_movement_detected:
            score += 1.5

        # Threat intel
        if alert.threat_intel.get("max_confidence", 0) > 0.7:
            score += 1.0

        # Critical asset
        if "critical-asset" in alert.tags:
            score += 1.0

        return min(round(score, 1), 10.0)

    def _generate_recommendations(self, alert: OCSFAlert, report: InvestigationReport) -> list[str]:
        """Generate actionable recommendations based on investigation findings."""
        recs = []

        if report.risk_score >= 8:
            recs.append("IMMEDIATE: Isolate affected hosts and initiate incident response")
        elif report.risk_score >= 6:
            recs.append("URGENT: Escalate to senior analyst for manual review")

        if report.lateral_movement_detected:
            recs.append("Investigate all pivot point hosts for compromise indicators")
            recs.append("Review network segmentation to limit lateral movement paths")

        if alert.threat_intel.get("matches"):
            recs.append("Block identified malicious IPs at perimeter firewall")
            recs.append("Search historical logs for additional connections to threat intel IOCs")

        if alert.mitre_technique_id == "T1110":
            recs.append("Review account lockout policies and enforce MFA")
            recs.append("Check if brute-forced credentials were successful in any session")

        if alert.mitre_technique_id == "T1003":
            recs.append("Reset credentials for all accounts on affected systems")
            recs.append("Deploy Credential Guard or LSA protection")

        if alert.mitre_technique_id in ("T1041", "T1048"):
            recs.append("Review DLP policies for data classification gaps")
            recs.append("Quantify potential data exposure and initiate breach assessment")

        for ioc in report.iocs:
            if ioc.ioc_type == "domain" and ioc.value.endswith(".onion"):
                recs.append(f"Block Tor exit nodes and investigate .onion domain: {ioc.value}")

        if not recs:
            recs.append("Continue monitoring — no immediate action required")
            recs.append("Add alert context to threat hunting hypotheses")

        return recs


# Module-level convenience
_default_agent = InvestigationAgent()


def investigate_alert(alert: OCSFAlert) -> InvestigationReport:
    """Investigate an alert using the default agent."""
    return _default_agent.investigate(alert)


def _is_internal(ip: str) -> bool:
    """Check if IP is RFC 1918 private."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
