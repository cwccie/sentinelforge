"""
OCSF-aligned schema definitions for SentinelForge.

Open Cybersecurity Schema Framework (OCSF) normalization ensures all alerts,
regardless of source format, are represented in a consistent structure for
triage, correlation, and investigation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any


class Severity(IntEnum):
    """Alert severity levels aligned with OCSF severity_id."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AlertStatus(str, Enum):
    """Lifecycle status of an alert."""
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CORRELATED = "correlated"
    ESCALATED = "escalated"
    REMEDIATED = "remediated"
    CLOSED = "closed"
    AUTO_CLOSED = "auto_closed"


class Verdict(str, Enum):
    """Triage verdict."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass
class OCSFAlert:
    """
    Normalized alert in OCSF-aligned format.

    Every ingested log/alert is converted to this structure before entering
    the triage pipeline.
    """
    # Identity
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Classification
    severity: Severity = Severity.MEDIUM
    category: str = ""
    class_name: str = ""
    activity: str = ""

    # Source context
    source_format: str = ""
    raw_log: str = ""

    # Network fields
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""

    # Identity fields
    username: str = ""
    hostname: str = ""
    domain: str = ""
    process_name: str = ""

    # Enrichment
    geo_src: dict[str, Any] = field(default_factory=dict)
    geo_dst: dict[str, Any] = field(default_factory=dict)
    threat_intel: dict[str, Any] = field(default_factory=dict)
    asset_context: dict[str, Any] = field(default_factory=dict)

    # ATT&CK mapping
    mitre_tactic: str = ""
    mitre_technique: str = ""
    mitre_technique_id: str = ""

    # Triage results
    status: AlertStatus = AlertStatus.NEW
    verdict: Verdict = Verdict.UNKNOWN
    confidence: float = 0.0
    triage_reason: str = ""

    # Correlation
    incident_id: str = ""
    related_alerts: list[str] = field(default_factory=list)

    # Metadata
    tags: list[str] = field(default_factory=list)
    enrichments: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "severity": self.severity.name,
            "severity_id": self.severity.value,
            "category": self.category,
            "class_name": self.class_name,
            "activity": self.activity,
            "source_format": self.source_format,
            "raw_log": self.raw_log,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "username": self.username,
            "hostname": self.hostname,
            "domain": self.domain,
            "process_name": self.process_name,
            "geo_src": self.geo_src,
            "geo_dst": self.geo_dst,
            "threat_intel": self.threat_intel,
            "asset_context": self.asset_context,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_id": self.mitre_technique_id,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "triage_reason": self.triage_reason,
            "incident_id": self.incident_id,
            "related_alerts": self.related_alerts,
            "tags": self.tags,
            "enrichments": self.enrichments,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OCSFAlert:
        """Deserialize from dictionary."""
        alert = cls()
        for key, value in data.items():
            if key == "severity":
                alert.severity = Severity[value] if isinstance(value, str) else Severity(value)
            elif key == "severity_id":
                continue
            elif key == "status":
                alert.status = AlertStatus(value)
            elif key == "verdict":
                alert.verdict = Verdict(value)
            elif hasattr(alert, key):
                setattr(alert, key, value)
        return alert


@dataclass
class Incident:
    """A correlated group of alerts forming a security incident."""
    incident_id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    status: str = "open"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = ""
    alert_ids: list[str] = field(default_factory=list)
    kill_chain_phase: str = ""
    mitre_tactics: list[str] = field(default_factory=list)
    assigned_playbook: str = ""
    timeline: list[dict[str, Any]] = field(default_factory=list)
    iocs: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "alert_ids": self.alert_ids,
            "kill_chain_phase": self.kill_chain_phase,
            "mitre_tactics": self.mitre_tactics,
            "assigned_playbook": self.assigned_playbook,
            "timeline": self.timeline,
            "iocs": self.iocs,
        }
