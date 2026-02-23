"""
Playbook Engine — loads YAML playbooks and executes response actions
with HITL approval gates and execution logging.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from sentinelforge.schemas import Incident, OCSFAlert

logger = logging.getLogger("sentinelforge.playbook")


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    DENIED = "denied"


@dataclass
class PlaybookStep:
    """A single step in a playbook."""
    name: str
    action: str
    description: str = ""
    requires_approval: bool = False
    parameters: dict[str, Any] = field(default_factory=dict)
    status: StepStatus = StepStatus.PENDING
    result: str = ""
    executed_at: str = ""
    approved_by: str = ""


@dataclass
class Playbook:
    """A complete response playbook."""
    name: str
    description: str = ""
    trigger_conditions: dict[str, Any] = field(default_factory=dict)
    severity_threshold: str = "MEDIUM"
    steps: list[PlaybookStep] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Playbook:
        """Load playbook from parsed YAML dict."""
        steps = []
        for step_data in data.get("steps", []):
            steps.append(PlaybookStep(
                name=step_data.get("name", "Unnamed Step"),
                action=step_data.get("action", ""),
                description=step_data.get("description", ""),
                requires_approval=step_data.get("requires_approval", False),
                parameters=step_data.get("parameters", {}),
            ))
        return cls(
            name=data.get("name", "Unnamed Playbook"),
            description=data.get("description", ""),
            trigger_conditions=data.get("trigger_conditions", {}),
            severity_threshold=data.get("severity_threshold", "MEDIUM"),
            steps=steps,
            tags=data.get("tags", []),
        )


@dataclass
class PlaybookExecution:
    """Record of a playbook execution."""
    playbook_name: str
    incident_id: str = ""
    alert_id: str = ""
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str = ""
    status: str = "running"
    steps_completed: int = 0
    steps_total: int = 0
    log: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_name": self.playbook_name,
            "incident_id": self.incident_id,
            "alert_id": self.alert_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "steps_completed": self.steps_completed,
            "steps_total": self.steps_total,
            "log": self.log,
        }


# Simulated action handlers
_ACTION_HANDLERS: dict[str, Any] = {}


def _handler_block_ip(params: dict) -> str:
    ip = params.get("ip", params.get("source_ip", "unknown"))
    return f"[SIMULATED] Firewall rule added: BLOCK {ip} on all interfaces"


def _handler_disable_account(params: dict) -> str:
    user = params.get("username", params.get("user", "unknown"))
    return f"[SIMULATED] Account '{user}' disabled in Active Directory"


def _handler_isolate_host(params: dict) -> str:
    host = params.get("hostname", params.get("host", "unknown"))
    return f"[SIMULATED] Host '{host}' isolated from network via EDR agent"


def _handler_send_notification(params: dict) -> str:
    channel = params.get("channel", "soc-alerts")
    return f"[SIMULATED] Notification sent to #{channel}"


def _handler_collect_forensics(params: dict) -> str:
    host = params.get("hostname", params.get("host", "unknown"))
    return f"[SIMULATED] Forensic data collection initiated on '{host}': memory dump, disk image, network captures"


def _handler_scan_endpoints(params: dict) -> str:
    scope = params.get("scope", "affected_hosts")
    return f"[SIMULATED] EDR scan initiated across {scope}"


def _handler_reset_credentials(params: dict) -> str:
    user = params.get("username", params.get("user", "unknown"))
    return f"[SIMULATED] Password reset forced for '{user}', all sessions terminated"


def _handler_update_signatures(params: dict) -> str:
    sig_type = params.get("type", "IDS")
    return f"[SIMULATED] {sig_type} signatures updated with new IOCs"


def _handler_quarantine_email(params: dict) -> str:
    msg_id = params.get("message_id", "unknown")
    return f"[SIMULATED] Email {msg_id} quarantined and removed from all mailboxes"


def _handler_generic(params: dict) -> str:
    return f"[SIMULATED] Action executed with params: {params}"


_ACTION_HANDLERS = {
    "block_ip": _handler_block_ip,
    "disable_account": _handler_disable_account,
    "isolate_host": _handler_isolate_host,
    "send_notification": _handler_send_notification,
    "collect_forensics": _handler_collect_forensics,
    "scan_endpoints": _handler_scan_endpoints,
    "reset_credentials": _handler_reset_credentials,
    "update_signatures": _handler_update_signatures,
    "quarantine_email": _handler_quarantine_email,
}


class PlaybookEngine:
    """
    Executes YAML-defined playbooks with HITL approval gates.
    """

    def __init__(self, playbook_dir: str | None = None, auto_approve: bool = False) -> None:
        self.playbook_dir = playbook_dir
        self.auto_approve = auto_approve
        self._playbooks: dict[str, Playbook] = {}
        self._executions: list[PlaybookExecution] = []

        if playbook_dir:
            self.load_all()

    def load_all(self) -> int:
        """Load all YAML playbooks from the playbook directory."""
        if not self.playbook_dir or not os.path.isdir(self.playbook_dir):
            return 0
        count = 0
        for fname in os.listdir(self.playbook_dir):
            if fname.endswith((".yml", ".yaml")):
                path = os.path.join(self.playbook_dir, fname)
                pb = load_playbook(path)
                if pb:
                    self._playbooks[pb.name] = pb
                    count += 1
        return count

    def get_playbook(self, name: str) -> Playbook | None:
        return self._playbooks.get(name)

    def list_playbooks(self) -> list[str]:
        return list(self._playbooks.keys())

    def match_playbook(self, alert: OCSFAlert) -> Playbook | None:
        """Find the best matching playbook for an alert."""
        for pb in self._playbooks.values():
            tc = pb.trigger_conditions
            if tc.get("mitre_technique_id") and tc["mitre_technique_id"] == alert.mitre_technique_id:
                return pb
            if tc.get("mitre_tactic") and tc["mitre_tactic"] == alert.mitre_tactic:
                return pb
            if tc.get("category") and tc["category"] == alert.category:
                return pb
            if tc.get("tags"):
                if any(tag in alert.tags for tag in tc["tags"]):
                    return pb
        return None

    def execute(
        self,
        playbook: Playbook,
        alert: OCSFAlert | None = None,
        incident: Incident | None = None,
        context: dict[str, Any] | None = None,
    ) -> PlaybookExecution:
        """
        Execute a playbook against an alert or incident.

        Steps requiring approval will be auto-approved if auto_approve=True,
        otherwise they will be marked as awaiting_approval.
        """
        execution = PlaybookExecution(
            playbook_name=playbook.name,
            alert_id=alert.alert_id if alert else "",
            incident_id=incident.incident_id if incident else "",
            steps_total=len(playbook.steps),
        )

        # Build parameter context
        ctx = context or {}
        if alert:
            ctx.update({
                "source_ip": alert.src_ip,
                "dest_ip": alert.dst_ip,
                "username": alert.username,
                "hostname": alert.hostname,
                "severity": alert.severity.name,
                "mitre_tactic": alert.mitre_tactic,
                "mitre_technique": alert.mitre_technique,
            })

        for step in playbook.steps:
            step_log: dict[str, Any] = {
                "step": step.name,
                "action": step.action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # HITL approval gate
            if step.requires_approval and not self.auto_approve:
                step.status = StepStatus.AWAITING_APPROVAL
                step_log["status"] = "awaiting_approval"
                step_log["result"] = "Step requires human approval before execution"
                execution.log.append(step_log)
                logger.info(f"Step '{step.name}' awaiting approval")
                continue

            if step.requires_approval and self.auto_approve:
                step.status = StepStatus.APPROVED
                step.approved_by = "auto-approve"
                step_log["approved_by"] = "auto-approve"

            # Execute action
            step.status = StepStatus.RUNNING
            # Merge step params with context
            params = {**ctx, **step.parameters}
            handler = _ACTION_HANDLERS.get(step.action, _handler_generic)

            try:
                result = handler(params)
                step.status = StepStatus.COMPLETED
                step.result = result
                step.executed_at = datetime.now(timezone.utc).isoformat()
                step_log["status"] = "completed"
                step_log["result"] = result
                execution.steps_completed += 1
                logger.info(f"Step '{step.name}' completed: {result}")
            except Exception as e:
                step.status = StepStatus.FAILED
                step.result = str(e)
                step_log["status"] = "failed"
                step_log["error"] = str(e)
                logger.error(f"Step '{step.name}' failed: {e}")

            execution.log.append(step_log)

        # Finalize execution
        execution.completed_at = datetime.now(timezone.utc).isoformat()
        if execution.steps_completed == execution.steps_total:
            execution.status = "completed"
        elif any(s.status == StepStatus.AWAITING_APPROVAL for s in playbook.steps):
            execution.status = "awaiting_approval"
        elif any(s.status == StepStatus.FAILED for s in playbook.steps):
            execution.status = "partial_failure"
        else:
            execution.status = "completed"

        self._executions.append(execution)
        return execution

    @property
    def executions(self) -> list[PlaybookExecution]:
        return list(self._executions)


def load_playbook(path: str) -> Playbook | None:
    """Load a single YAML playbook from file."""
    if not HAS_YAML:
        # Fallback: basic YAML-like parsing for simple files
        return _load_playbook_fallback(path)
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        if data:
            return Playbook.from_dict(data)
    except Exception as e:
        logger.error(f"Failed to load playbook {path}: {e}")
    return None


def _load_playbook_fallback(path: str) -> Playbook | None:
    """Minimal YAML-like parser for when PyYAML is not installed."""
    try:
        with open(path) as f:
            content = f.read()
        # Very basic extraction
        name = ""
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("name:"):
                name = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                break
        if name:
            return Playbook(name=name, description=f"Loaded from {path} (no YAML parser)")
    except Exception:
        pass
    return None


def execute_playbook(
    playbook_name_or_path: str,
    alert: OCSFAlert | None = None,
    auto_approve: bool = False,
) -> PlaybookExecution | None:
    """Convenience function to load and execute a playbook."""
    pb = load_playbook(playbook_name_or_path)
    if not pb:
        return None
    engine = PlaybookEngine(auto_approve=auto_approve)
    return engine.execute(pb, alert=alert)
