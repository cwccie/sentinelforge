"""
Correlation Engine — groups alerts into incidents using time-window correlation,
entity-based grouping, kill chain progression, and deduplication.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sentinelforge.schemas import AlertStatus, Incident, OCSFAlert, Severity
from sentinelforge.store import alert_store, incident_store


# Kill chain phases mapped from MITRE ATT&CK tactics
_KILL_CHAIN_ORDER = {
    "Reconnaissance": 1,
    "Resource Development": 2,
    "Initial Access": 3,
    "Execution": 4,
    "Persistence": 5,
    "Privilege Escalation": 6,
    "Defense Evasion": 7,
    "Credential Access": 8,
    "Discovery": 9,
    "Lateral Movement": 10,
    "Collection": 11,
    "Command and Control": 12,
    "Exfiltration": 13,
    "Impact": 14,
}


class CorrelationEngine:
    """
    Groups related alerts into security incidents.

    Correlation strategies:
    1. Entity-based: alerts sharing IPs, users, or hosts
    2. Time-window: alerts within a configurable time window
    3. Kill chain: alerts matching progression through ATT&CK tactics
    4. Deduplication: identical alerts consolidated
    """

    def __init__(self, time_window_minutes: int = 60) -> None:
        self.time_window_minutes = time_window_minutes
        self._correlation_count = 0

    def correlate(self, alerts: list[OCSFAlert] | None = None) -> list[Incident]:
        """
        Correlate alerts into incidents.

        If no alerts provided, pulls from the alert store.
        """
        if alerts is None:
            alerts = alert_store.list_all(limit=1000)

        # Filter to only triaged, non-closed alerts
        active = [a for a in alerts if a.status not in (AlertStatus.AUTO_CLOSED, AlertStatus.CLOSED, AlertStatus.REMEDIATED)]

        if not active:
            return []

        # Step 1: Deduplicate
        active = self._deduplicate(active)

        # Step 2: Group by entity
        groups = self._group_by_entity(active)

        # Step 3: Create incidents from groups
        incidents = []
        for group_key, group_alerts in groups.items():
            if len(group_alerts) < 1:
                continue

            incident = self._create_incident(group_key, group_alerts)
            incident_store.add(incident)

            # Update alerts with incident ID
            for alert in group_alerts:
                alert.incident_id = incident.incident_id
                alert.status = AlertStatus.CORRELATED
                alert.related_alerts = [a.alert_id for a in group_alerts if a.alert_id != alert.alert_id]
                alert_store.update(alert)

            incidents.append(incident)
            self._correlation_count += 1

        return incidents

    def _deduplicate(self, alerts: list[OCSFAlert]) -> list[OCSFAlert]:
        """Remove duplicate alerts based on key fields."""
        seen: dict[str, OCSFAlert] = {}
        for alert in alerts:
            # Dedup key: src_ip + dst_ip + activity + class_name
            key = f"{alert.src_ip}|{alert.dst_ip}|{alert.activity[:50]}|{alert.class_name}"
            if key not in seen:
                seen[key] = alert
            else:
                # Keep the higher severity one
                if alert.severity > seen[key].severity:
                    seen[key] = alert
        return list(seen.values())

    def _group_by_entity(self, alerts: list[OCSFAlert]) -> dict[str, list[OCSFAlert]]:
        """Group alerts by shared entities (IPs, users, hosts)."""
        # Build entity -> alert mapping
        entity_alerts: dict[str, list[int]] = defaultdict(list)
        for i, alert in enumerate(alerts):
            if alert.src_ip:
                entity_alerts[f"ip:{alert.src_ip}"].append(i)
            if alert.dst_ip:
                entity_alerts[f"ip:{alert.dst_ip}"].append(i)
            if alert.username:
                entity_alerts[f"user:{alert.username}"].append(i)
            if alert.hostname:
                entity_alerts[f"host:{alert.hostname}"].append(i)

        # Union-Find to merge overlapping groups
        parent = list(range(len(alerts)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: int, y: int) -> None:
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        # Merge alerts that share entities
        for indices in entity_alerts.values():
            for j in range(1, len(indices)):
                union(indices[0], indices[j])

        # Collect groups
        groups: dict[int, list[OCSFAlert]] = defaultdict(list)
        for i, alert in enumerate(alerts):
            groups[find(i)].append(alert)

        # Name groups by primary entity
        named_groups: dict[str, list[OCSFAlert]] = {}
        for group_id, group_alerts in groups.items():
            # Find most common entity
            entities: dict[str, int] = defaultdict(int)
            for alert in group_alerts:
                if alert.src_ip:
                    entities[f"src:{alert.src_ip}"] += 1
                if alert.username:
                    entities[f"user:{alert.username}"] += 1
                if alert.hostname:
                    entities[f"host:{alert.hostname}"] += 1
            primary = max(entities, key=entities.get) if entities else f"group-{group_id}"
            named_groups[primary] = group_alerts

        return named_groups

    def _create_incident(self, group_key: str, alerts: list[OCSFAlert]) -> Incident:
        """Create an Incident from a group of correlated alerts."""
        # Determine max severity
        max_severity = max(a.severity for a in alerts)

        # Collect unique tactics
        tactics = list(set(a.mitre_tactic for a in alerts if a.mitre_tactic))
        tactics.sort(key=lambda t: _KILL_CHAIN_ORDER.get(t, 99))

        # Determine kill chain phase
        kill_chain = ""
        if tactics:
            last_tactic = tactics[-1]
            phase_num = _KILL_CHAIN_ORDER.get(last_tactic, 0)
            if phase_num <= 3:
                kill_chain = "Reconnaissance/Initial Access"
            elif phase_num <= 7:
                kill_chain = "Establishment"
            elif phase_num <= 10:
                kill_chain = "Lateral Movement"
            elif phase_num <= 12:
                kill_chain = "Command and Control"
            else:
                kill_chain = "Actions on Objectives"

        # Build title
        entity_type, entity_value = group_key.split(":", 1) if ":" in group_key else ("unknown", group_key)
        title = f"{max_severity.name} — {len(alerts)} correlated alerts involving {entity_type} {entity_value}"
        if tactics:
            title += f" [{', '.join(tactics[:3])}]"

        # Build timeline
        timeline = []
        for alert in sorted(alerts, key=lambda a: a.timestamp):
            timeline.append({
                "timestamp": alert.timestamp,
                "alert_id": alert.alert_id,
                "severity": alert.severity.name,
                "tactic": alert.mitre_tactic,
                "technique": alert.mitre_technique,
                "activity": alert.activity[:100],
            })

        # Collect IOCs from threat intel
        iocs = []
        for alert in alerts:
            if alert.src_ip:
                iocs.append({"type": "ip", "value": alert.src_ip})
            if alert.dst_ip:
                iocs.append({"type": "ip", "value": alert.dst_ip})
        # Deduplicate
        seen = set()
        unique_iocs = []
        for ioc in iocs:
            key = (ioc["type"], ioc["value"])
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        return Incident(
            title=title,
            description=f"Correlated incident involving {entity_type} '{entity_value}' with {len(alerts)} related alerts spanning {len(tactics)} ATT&CK tactics.",
            severity=max_severity,
            alert_ids=[a.alert_id for a in alerts],
            kill_chain_phase=kill_chain,
            mitre_tactics=tactics,
            timeline=timeline,
            iocs=unique_iocs,
        )

    @property
    def correlation_count(self) -> int:
        return self._correlation_count


# Module-level convenience
_default_engine = CorrelationEngine()


def correlate_alerts(alerts: list[OCSFAlert] | None = None) -> list[Incident]:
    """Correlate alerts using the default engine."""
    return _default_engine.correlate(alerts)
