"""
In-memory data store for SentinelForge.

Provides thread-safe storage for alerts, incidents, and playbook state.
In production this would be backed by Elasticsearch, PostgreSQL, or similar.
"""

from __future__ import annotations

import threading
from typing import Any

from sentinelforge.schemas import AlertStatus, Incident, OCSFAlert, Severity


class AlertStore:
    """Thread-safe in-memory alert storage."""

    def __init__(self) -> None:
        self._alerts: dict[str, OCSFAlert] = {}
        self._lock = threading.Lock()

    def add(self, alert: OCSFAlert) -> str:
        with self._lock:
            self._alerts[alert.alert_id] = alert
        return alert.alert_id

    def get(self, alert_id: str) -> OCSFAlert | None:
        with self._lock:
            return self._alerts.get(alert_id)

    def update(self, alert: OCSFAlert) -> None:
        with self._lock:
            self._alerts[alert.alert_id] = alert

    def list_all(
        self,
        status: AlertStatus | None = None,
        severity: Severity | None = None,
        limit: int = 100,
    ) -> list[OCSFAlert]:
        with self._lock:
            alerts = list(self._alerts.values())
        if status is not None:
            alerts = [a for a in alerts if a.status == status]
        if severity is not None:
            alerts = [a for a in alerts if a.severity == severity]
        return sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:limit]

    def count(self) -> int:
        with self._lock:
            return len(self._alerts)

    def clear(self) -> None:
        with self._lock:
            self._alerts.clear()

    def search(self, **kwargs: Any) -> list[OCSFAlert]:
        """Search alerts by any field value."""
        with self._lock:
            results = []
            for alert in self._alerts.values():
                match = True
                for key, value in kwargs.items():
                    if not hasattr(alert, key) or getattr(alert, key) != value:
                        match = False
                        break
                if match:
                    results.append(alert)
        return results


class IncidentStore:
    """Thread-safe in-memory incident storage."""

    def __init__(self) -> None:
        self._incidents: dict[str, Incident] = {}
        self._lock = threading.Lock()

    def add(self, incident: Incident) -> str:
        with self._lock:
            self._incidents[incident.incident_id] = incident
        return incident.incident_id

    def get(self, incident_id: str) -> Incident | None:
        with self._lock:
            return self._incidents.get(incident_id)

    def update(self, incident: Incident) -> None:
        with self._lock:
            self._incidents[incident.incident_id] = incident

    def list_all(self, status: str | None = None, limit: int = 100) -> list[Incident]:
        with self._lock:
            incidents = list(self._incidents.values())
        if status is not None:
            incidents = [i for i in incidents if i.status == status]
        return sorted(incidents, key=lambda i: i.created_at, reverse=True)[:limit]

    def count(self) -> int:
        with self._lock:
            return len(self._incidents)

    def clear(self) -> None:
        with self._lock:
            self._incidents.clear()


# Global singletons
alert_store = AlertStore()
incident_store = IncidentStore()
