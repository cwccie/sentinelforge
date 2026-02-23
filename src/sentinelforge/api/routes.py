"""
REST API routes for SentinelForge.

Provides endpoints for:
- Alert submission and retrieval
- Incident management
- Playbook execution
- System metrics
"""

from __future__ import annotations

import json
from typing import Any

try:
    from flask import Flask, Blueprint, request, jsonify
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

from sentinelforge.ingest import ingest_log
from sentinelforge.triage import triage_alert
from sentinelforge.investigate import investigate_alert
from sentinelforge.correlate import correlate_alerts
from sentinelforge.schemas import AlertStatus, OCSFAlert, Severity
from sentinelforge.store import alert_store, incident_store


def create_api_app() -> Any:
    """Create and configure the Flask API application."""
    if not HAS_FLASK:
        raise ImportError("Flask is required for the API. Install with: pip install flask")

    app = Flask(__name__)
    api = Blueprint("api", __name__, url_prefix="/api/v1")

    # ── Alert endpoints ──────────────────────────────────────────

    @api.route("/alerts", methods=["POST"])
    def submit_alert():
        """Submit a raw log for ingestion and triage."""
        data = request.get_json(force=True)
        raw_log = data.get("raw_log", "")
        if not raw_log:
            return jsonify({"error": "raw_log field is required"}), 400

        alert = ingest_log(raw_log)
        alert = triage_alert(alert)
        alert_store.update(alert)

        return jsonify({
            "alert_id": alert.alert_id,
            "severity": alert.severity.name,
            "verdict": alert.verdict.value,
            "status": alert.status.value,
            "mitre_tactic": alert.mitre_tactic,
            "mitre_technique": alert.mitre_technique,
        }), 201

    @api.route("/alerts", methods=["GET"])
    def list_alerts():
        """List alerts with optional filtering."""
        status = request.args.get("status")
        severity = request.args.get("severity")
        limit = int(request.args.get("limit", 50))

        status_filter = AlertStatus(status) if status else None
        severity_filter = Severity[severity.upper()] if severity else None

        alerts = alert_store.list_all(
            status=status_filter,
            severity=severity_filter,
            limit=limit,
        )
        return jsonify({
            "count": len(alerts),
            "alerts": [a.to_dict() for a in alerts],
        })

    @api.route("/alerts/<alert_id>", methods=["GET"])
    def get_alert(alert_id: str):
        """Get a specific alert by ID."""
        alert = alert_store.get(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
        return jsonify(alert.to_dict())

    @api.route("/alerts/<alert_id>/investigate", methods=["POST"])
    def investigate(alert_id: str):
        """Run investigation on an alert."""
        alert = alert_store.get(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
        report = investigate_alert(alert)
        return jsonify(report.to_dict())

    # ── Incident endpoints ───────────────────────────────────────

    @api.route("/incidents", methods=["GET"])
    def list_incidents():
        """List all incidents."""
        status = request.args.get("status")
        incidents = incident_store.list_all(status=status)
        return jsonify({
            "count": len(incidents),
            "incidents": [i.to_dict() for i in incidents],
        })

    @api.route("/incidents/<incident_id>", methods=["GET"])
    def get_incident(incident_id: str):
        """Get a specific incident."""
        incident = incident_store.get(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found"}), 404
        return jsonify(incident.to_dict())

    @api.route("/correlate", methods=["POST"])
    def run_correlation():
        """Trigger correlation engine on current alerts."""
        incidents = correlate_alerts()
        return jsonify({
            "incidents_created": len(incidents),
            "incidents": [i.to_dict() for i in incidents],
        })

    # ── Metrics endpoint ─────────────────────────────────────────

    @api.route("/metrics", methods=["GET"])
    def metrics():
        """System metrics and health."""
        alerts = alert_store.list_all(limit=10000)
        severity_dist = {}
        status_dist = {}
        for alert in alerts:
            severity_dist[alert.severity.name] = severity_dist.get(alert.severity.name, 0) + 1
            status_dist[alert.status.value] = status_dist.get(alert.status.value, 0) + 1

        return jsonify({
            "total_alerts": alert_store.count(),
            "total_incidents": incident_store.count(),
            "severity_distribution": severity_dist,
            "status_distribution": status_dist,
        })

    # ── Batch ingestion ──────────────────────────────────────────

    @api.route("/ingest/batch", methods=["POST"])
    def batch_ingest():
        """Ingest multiple raw logs at once."""
        data = request.get_json(force=True)
        logs = data.get("logs", [])
        if not logs:
            return jsonify({"error": "logs array is required"}), 400

        results = []
        for raw in logs:
            alert = ingest_log(raw)
            alert = triage_alert(alert)
            alert_store.update(alert)
            results.append({
                "alert_id": alert.alert_id,
                "severity": alert.severity.name,
                "verdict": alert.verdict.value,
            })

        return jsonify({"ingested": len(results), "alerts": results}), 201

    app.register_blueprint(api)
    return app
