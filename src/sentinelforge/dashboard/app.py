"""
Flask + WebSocket dashboard application.

Provides a real-time web interface for SOC analysts:
- Live alert feed with severity-coded display
- Incident timeline visualization
- Investigation workspace
- Playbook execution status
- System metrics and health
"""

from __future__ import annotations

import json
import os
from typing import Any

try:
    from flask import Flask, render_template, jsonify, request
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

try:
    from flask_sock import Sock
    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False

from sentinelforge.store import alert_store, incident_store
from sentinelforge.api.routes import create_api_app


_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def create_dashboard_app() -> Any:
    """Create the dashboard Flask application with API and WebSocket support."""
    if not HAS_FLASK:
        raise ImportError("Flask is required. Install with: pip install flask")

    app = Flask(
        __name__,
        template_folder=_TEMPLATE_DIR,
        static_folder=_STATIC_DIR,
    )

    # Register API blueprint
    api_app = create_api_app()
    for bp in api_app.blueprints.values():
        app.register_blueprint(bp)

    # WebSocket support
    ws_clients: list[Any] = []
    if HAS_WEBSOCKET:
        sock = Sock(app)

        @sock.route("/ws/alerts")
        def alert_feed(ws):
            ws_clients.append(ws)
            try:
                while True:
                    # Keep connection alive, receive any messages
                    data = ws.receive(timeout=30)
                    if data is None:
                        break
            except Exception:
                pass
            finally:
                if ws in ws_clients:
                    ws_clients.remove(ws)

    # Dashboard routes
    @app.route("/")
    def index():
        try:
            return render_template("index.html")
        except Exception:
            return _fallback_dashboard()

    @app.route("/dashboard/data")
    def dashboard_data():
        """JSON endpoint for dashboard widgets."""
        alerts = alert_store.list_all(limit=100)
        incidents = incident_store.list_all(limit=50)

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        status_counts = {}
        for alert in alerts:
            severity_counts[alert.severity.name] = severity_counts.get(alert.severity.name, 0) + 1
            status_counts[alert.status.value] = status_counts.get(alert.status.value, 0) + 1

        return jsonify({
            "alerts": [a.to_dict() for a in alerts[:20]],
            "incidents": [i.to_dict() for i in incidents[:10]],
            "metrics": {
                "total_alerts": alert_store.count(),
                "total_incidents": incident_store.count(),
                "severity_distribution": severity_counts,
                "status_distribution": status_counts,
            },
        })

    return app


def _fallback_dashboard() -> str:
    """Fallback HTML when templates are not available."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelForge SOC Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0}
.header{background:#1e293b;padding:1rem 2rem;border-bottom:2px solid #3b82f6;display:flex;align-items:center;gap:1rem}
.header h1{font-size:1.5rem;color:#3b82f6}.header .badge{background:#22c55e;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem;padding:1.5rem}
.card{background:#1e293b;border-radius:8px;padding:1.5rem;border:1px solid #334155}
.card h3{color:#94a3b8;font-size:0.875rem;text-transform:uppercase;margin-bottom:0.5rem}
.card .value{font-size:2rem;font-weight:bold}
.critical{color:#ef4444}.high{color:#f97316}.medium{color:#eab308}.low{color:#22c55e}.info{color:#3b82f6}
.alert-feed{padding:0 1.5rem 1.5rem}.alert-feed h2{margin-bottom:1rem;color:#94a3b8}
table{width:100%;border-collapse:collapse}th,td{padding:0.75rem;text-align:left;border-bottom:1px solid #334155}
th{color:#94a3b8;font-size:0.75rem;text-transform:uppercase}
.severity-badge{padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold}
.sev-CRITICAL{background:#7f1d1d;color:#fca5a5}.sev-HIGH{background:#7c2d12;color:#fdba74}
.sev-MEDIUM{background:#713f12;color:#fde047}.sev-LOW{background:#14532d;color:#86efac}
.sev-INFO{background:#1e3a5f;color:#93c5fd}
#loading{text-align:center;padding:2rem;color:#64748b}
</style>
</head>
<body>
<div class="header"><h1>SentinelForge</h1><span class="badge">LIVE</span><span style="color:#64748b">Autonomous SOC Platform</span></div>
<div class="grid" id="metrics">
<div class="card"><h3>Total Alerts</h3><div class="value" id="total-alerts">-</div></div>
<div class="card"><h3>Total Incidents</h3><div class="value" id="total-incidents">-</div></div>
<div class="card"><h3>Critical Alerts</h3><div class="value critical" id="critical-count">-</div></div>
<div class="card"><h3>High Alerts</h3><div class="value high" id="high-count">-</div></div>
</div>
<div class="alert-feed"><h2>Recent Alerts</h2>
<table><thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Source</th><th>Activity</th><th>Status</th></tr></thead>
<tbody id="alert-table"><tr><td colspan="6" id="loading">Loading...</td></tr></tbody></table></div>
<script>
async function loadData(){
try{const r=await fetch('/dashboard/data');const d=await r.json();
document.getElementById('total-alerts').textContent=d.metrics.total_alerts;
document.getElementById('total-incidents').textContent=d.metrics.total_incidents;
document.getElementById('critical-count').textContent=d.metrics.severity_distribution.CRITICAL||0;
document.getElementById('high-count').textContent=d.metrics.severity_distribution.HIGH||0;
const tb=document.getElementById('alert-table');tb.innerHTML='';
if(d.alerts.length===0){tb.innerHTML='<tr><td colspan="6" style="text-align:center;color:#64748b">No alerts yet. Submit logs via API or run demo mode.</td></tr>';return}
d.alerts.forEach(a=>{const tr=document.createElement('tr');
tr.innerHTML=`<td>${new Date(a.timestamp).toLocaleString()}</td><td><span class="severity-badge sev-${a.severity}">${a.severity}</span></td><td>${a.category||'-'}</td><td>${a.src_ip||'-'}</td><td>${(a.activity||a.class_name||'-').substring(0,80)}</td><td>${a.status}</td>`;
tb.appendChild(tr)})
}catch(e){document.getElementById('loading').textContent='Error loading data: '+e.message}}
loadData();setInterval(loadData,5000);
</script>
</body></html>"""
