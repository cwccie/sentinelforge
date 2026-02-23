"""Shared test fixtures for SentinelForge."""

import pytest
from sentinelforge.schemas import OCSFAlert, Severity, AlertStatus, Verdict
from sentinelforge.store import AlertStore, IncidentStore, alert_store, incident_store


@pytest.fixture(autouse=True)
def clean_stores():
    """Clear global stores before each test."""
    alert_store.clear()
    incident_store.clear()
    yield
    alert_store.clear()
    incident_store.clear()


@pytest.fixture
def sample_syslog_failed_login():
    return '<134>1 2026-02-23T08:15:30Z firewall01 sshd 12345 - - Failed password for admin from 198.51.100.23 port 22 ssh2'


@pytest.fixture
def sample_syslog_benign():
    return 'Jan 23 08:30:00 server02 CRON[9876]: (root) CMD (/usr/local/bin/backup.sh)'


@pytest.fixture
def sample_cef():
    return 'CEF:0|SecurityCo|Firewall|1.0|100|Connection to Known C2|9|src=10.0.1.10 dst=203.0.113.66 dpt=443 spt=54321 proto=TCP act=blocked cat=C2'


@pytest.fixture
def sample_leef():
    return 'LEEF:2.0|IBM|QRadar|3.0|PortScan|src=192.0.2.99\tsrcPort=0\tdst=10.0.1.50\tdstPort=445\tproto=TCP\tsev=5\taction=port scan detected'


@pytest.fixture
def sample_json():
    return '{"event_type":"authentication","source_ip":"198.51.100.23","dest_ip":"10.0.1.50","username":"administrator","message":"Failed login attempt","severity":"HIGH"}'


@pytest.fixture
def sample_windows_xml():
    return '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-02-23T08:12:00.000Z"/>
    <Computer>DC01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">administrator</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="FailureReason">Unknown user name or bad password</Data>
    <Data Name="IpAddress">198.51.100.23</Data>
    <Data Name="IpPort">54321</Data>
  </EventData>
</Event>'''


@pytest.fixture
def high_severity_alert():
    alert = OCSFAlert()
    alert.severity = Severity.HIGH
    alert.src_ip = "198.51.100.23"
    alert.dst_ip = "10.0.1.50"
    alert.username = "admin"
    alert.hostname = "dc01"
    alert.activity = "Failed password for admin from 198.51.100.23"
    alert.category = "Authentication"
    alert.raw_log = "Failed password for admin from 198.51.100.23 port 22 ssh2"
    return alert


@pytest.fixture
def critical_alert():
    alert = OCSFAlert()
    alert.severity = Severity.CRITICAL
    alert.src_ip = "10.0.1.10"
    alert.dst_ip = "203.0.113.66"
    alert.username = "jdoe"
    alert.hostname = "WORKSTATION-01"
    alert.activity = "mimikatz.exe detected accessing LSASS process"
    alert.category = "Malware"
    alert.raw_log = "mimikatz.exe detected on WORKSTATION-01"
    alert.mitre_tactic = "Credential Access"
    alert.mitre_technique = "OS Credential Dumping"
    alert.mitre_technique_id = "T1003"
    return alert
