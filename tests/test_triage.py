"""Tests for the triage agent."""

import pytest
from sentinelforge.triage.agent import TriageAgent, triage_alert
from sentinelforge.schemas import OCSFAlert, Severity, AlertStatus, Verdict


class TestTriageAgent:
    def setup_method(self):
        self.agent = TriageAgent()

    def test_auto_close_benign_cron(self):
        alert = OCSFAlert(activity="CRON[1234]: (root) CMD (/usr/bin/test)")
        result = self.agent.triage(alert)
        assert result.auto_close is True
        assert result.verdict == Verdict.BENIGN

    def test_auto_close_benign_ssh_internal(self):
        alert = OCSFAlert(activity="Accepted publickey for deploy from 10.0.1.25")
        result = self.agent.triage(alert)
        assert result.auto_close is True

    def test_detect_brute_force(self):
        alert = OCSFAlert(activity="Failed password for admin from 1.2.3.4", category="Authentication")
        result = self.agent.triage(alert)
        assert result.mitre_technique_id == "T1110"
        assert result.mitre_tactic == "Credential Access"

    def test_detect_credential_dumping(self):
        alert = OCSFAlert(activity="mimikatz.exe detected accessing LSASS process")
        result = self.agent.triage(alert)
        assert result.mitre_technique_id == "T1003"
        assert result.severity >= Severity.HIGH

    def test_detect_ransomware(self):
        alert = OCSFAlert(activity="Files being encrypted with .locked extension")
        result = self.agent.triage(alert)
        assert result.mitre_technique_id == "T1486"

    def test_detect_lateral_movement(self):
        alert = OCSFAlert(activity="psexec remote execution to domain controller")
        result = self.agent.triage(alert)
        assert result.mitre_technique_id == "T1021"

    def test_detect_exfiltration(self):
        alert = OCSFAlert(activity="Data exfiltration upload 500MB to external host")
        result = self.agent.triage(alert)
        assert result.mitre_technique_id == "T1041"

    def test_detect_defense_evasion(self):
        alert = OCSFAlert(activity="User cleared auth.log: rm -rf /var/log/auth.log")
        result = self.agent.triage(alert)
        assert result.mitre_technique_id == "T1070"

    def test_detect_phishing(self):
        alert = OCSFAlert(activity="Suspicious phishing email with malicious link")
        result = self.agent.triage(alert)
        assert result.mitre_technique_id == "T1566"

    def test_threat_intel_boost(self):
        alert = OCSFAlert(
            activity="Outbound connection",
            severity=Severity.LOW,
            threat_intel={"max_confidence": 0.9, "threat_types": ["C2"]},
        )
        result = self.agent.triage(alert)
        assert result.severity >= Severity.HIGH
        assert result.confidence > 0.5

    def test_critical_asset_boost(self):
        alert = OCSFAlert(activity="Connection detected", tags=["critical-asset"])
        result = self.agent.triage(alert)
        assert "critical-asset-involved" in (result.tags or [])

    def test_apply_triage_updates_alert(self, high_severity_alert):
        result = self.agent.apply_triage(high_severity_alert)
        assert result.status in (AlertStatus.TRIAGED, AlertStatus.AUTO_CLOSED)
        assert result.verdict != Verdict.UNKNOWN

    def test_triage_count_increments(self):
        initial = self.agent.triage_count
        self.agent.triage(OCSFAlert(activity="test"))
        assert self.agent.triage_count == initial + 1


class TestModuleLevelTriage:
    def test_triage_alert_function(self, high_severity_alert):
        result = triage_alert(high_severity_alert)
        assert result.status != AlertStatus.NEW
