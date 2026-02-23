"""Tests for schema definitions."""

import pytest
from sentinelforge.schemas import OCSFAlert, Incident, Severity, AlertStatus, Verdict


class TestOCSFAlert:
    def test_defaults(self):
        alert = OCSFAlert()
        assert alert.severity == Severity.MEDIUM
        assert alert.status == AlertStatus.NEW
        assert alert.verdict == Verdict.UNKNOWN
        assert alert.alert_id  # Should have UUID

    def test_to_dict(self):
        alert = OCSFAlert(src_ip="1.2.3.4", severity=Severity.HIGH)
        d = alert.to_dict()
        assert d["src_ip"] == "1.2.3.4"
        assert d["severity"] == "HIGH"
        assert d["severity_id"] == 3

    def test_from_dict(self):
        d = {"src_ip": "1.2.3.4", "severity": "HIGH", "status": "triaged", "verdict": "suspicious"}
        alert = OCSFAlert.from_dict(d)
        assert alert.src_ip == "1.2.3.4"
        assert alert.severity == Severity.HIGH
        assert alert.status == AlertStatus.TRIAGED
        assert alert.verdict == Verdict.SUSPICIOUS

    def test_roundtrip(self):
        original = OCSFAlert(
            src_ip="1.2.3.4",
            severity=Severity.CRITICAL,
            category="Test",
            status=AlertStatus.TRIAGED,
        )
        d = original.to_dict()
        restored = OCSFAlert.from_dict(d)
        assert restored.src_ip == original.src_ip
        assert restored.severity == original.severity
        assert restored.status == original.status


class TestIncident:
    def test_defaults(self):
        inc = Incident()
        assert inc.incident_id.startswith("INC-")
        assert inc.status == "open"

    def test_to_dict(self):
        inc = Incident(title="Test Incident", severity=Severity.HIGH)
        d = inc.to_dict()
        assert d["title"] == "Test Incident"
        assert d["severity"] == "HIGH"


class TestSeverity:
    def test_ordering(self):
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_values(self):
        assert Severity.INFO.value == 0
        assert Severity.CRITICAL.value == 4
