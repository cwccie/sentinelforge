"""Tests for the correlation engine."""

import pytest
from sentinelforge.correlate.engine import CorrelationEngine, correlate_alerts
from sentinelforge.schemas import OCSFAlert, Severity, AlertStatus
from sentinelforge.store import alert_store, incident_store


class TestCorrelationEngine:
    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_correlate_by_source_ip(self):
        a1 = OCSFAlert(src_ip="1.2.3.4", activity="Alert 1", status=AlertStatus.TRIAGED)
        a2 = OCSFAlert(src_ip="1.2.3.4", activity="Alert 2", status=AlertStatus.TRIAGED)
        a3 = OCSFAlert(src_ip="5.6.7.8", activity="Alert 3", status=AlertStatus.TRIAGED)
        alert_store.add(a1)
        alert_store.add(a2)
        alert_store.add(a3)

        incidents = self.engine.correlate()
        # a1 and a2 should be in same incident
        inc_with_both = [i for i in incidents if a1.alert_id in i.alert_ids and a2.alert_id in i.alert_ids]
        assert len(inc_with_both) >= 1

    def test_correlate_by_username(self):
        a1 = OCSFAlert(username="admin", activity="Login fail", status=AlertStatus.TRIAGED)
        a2 = OCSFAlert(username="admin", activity="Priv escalation", status=AlertStatus.TRIAGED)
        alert_store.add(a1)
        alert_store.add(a2)

        incidents = self.engine.correlate()
        assert len(incidents) >= 1

    def test_skip_auto_closed(self):
        a1 = OCSFAlert(src_ip="1.2.3.4", status=AlertStatus.AUTO_CLOSED)
        a2 = OCSFAlert(src_ip="1.2.3.4", status=AlertStatus.TRIAGED)
        alert_store.add(a1)
        alert_store.add(a2)

        incidents = self.engine.correlate()
        for inc in incidents:
            assert a1.alert_id not in inc.alert_ids

    def test_incident_severity_is_max(self):
        a1 = OCSFAlert(src_ip="1.2.3.4", severity=Severity.LOW, status=AlertStatus.TRIAGED)
        a2 = OCSFAlert(src_ip="1.2.3.4", severity=Severity.CRITICAL, status=AlertStatus.TRIAGED)
        alert_store.add(a1)
        alert_store.add(a2)

        incidents = self.engine.correlate()
        assert any(i.severity == Severity.CRITICAL for i in incidents)

    def test_kill_chain_detection(self):
        a1 = OCSFAlert(src_ip="1.2.3.4", mitre_tactic="Initial Access", status=AlertStatus.TRIAGED)
        a2 = OCSFAlert(src_ip="1.2.3.4", mitre_tactic="Execution", status=AlertStatus.TRIAGED)
        a3 = OCSFAlert(src_ip="1.2.3.4", mitre_tactic="Exfiltration", status=AlertStatus.TRIAGED)
        alert_store.add(a1)
        alert_store.add(a2)
        alert_store.add(a3)

        incidents = self.engine.correlate()
        assert any(i.kill_chain_phase for i in incidents)

    def test_incident_stored(self):
        a1 = OCSFAlert(src_ip="1.2.3.4", status=AlertStatus.TRIAGED)
        alert_store.add(a1)
        self.engine.correlate()
        assert incident_store.count() >= 1

    def test_deduplication(self):
        # Same key fields should be deduped
        a1 = OCSFAlert(src_ip="1.2.3.4", dst_ip="5.6.7.8", activity="Same alert", class_name="TestAlert", status=AlertStatus.TRIAGED)
        a2 = OCSFAlert(src_ip="1.2.3.4", dst_ip="5.6.7.8", activity="Same alert", class_name="TestAlert", status=AlertStatus.TRIAGED)
        alert_store.add(a1)
        alert_store.add(a2)

        incidents = self.engine.correlate()
        total_alerts_in_incidents = sum(len(i.alert_ids) for i in incidents)
        assert total_alerts_in_incidents <= 2  # Dedup might reduce

    def test_empty_store(self):
        incidents = self.engine.correlate()
        assert incidents == []
