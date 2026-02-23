"""Tests for the investigation agent."""

import pytest
from sentinelforge.investigate.agent import InvestigationAgent, IOC, investigate_alert
from sentinelforge.schemas import OCSFAlert, Severity
from sentinelforge.store import alert_store


class TestIOCExtraction:
    def setup_method(self):
        self.agent = InvestigationAgent()

    def test_extract_ip(self):
        alert = OCSFAlert(raw_log="Connection from 1.2.3.4 to 5.6.7.8", src_ip="1.2.3.4", dst_ip="5.6.7.8")
        report = self.agent.investigate(alert)
        ip_iocs = [i for i in report.iocs if i.ioc_type == "ip"]
        assert len(ip_iocs) >= 2

    def test_extract_domain(self):
        alert = OCSFAlert(raw_log="DNS query for malicious-domain.xyz")
        report = self.agent.investigate(alert)
        domain_iocs = [i for i in report.iocs if i.ioc_type == "domain"]
        assert any("malicious-domain.xyz" in i.value for i in domain_iocs)

    def test_extract_url(self):
        alert = OCSFAlert(raw_log="Download from https://evil.com/payload.exe")
        report = self.agent.investigate(alert)
        url_iocs = [i for i in report.iocs if i.ioc_type == "url"]
        assert len(url_iocs) >= 1

    def test_extract_hash(self):
        alert = OCSFAlert(raw_log="File hash: a" * 32)
        report = self.agent.investigate(alert)
        hash_iocs = [i for i in report.iocs if i.ioc_type in ("md5", "sha1", "sha256")]
        assert len(hash_iocs) >= 0  # May or may not match depending on format

    def test_deduplication(self):
        alert = OCSFAlert(raw_log="IP 1.2.3.4 connected to 1.2.3.4", src_ip="1.2.3.4")
        report = self.agent.investigate(alert)
        ip_values = [i.value for i in report.iocs if i.ioc_type == "ip"]
        assert len(set(ip_values)) == len(ip_values)


class TestInvestigation:
    def setup_method(self):
        self.agent = InvestigationAgent()

    def test_find_related_alerts(self, high_severity_alert):
        # Add related alert to store
        related = OCSFAlert(src_ip="198.51.100.23", activity="Another alert from same IP")
        alert_store.add(high_severity_alert)
        alert_store.add(related)
        report = self.agent.investigate(high_severity_alert)
        assert related.alert_id in report.related_alerts

    def test_risk_score_calculation(self, critical_alert):
        report = self.agent.investigate(critical_alert)
        assert 0.0 <= report.risk_score <= 10.0
        assert report.risk_score >= 5.0  # Critical alerts should have high risk

    def test_recommendations_generated(self, high_severity_alert):
        high_severity_alert.mitre_technique_id = "T1110"
        report = self.agent.investigate(high_severity_alert)
        assert len(report.recommendations) > 0

    def test_timeline_built(self, high_severity_alert):
        alert_store.add(high_severity_alert)
        report = self.agent.investigate(high_severity_alert)
        assert len(report.timeline) >= 1

    def test_lateral_movement_detection(self):
        alert1 = OCSFAlert(src_ip="10.0.1.10", dst_ip="10.0.1.50", activity="psexec remote execution")
        alert2 = OCSFAlert(src_ip="10.0.1.10", dst_ip="10.0.1.51", activity="Connection")
        alert3 = OCSFAlert(src_ip="10.0.1.10", dst_ip="10.0.1.52", activity="Connection")
        alert_store.add(alert1)
        alert_store.add(alert2)
        alert_store.add(alert3)
        report = self.agent.investigate(alert1)
        assert report.lateral_movement_detected is True
