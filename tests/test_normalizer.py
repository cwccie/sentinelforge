"""Tests for OCSF normalization."""

import pytest
from sentinelforge.ingest.normalizer import normalize
from sentinelforge.schemas import Severity


class TestNormalization:
    def test_normalize_basic_fields(self):
        parsed = {
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "username": "testuser",
            "hostname": "testhost",
            "activity": "test activity",
            "source_format": "syslog",
            "severity_hint": "HIGH",
        }
        alert = normalize(parsed)
        assert alert.src_ip == "1.2.3.4"
        assert alert.dst_ip == "5.6.7.8"
        assert alert.username == "testuser"
        assert alert.severity == Severity.HIGH

    def test_normalize_severity_mapping(self):
        for sev_str, expected in [("CRITICAL", Severity.CRITICAL), ("HIGH", Severity.HIGH),
                                   ("MEDIUM", Severity.MEDIUM), ("LOW", Severity.LOW), ("INFO", Severity.INFO)]:
            alert = normalize({"severity_hint": sev_str})
            assert alert.severity == expected

    def test_normalize_infers_category(self):
        alert = normalize({"activity": "Failed password for user admin"})
        assert alert.category == "Authentication"

    def test_normalize_infers_category_dns(self):
        alert = normalize({"activity": "DNS query for suspicious domain"})
        assert alert.category == "DNS Activity"

    def test_normalize_infers_category_firewall(self):
        alert = normalize({"activity": "UFW BLOCK incoming connection"})
        assert alert.category == "Firewall"

    def test_normalize_preserves_extensions(self):
        parsed = {"extensions": {"custom_field": "value"}}
        alert = normalize(parsed)
        assert alert.enrichments["original_fields"]["custom_field"] == "value"

    def test_normalize_handles_empty(self):
        alert = normalize({})
        assert alert.severity == Severity.MEDIUM
        assert alert.src_ip == ""
