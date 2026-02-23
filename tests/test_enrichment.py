"""Tests for alert enrichment."""

import pytest
from sentinelforge.ingest.enrichment import enrich
from sentinelforge.schemas import OCSFAlert, Severity


class TestGeoIPEnrichment:
    def test_known_ip_geoip(self):
        alert = OCSFAlert(src_ip="198.51.100.23")
        enriched = enrich(alert)
        assert enriched.geo_src.get("country") == "RU"

    def test_internal_ip_geoip(self):
        alert = OCSFAlert(src_ip="10.0.1.10")
        enriched = enrich(alert)
        assert enriched.geo_src.get("country") == "INTERNAL"

    def test_unknown_ip_geoip(self):
        alert = OCSFAlert(src_ip="9.9.9.9")
        enriched = enrich(alert)
        assert enriched.geo_src.get("country") == "UNKNOWN"


class TestThreatIntelEnrichment:
    def test_known_malicious_ip(self):
        alert = OCSFAlert(src_ip="198.51.100.23")
        enriched = enrich(alert)
        assert enriched.threat_intel.get("max_confidence", 0) > 0.8
        assert "threat-intel-match" in enriched.tags

    def test_severity_boost_on_threat_match(self):
        alert = OCSFAlert(src_ip="198.51.100.23", severity=Severity.LOW)
        enriched = enrich(alert)
        assert enriched.severity >= Severity.HIGH

    def test_clean_ip_no_threat(self):
        alert = OCSFAlert(src_ip="8.8.8.8")
        enriched = enrich(alert)
        assert not enriched.threat_intel.get("matches")


class TestAssetEnrichment:
    def test_known_asset(self):
        alert = OCSFAlert(src_ip="10.0.1.10")
        enriched = enrich(alert)
        assert enriched.asset_context.get("asset_type") == "workstation"

    def test_critical_asset_tag(self):
        alert = OCSFAlert(dst_ip="10.0.2.100")
        enriched = enrich(alert)
        assert "critical-asset" in enriched.tags
        assert enriched.severity >= Severity.HIGH
