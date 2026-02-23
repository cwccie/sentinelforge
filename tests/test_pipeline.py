"""Tests for the full ingestion pipeline."""

import pytest
from sentinelforge.ingest.pipeline import ingest_log, ingest_batch
from sentinelforge.schemas import Severity
from sentinelforge.store import alert_store


class TestIngestionPipeline:
    def test_ingest_single_log(self, sample_syslog_failed_login):
        alert = ingest_log(sample_syslog_failed_login)
        assert alert.alert_id
        assert alert.source_format == "syslog"
        assert alert.hostname == "firewall01"

    def test_ingest_stores_alert(self, sample_cef):
        alert = ingest_log(sample_cef)
        stored = alert_store.get(alert.alert_id)
        assert stored is not None
        assert stored.alert_id == alert.alert_id

    def test_ingest_batch(self, sample_syslog_failed_login, sample_cef, sample_json):
        alerts = ingest_batch([sample_syslog_failed_login, sample_cef, sample_json])
        assert len(alerts) == 3
        assert alert_store.count() == 3

    def test_ingest_enriches_alert(self, sample_cef):
        alert = ingest_log(sample_cef)
        # CEF sample has known threat intel IP
        assert alert.geo_dst or alert.geo_src

    def test_ingest_no_store(self, sample_cef):
        alert = ingest_log(sample_cef, auto_store=False)
        assert alert.alert_id
        assert alert_store.count() == 0
