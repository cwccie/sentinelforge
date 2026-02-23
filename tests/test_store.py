"""Tests for the data store."""

import pytest
from sentinelforge.store import AlertStore, IncidentStore
from sentinelforge.schemas import OCSFAlert, Incident, Severity, AlertStatus


class TestAlertStore:
    def setup_method(self):
        self.store = AlertStore()

    def test_add_and_get(self):
        alert = OCSFAlert(src_ip="1.2.3.4")
        aid = self.store.add(alert)
        retrieved = self.store.get(aid)
        assert retrieved is not None
        assert retrieved.src_ip == "1.2.3.4"

    def test_get_nonexistent(self):
        assert self.store.get("nonexistent") is None

    def test_update(self):
        alert = OCSFAlert(src_ip="1.2.3.4")
        self.store.add(alert)
        alert.src_ip = "5.6.7.8"
        self.store.update(alert)
        assert self.store.get(alert.alert_id).src_ip == "5.6.7.8"

    def test_list_all(self):
        for i in range(5):
            self.store.add(OCSFAlert())
        assert len(self.store.list_all()) == 5

    def test_list_filter_severity(self):
        self.store.add(OCSFAlert(severity=Severity.HIGH))
        self.store.add(OCSFAlert(severity=Severity.LOW))
        highs = self.store.list_all(severity=Severity.HIGH)
        assert len(highs) == 1

    def test_list_filter_status(self):
        self.store.add(OCSFAlert(status=AlertStatus.TRIAGED))
        self.store.add(OCSFAlert(status=AlertStatus.NEW))
        triaged = self.store.list_all(status=AlertStatus.TRIAGED)
        assert len(triaged) == 1

    def test_count(self):
        self.store.add(OCSFAlert())
        self.store.add(OCSFAlert())
        assert self.store.count() == 2

    def test_clear(self):
        self.store.add(OCSFAlert())
        self.store.clear()
        assert self.store.count() == 0

    def test_search(self):
        self.store.add(OCSFAlert(src_ip="1.2.3.4"))
        self.store.add(OCSFAlert(src_ip="5.6.7.8"))
        results = self.store.search(src_ip="1.2.3.4")
        assert len(results) == 1


class TestIncidentStore:
    def setup_method(self):
        self.store = IncidentStore()

    def test_add_and_get(self):
        inc = Incident(title="Test")
        iid = self.store.add(inc)
        assert self.store.get(iid).title == "Test"

    def test_list_filter_status(self):
        self.store.add(Incident(status="open"))
        self.store.add(Incident(status="closed"))
        open_incs = self.store.list_all(status="open")
        assert len(open_incs) == 1

    def test_count(self):
        self.store.add(Incident())
        assert self.store.count() == 1
