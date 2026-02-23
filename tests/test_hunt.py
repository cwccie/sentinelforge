"""Tests for the threat hunting module."""

import pytest
from sentinelforge.hunt.hunter import ThreatHunter, HuntHypothesis, hunt, HUNT_HYPOTHESES
from sentinelforge.schemas import OCSFAlert, Severity, AlertStatus
from sentinelforge.store import alert_store


class TestThreatHunter:
    def setup_method(self):
        self.hunter = ThreatHunter()

    def test_builtin_hypotheses_loaded(self):
        assert len(self.hunter.hypotheses) >= 8

    def test_hunt_brute_force(self):
        # Add brute force alerts
        for i in range(10):
            alert = OCSFAlert(
                src_ip="1.2.3.4",
                category="Authentication",
                activity=f"Failed password attempt {i}",
            )
            alert_store.add(alert)

        result = self.hunter.execute_hunt(HUNT_HYPOTHESES[0])  # brute_force_detection
        assert result.match_count >= 10

    def test_hunt_no_matches(self):
        alert = OCSFAlert(activity="Normal benign activity")
        alert_store.add(alert)

        result = self.hunter.execute_hunt(HuntHypothesis(
            name="test_hunt",
            description="Test",
            query={"activity_pattern": r"ZZZZ_NO_MATCH_ZZZZ"},
        ))
        assert result.match_count == 0

    def test_anomaly_detection(self):
        # Create frequency spike
        for i in range(20):
            alert = OCSFAlert(
                src_ip="1.2.3.4",
                category="Authentication",
                activity="Failed login",
            )
            alert_store.add(alert)

        result = self.hunter.execute_hunt(HUNT_HYPOTHESES[0])
        assert len(result.anomalies) >= 1

    def test_anomaly_score_range(self):
        alert = OCSFAlert(
            src_ip="1.2.3.4",
            category="Authentication",
            activity="Failed password",
        )
        alert_store.add(alert)

        result = self.hunter.execute_hunt(HUNT_HYPOTHESES[0])
        assert 0.0 <= result.anomaly_score <= 10.0

    def test_hunt_summary(self):
        alert = OCSFAlert(
            src_ip="1.2.3.4",
            category="Authentication",
            activity="Failed password for admin",
        )
        alert_store.add(alert)

        result = self.hunter.execute_hunt(HUNT_HYPOTHESES[0])
        assert "brute_force_detection" in result.summary

    def test_custom_hypothesis(self):
        alert = OCSFAlert(activity="Custom pattern ABCDEF detected")
        alert_store.add(alert)

        hyp = HuntHypothesis(
            name="custom_test",
            description="Custom test hunt",
            query={"activity_pattern": r"ABCDEF"},
        )
        self.hunter.add_hypothesis(hyp)
        result = self.hunter.execute_hunt(hyp)
        assert result.match_count >= 1

    def test_hunt_count_increments(self):
        initial = self.hunter.hunt_count
        self.hunter.execute_hunt(HUNT_HYPOTHESES[0])
        assert self.hunter.hunt_count == initial + 1


class TestModuleLevelHunt:
    def test_hunt_function(self):
        alert = OCSFAlert(
            category="Authentication",
            activity="Failed password for user",
        )
        alert_store.add(alert)
        results = hunt("brute_force_detection")
        # May or may not have results depending on matches
        assert isinstance(results, list)

    def test_hunt_all(self):
        alert = OCSFAlert(activity="Normal activity")
        alert_store.add(alert)
        results = hunt()
        assert isinstance(results, list)
