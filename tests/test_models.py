"""Tests for detection models."""

import pytest
from sentinelforge.models.detector import RuleEngine, AnomalyDetector, BUILTIN_RULES, DetectionRule
from sentinelforge.schemas import OCSFAlert, Severity


class TestRuleEngine:
    def setup_method(self):
        self.engine = RuleEngine()

    def test_builtin_rules_loaded(self):
        assert len(self.engine.rules) >= 10

    def test_detect_brute_force(self):
        alert = OCSFAlert(
            activity="Failed password for admin from 1.2.3.4",
            category="Authentication",
        )
        detections = self.engine.evaluate(alert)
        rule_ids = [d.rule_id for d in detections]
        assert "SF-001" in rule_ids

    def test_detect_powershell(self):
        alert = OCSFAlert(activity="powershell.exe -enc SQBFAFgA -nop -w hidden")
        detections = self.engine.evaluate(alert)
        rule_ids = [d.rule_id for d in detections]
        assert "SF-002" in rule_ids

    def test_detect_credential_dump(self):
        alert = OCSFAlert(activity="mimikatz.exe detected")
        detections = self.engine.evaluate(alert)
        rule_ids = [d.rule_id for d in detections]
        assert "SF-003" in rule_ids

    def test_detect_ransomware(self):
        alert = OCSFAlert(activity="Files encrypted with .locked extension, ransom note detected")
        detections = self.engine.evaluate(alert)
        rule_ids = [d.rule_id for d in detections]
        assert "SF-007" in rule_ids

    def test_threat_intel_rule(self):
        alert = OCSFAlert(
            activity="Outbound connection",
            threat_intel={"max_confidence": 0.95},
        )
        detections = self.engine.evaluate(alert)
        rule_ids = [d.rule_id for d in detections]
        assert "SF-004" in rule_ids

    def test_no_detection(self):
        alert = OCSFAlert(activity="Normal user login successful")
        detections = self.engine.evaluate(alert)
        assert len(detections) == 0

    def test_batch_threshold_detection(self):
        alerts = [
            OCSFAlert(
                src_ip="1.2.3.4",
                category="Authentication",
                activity=f"Failed password attempt #{i}",
            )
            for i in range(10)
        ]
        detections = self.engine.evaluate_batch(alerts)
        threshold_dets = [d for d in detections if "threshold" in d.rule_name.lower()]
        assert len(threshold_dets) >= 1

    def test_disable_rule(self):
        assert self.engine.disable_rule("SF-001") is True
        alert = OCSFAlert(activity="Failed password for admin", category="Authentication")
        detections = self.engine.evaluate(alert)
        rule_ids = [d.rule_id for d in detections]
        assert "SF-001" not in rule_ids

    def test_add_custom_rule(self):
        custom = DetectionRule(
            rule_id="CUSTOM-001",
            name="Custom Rule",
            description="Test custom rule",
            severity=Severity.HIGH,
            conditions={"activity_pattern": r"CUSTOM_PATTERN_XYZ"},
        )
        self.engine.add_rule(custom)
        alert = OCSFAlert(activity="Found CUSTOM_PATTERN_XYZ in log")
        detections = self.engine.evaluate(alert)
        assert any(d.rule_id == "CUSTOM-001" for d in detections)


class TestAnomalyDetector:
    def setup_method(self):
        self.detector = AnomalyDetector()

    def test_build_baseline(self):
        alerts = [OCSFAlert(src_ip=f"10.0.0.{i}", dst_ip=f"10.0.1.{i}") for i in range(20)]
        baselines = self.detector.build_baseline(alerts)
        assert "events_per_source" in baselines
        assert baselines["events_per_source"]["count"] == 20

    def test_detect_frequency_anomaly(self):
        # Create normal baseline — each IP appears once
        normal = [OCSFAlert(src_ip=f"10.0.0.{i}", dst_ip="10.0.1.1") for i in range(20)]
        self.detector.build_baseline(normal)

        # Add anomalous source with many events — should stand out
        anomalous = list(normal) + [OCSFAlert(src_ip="10.0.0.99", dst_ip="10.0.1.1") for _ in range(100)]
        anomalies = self.detector.detect_anomalies(anomalous)
        # Should detect the spike from 10.0.0.99
        freq_anomalies = [a for a in anomalies if a["type"] == "frequency_anomaly"]
        assert any(a["entity"] == "10.0.0.99" for a in freq_anomalies)

    def test_baselines_property(self):
        alerts = [OCSFAlert(src_ip="10.0.0.1") for _ in range(5)]
        self.detector.build_baseline(alerts)
        assert isinstance(self.detector.baselines, dict)
