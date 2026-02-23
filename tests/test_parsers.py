"""Tests for multi-format log parsers."""

import json
import pytest
from sentinelforge.ingest.parsers import (
    detect_format, parse_log, parse_cef, parse_leef,
    parse_syslog, parse_json_alert, parse_windows_xml,
)


class TestFormatDetection:
    def test_detect_cef(self):
        assert detect_format("CEF:0|Vendor|Product|1.0|100|Name|5|key=value") == "cef"

    def test_detect_leef(self):
        assert detect_format("LEEF:2.0|IBM|QRadar|3.0|Event|key=value") == "leef"

    def test_detect_json(self):
        assert detect_format('{"event": "test"}') == "json"

    def test_detect_syslog_rfc5424(self):
        assert detect_format("<134>1 2026-02-23T10:00:00Z host app 1234 - - msg") == "syslog"

    def test_detect_syslog_rfc3164(self):
        assert detect_format("Jan 23 10:00:00 host msg") == "syslog"

    def test_detect_syslog_rfc3164_with_pri(self):
        assert detect_format("<38>Feb 23 10:00:00 host kernel: msg") == "syslog"

    def test_detect_windows_xml(self):
        assert detect_format("<Event xmlns='test'>...</Event>") == "windows_xml"

    def test_detect_unknown(self):
        assert detect_format("some random text") == "unknown"


class TestCEFParser:
    def test_parse_basic_cef(self, sample_cef):
        result = parse_cef(sample_cef)
        assert result["device_vendor"] == "SecurityCo"
        assert result["device_product"] == "Firewall"
        assert result["class_name"] == "Connection to Known C2"
        assert result["severity_hint"] == "CRITICAL"

    def test_parse_cef_network_fields(self, sample_cef):
        result = parse_cef(sample_cef)
        assert result["src_ip"] == "10.0.1.10"
        assert result["dst_ip"] == "203.0.113.66"
        assert result["dst_port"] == 443
        assert result["protocol"] == "TCP"

    def test_parse_cef_severity_mapping(self):
        low = parse_cef("CEF:0|V|P|1|1|Name|2|")
        assert low["severity_hint"] == "LOW"
        med = parse_cef("CEF:0|V|P|1|1|Name|5|")
        assert med["severity_hint"] == "MEDIUM"
        high = parse_cef("CEF:0|V|P|1|1|Name|7|")
        assert high["severity_hint"] == "HIGH"

    def test_parse_cef_extensions(self, sample_cef):
        result = parse_cef(sample_cef)
        assert "extensions" in result
        assert result["extensions"]["cat"] == "C2"


class TestLEEFParser:
    def test_parse_basic_leef(self, sample_leef):
        result = parse_leef(sample_leef)
        assert result["device_vendor"] == "IBM"
        assert result["class_name"] == "PortScan"

    def test_parse_leef_network_fields(self, sample_leef):
        result = parse_leef(sample_leef)
        assert result["src_ip"] == "192.0.2.99"
        assert result["dst_ip"] == "10.0.1.50"
        assert result["dst_port"] == 445


class TestSyslogParser:
    def test_parse_rfc5424(self, sample_syslog_failed_login):
        result = parse_syslog(sample_syslog_failed_login)
        assert result["hostname"] == "firewall01"
        assert result["severity_hint"] in ("MEDIUM", "LOW", "INFO")
        assert "admin" in result.get("username", "") or "admin" in result.get("activity", "")

    def test_parse_rfc3164(self, sample_syslog_benign):
        result = parse_syslog(sample_syslog_benign)
        assert result["hostname"] == "server02"

    def test_extract_ip(self):
        result = parse_syslog("<134>1 2026-01-01T00:00:00Z host sshd 1 - - Failed from 1.2.3.4 port 22")
        assert result.get("src_ip") == "1.2.3.4"

    def test_extract_username(self):
        result = parse_syslog("<134>1 2026-01-01T00:00:00Z host sshd 1 - - Failed password for testuser from 1.2.3.4")
        assert result.get("username") == "testuser"


class TestJSONParser:
    def test_parse_json(self, sample_json):
        result = parse_json_alert(sample_json)
        assert result["src_ip"] == "198.51.100.23"
        assert result["dst_ip"] == "10.0.1.50"
        assert result["username"] == "administrator"
        assert result["severity_hint"] == "HIGH"

    def test_parse_json_with_alternate_fields(self):
        data = '{"source_ip": "1.2.3.4", "user": "bob", "msg": "test event"}'
        result = parse_json_alert(data)
        assert result["src_ip"] == "1.2.3.4"
        assert result["username"] == "bob"

    def test_parse_invalid_json(self):
        result = parse_json_alert("not valid json")
        assert "raw_log" in result


class TestWindowsXMLParser:
    def test_parse_windows_event(self, sample_windows_xml):
        result = parse_windows_xml(sample_windows_xml)
        assert result["class_name"] == "EventID-4625"
        assert result["hostname"] == "DC01.corp.local"
        assert result["username"] == "administrator"
        assert result["domain"] == "CORP"
        assert result["src_ip"] == "198.51.100.23"

    def test_parse_invalid_xml(self):
        result = parse_windows_xml("not xml at all")
        assert "raw_log" in result


class TestAutoDetectParsing:
    def test_parse_log_cef(self, sample_cef):
        result = parse_log(sample_cef)
        assert result["source_format"] == "cef"

    def test_parse_log_syslog(self, sample_syslog_failed_login):
        result = parse_log(sample_syslog_failed_login)
        assert result["source_format"] == "syslog"

    def test_parse_log_json(self, sample_json):
        result = parse_log(sample_json)
        assert result["source_format"] == "json"

    def test_parse_log_preserves_raw(self, sample_cef):
        result = parse_log(sample_cef)
        assert result["raw_log"] == sample_cef
