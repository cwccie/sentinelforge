"""
Multi-format log parsers.

Each parser extracts structured fields from a specific log format and returns
a dictionary ready for OCSF normalization.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from xml.etree import ElementTree


def detect_format(raw: str) -> str:
    """Auto-detect log format from raw string."""
    stripped = raw.strip()
    if stripped.startswith("CEF:"):
        return "cef"
    if stripped.startswith("LEEF:"):
        return "leef"
    if stripped.startswith("<Event") or stripped.startswith("<?xml"):
        return "windows_xml"
    if stripped.startswith("{"):
        try:
            json.loads(stripped)
            return "json"
        except json.JSONDecodeError:
            pass
    # Check for syslog priority marker  <NNN>
    if re.match(r"^<\d{1,3}>", stripped):
        return "syslog"
    # Fallback: try RFC 3164 pattern (month day time host)
    if re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", stripped):
        return "syslog"
    return "unknown"


def parse_log(raw: str) -> dict[str, Any]:
    """Parse a raw log line, auto-detecting format."""
    fmt = detect_format(raw)
    parsers = {
        "cef": parse_cef,
        "leef": parse_leef,
        "syslog": parse_syslog,
        "json": parse_json_alert,
        "windows_xml": parse_windows_xml,
    }
    parser = parsers.get(fmt)
    if parser is None:
        return {"source_format": "unknown", "raw_log": raw, "activity": raw[:200]}
    result = parser(raw)
    result["source_format"] = fmt
    result["raw_log"] = raw
    return result


def parse_cef(raw: str) -> dict[str, Any]:
    """
    Parse Common Event Format (CEF) log.
    Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    result: dict[str, Any] = {}
    stripped = raw.strip()
    if not stripped.startswith("CEF:"):
        return {"raw_log": raw, "source_format": "cef"}

    # Split header (pipe-delimited, max 8 parts)
    parts = stripped.split("|", 7)
    if len(parts) >= 7:
        result["cef_version"] = parts[0].replace("CEF:", "")
        result["device_vendor"] = parts[1]
        result["device_product"] = parts[2]
        result["device_version"] = parts[3]
        result["signature_id"] = parts[4]
        result["class_name"] = parts[5]
        result["cef_severity"] = parts[6]

        # Map CEF severity (0-10) to our severity
        try:
            sev_num = int(parts[6])
            if sev_num <= 3:
                result["severity_hint"] = "LOW"
            elif sev_num <= 6:
                result["severity_hint"] = "MEDIUM"
            elif sev_num <= 8:
                result["severity_hint"] = "HIGH"
            else:
                result["severity_hint"] = "CRITICAL"
        except ValueError:
            result["severity_hint"] = parts[6].upper() if parts[6] else "MEDIUM"

    # Parse extension key=value pairs
    if len(parts) == 8:
        ext_str = parts[7]
        ext_pairs = re.findall(r"(\w+)=((?:[^ ]| (?!\w+=))*)", ext_str)
        extensions = {k: v.strip() for k, v in ext_pairs}
        result["src_ip"] = extensions.get("src", "")
        result["dst_ip"] = extensions.get("dst", "")
        result["src_port"] = _safe_int(extensions.get("spt", "0"))
        result["dst_port"] = _safe_int(extensions.get("dpt", "0"))
        result["protocol"] = extensions.get("proto", "")
        result["username"] = extensions.get("suser", extensions.get("duser", ""))
        result["hostname"] = extensions.get("shost", extensions.get("dhost", ""))
        result["activity"] = extensions.get("act", extensions.get("msg", ""))
        result["category"] = extensions.get("cat", "")
        if extensions.get("rt"):
            result["timestamp"] = extensions["rt"]
        result["extensions"] = extensions

    return result


def parse_leef(raw: str) -> dict[str, Any]:
    """
    Parse Log Event Extended Format (LEEF) log.
    Format: LEEF:Version|Vendor|Product|Version|EventID|Extension
    """
    result: dict[str, Any] = {}
    stripped = raw.strip()
    if not stripped.startswith("LEEF:"):
        return {"raw_log": raw, "source_format": "leef"}

    parts = stripped.split("|", 5)
    if len(parts) >= 5:
        result["leef_version"] = parts[0].replace("LEEF:", "")
        result["device_vendor"] = parts[1]
        result["device_product"] = parts[2]
        result["device_version"] = parts[3]
        result["class_name"] = parts[4]

    # LEEF 2.0 uses tab or custom delimiter for extensions
    if len(parts) == 6:
        ext_str = parts[5]
        # Try tab-delimited first, then key=value
        if "\t" in ext_str:
            pairs = ext_str.split("\t")
            extensions = {}
            for pair in pairs:
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    extensions[k.strip()] = v.strip()
        else:
            ext_pairs = re.findall(r"(\w+)=((?:[^\t])*?)(?=\s+\w+=|\s*$)", ext_str)
            extensions = {k: v.strip() for k, v in ext_pairs}

        result["src_ip"] = extensions.get("src", extensions.get("srcIP", ""))
        result["dst_ip"] = extensions.get("dst", extensions.get("dstIP", ""))
        result["src_port"] = _safe_int(extensions.get("srcPort", "0"))
        result["dst_port"] = _safe_int(extensions.get("dstPort", "0"))
        result["protocol"] = extensions.get("proto", "")
        result["username"] = extensions.get("usrName", "")
        result["hostname"] = extensions.get("srcHostName", extensions.get("identHostName", ""))
        result["activity"] = extensions.get("action", "")
        result["severity_hint"] = extensions.get("sev", "MEDIUM").upper()
        result["extensions"] = extensions

    return result


def parse_syslog(raw: str) -> dict[str, Any]:
    """
    Parse syslog messages (RFC 5424 and RFC 3164).
    """
    result: dict[str, Any] = {}
    stripped = raw.strip()

    # Try RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
    rfc5424 = re.match(
        r"^<(\d{1,3})>(\d+)\s+"          # PRI, VERSION
        r"(\S+)\s+"                        # TIMESTAMP
        r"(\S+)\s+"                        # HOSTNAME
        r"(\S+)\s+"                        # APP-NAME
        r"(\S+)\s+"                        # PROCID
        r"(\S+)\s*"                        # MSGID
        r"(.*)",                           # MSG
        stripped, re.DOTALL,
    )
    if rfc5424:
        pri = int(rfc5424.group(1))
        result["facility"] = pri >> 3
        result["syslog_severity"] = pri & 0x07
        result["syslog_version"] = rfc5424.group(2)
        result["timestamp"] = rfc5424.group(3)
        result["hostname"] = rfc5424.group(4)
        result["process_name"] = rfc5424.group(5)
        result["activity"] = rfc5424.group(8)
        result["severity_hint"] = _syslog_severity_map(result["syslog_severity"])
        _extract_syslog_fields(result)
        return result

    # Try RFC 3164: <PRI>TIMESTAMP HOSTNAME MSG
    rfc3164_pri = re.match(
        r"^<(\d{1,3})>"
        r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(\S+)\s+"
        r"(.*)",
        stripped, re.DOTALL,
    )
    if rfc3164_pri:
        pri = int(rfc3164_pri.group(1))
        result["facility"] = pri >> 3
        result["syslog_severity"] = pri & 0x07
        result["timestamp"] = rfc3164_pri.group(2)
        result["hostname"] = rfc3164_pri.group(3)
        result["activity"] = rfc3164_pri.group(4)
        result["severity_hint"] = _syslog_severity_map(result["syslog_severity"])
        _extract_syslog_fields(result)
        return result

    # RFC 3164 without priority
    rfc3164 = re.match(
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(\S+)\s+"
        r"(.*)",
        stripped, re.DOTALL,
    )
    if rfc3164:
        result["timestamp"] = rfc3164.group(1)
        result["hostname"] = rfc3164.group(2)
        result["activity"] = rfc3164.group(3)
        result["severity_hint"] = "MEDIUM"
        _extract_syslog_fields(result)
        return result

    result["activity"] = stripped
    result["severity_hint"] = "MEDIUM"
    return result


def _extract_syslog_fields(result: dict[str, Any]) -> None:
    """Extract common fields from syslog message body."""
    msg = result.get("activity", "")

    # Extract process name from "process[pid]:" pattern
    proc_match = re.match(r"^(\S+?)(?:\[(\d+)\])?:\s*(.*)", msg)
    if proc_match:
        if not result.get("process_name") or result["process_name"] == "-":
            result["process_name"] = proc_match.group(1)
        result["activity"] = proc_match.group(3)

    # Extract IPs
    ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", msg)
    if ips:
        result.setdefault("src_ip", ips[0])
        if len(ips) > 1:
            result.setdefault("dst_ip", ips[1])

    # Extract username patterns
    user_match = re.search(r"(?:user[= ]|for\s+)(\S+)", msg, re.IGNORECASE)
    if user_match:
        result.setdefault("username", user_match.group(1).rstrip(",:"))

    # Extract port
    port_match = re.search(r"port\s+(\d+)", msg, re.IGNORECASE)
    if port_match:
        result.setdefault("src_port", int(port_match.group(1)))


def parse_json_alert(raw: str) -> dict[str, Any]:
    """Parse JSON-formatted alert/log."""
    try:
        data = json.loads(raw.strip())
    except json.JSONDecodeError:
        return {"raw_log": raw, "source_format": "json", "activity": raw[:200]}

    result: dict[str, Any] = {}
    # Map common JSON field names to our schema
    field_map = {
        "src_ip": ["src_ip", "source_ip", "srcip", "src", "source_address", "SrcAddr"],
        "dst_ip": ["dst_ip", "dest_ip", "dstip", "dst", "dest_address", "DstAddr"],
        "src_port": ["src_port", "source_port", "srcport", "spt", "SrcPort"],
        "dst_port": ["dst_port", "dest_port", "dstport", "dpt", "DstPort"],
        "protocol": ["protocol", "proto", "Proto"],
        "username": ["username", "user", "userName", "account_name", "User"],
        "hostname": ["hostname", "host", "computer_name", "Host"],
        "process_name": ["process_name", "process", "Image", "ProcessName"],
        "severity_hint": ["severity", "priority", "risk_level", "Severity"],
        "category": ["category", "event_category", "Category"],
        "class_name": ["event_type", "event_name", "alert_name", "Name", "class_name"],
        "activity": ["message", "msg", "description", "activity", "Message"],
        "timestamp": ["timestamp", "time", "@timestamp", "event_time", "Timestamp"],
        "domain": ["domain", "Domain"],
    }

    for our_field, candidates in field_map.items():
        for candidate in candidates:
            if candidate in data:
                val = data[candidate]
                if our_field in ("src_port", "dst_port"):
                    val = _safe_int(str(val))
                result[our_field] = val
                break

    # Preserve original data as extensions
    result["extensions"] = data
    return result


def parse_windows_xml(raw: str) -> dict[str, Any]:
    """Parse Windows Event Log XML format."""
    result: dict[str, Any] = {}
    try:
        # Strip BOM if present
        cleaned = raw.strip().lstrip("\ufeff")
        root = ElementTree.fromstring(cleaned)
    except ElementTree.ParseError:
        return {"raw_log": raw, "source_format": "windows_xml", "activity": raw[:200]}

    # Handle namespace
    ns = ""
    ns_match = re.match(r"\{(.+?)\}", root.tag)
    if ns_match:
        ns = f"{{{ns_match.group(1)}}}"

    # System section
    system = root.find(f"{ns}System")
    if system is not None:
        provider = system.find(f"{ns}Provider")
        if provider is not None:
            result["process_name"] = provider.get("Name", "")

        event_id_el = system.find(f"{ns}EventID")
        if event_id_el is not None and event_id_el.text:
            result["class_name"] = f"EventID-{event_id_el.text}"
            result["event_id"] = int(event_id_el.text)

        level_el = system.find(f"{ns}Level")
        if level_el is not None and level_el.text:
            level = int(level_el.text)
            severity_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW", 5: "INFO"}
            result["severity_hint"] = severity_map.get(level, "MEDIUM")

        time_el = system.find(f"{ns}TimeCreated")
        if time_el is not None:
            result["timestamp"] = time_el.get("SystemTime", "")

        computer_el = system.find(f"{ns}Computer")
        if computer_el is not None and computer_el.text:
            result["hostname"] = computer_el.text

    # EventData section
    event_data = root.find(f"{ns}EventData")
    if event_data is not None:
        data_items = {}
        for data_el in event_data.findall(f"{ns}Data"):
            name = data_el.get("Name", "")
            value = data_el.text or ""
            data_items[name] = value

        result["username"] = data_items.get("TargetUserName", data_items.get("SubjectUserName", ""))
        result["domain"] = data_items.get("TargetDomainName", data_items.get("SubjectDomainName", ""))
        result["src_ip"] = data_items.get("IpAddress", "")
        result["src_port"] = _safe_int(data_items.get("IpPort", "0"))
        result["activity"] = data_items.get("Status", data_items.get("FailureReason", ""))
        result["extensions"] = data_items

    return result


def _safe_int(val: str) -> int:
    """Safely convert string to int, returning 0 on failure."""
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0


def _syslog_severity_map(sev: int) -> str:
    """Map syslog severity (0-7) to our severity names."""
    mapping = {
        0: "CRITICAL",  # Emergency
        1: "CRITICAL",  # Alert
        2: "CRITICAL",  # Critical
        3: "HIGH",      # Error
        4: "MEDIUM",    # Warning
        5: "LOW",       # Notice
        6: "INFO",      # Informational
        7: "INFO",      # Debug
    }
    return mapping.get(sev, "MEDIUM")
