"""
Alert enrichment — adds contextual data to normalized alerts.

Includes GeoIP lookup (mock), threat intelligence, and asset context.
In production, these would call real APIs (MaxMind, VirusTotal, CMDB).
"""

from __future__ import annotations

import ipaddress
from typing import Any

from sentinelforge.schemas import OCSFAlert, Severity


# Mock threat intel database — known malicious IPs/domains
_THREAT_INTEL_DB: dict[str, dict[str, Any]] = {
    "198.51.100.23": {"threat_type": "C2 Server", "confidence": 0.95, "source": "AlienVault OTX", "last_seen": "2026-02-20"},
    "203.0.113.66": {"threat_type": "Botnet Controller", "confidence": 0.88, "source": "Abuse.ch", "last_seen": "2026-02-18"},
    "192.0.2.99": {"threat_type": "Scanner", "confidence": 0.72, "source": "Shodan", "last_seen": "2026-02-15"},
    "10.0.0.0/8": {"threat_type": "Internal", "confidence": 0.0, "source": "RFC1918"},
    "172.16.0.0/12": {"threat_type": "Internal", "confidence": 0.0, "source": "RFC1918"},
    "192.168.0.0/16": {"threat_type": "Internal", "confidence": 0.0, "source": "RFC1918"},
}

# Mock GeoIP database
_GEOIP_DB: dict[str, dict[str, str]] = {
    "198.51.100.23": {"country": "RU", "city": "Moscow", "asn": "AS12345", "org": "Suspicious Hosting Ltd"},
    "203.0.113.66": {"country": "CN", "city": "Shanghai", "asn": "AS67890", "org": "Cloud Provider Co"},
    "192.0.2.99": {"country": "NL", "city": "Amsterdam", "asn": "AS11111", "org": "VPS Provider"},
    "8.8.8.8": {"country": "US", "city": "Mountain View", "asn": "AS15169", "org": "Google LLC"},
    "1.1.1.1": {"country": "AU", "city": "Sydney", "asn": "AS13335", "org": "Cloudflare Inc"},
}

# Mock asset inventory
_ASSET_DB: dict[str, dict[str, Any]] = {
    "10.0.1.10": {"asset_type": "workstation", "owner": "jdoe", "department": "Engineering", "criticality": "medium"},
    "10.0.1.50": {"asset_type": "server", "owner": "ops-team", "department": "IT", "criticality": "high", "role": "domain-controller"},
    "10.0.2.100": {"asset_type": "server", "owner": "ops-team", "department": "IT", "criticality": "critical", "role": "database"},
    "10.0.1.25": {"asset_type": "workstation", "owner": "admin1", "department": "IT", "criticality": "high"},
    "192.168.1.100": {"asset_type": "workstation", "owner": "ceo", "department": "Executive", "criticality": "critical"},
}


def enrich(alert: OCSFAlert) -> OCSFAlert:
    """
    Enrich an alert with GeoIP, threat intelligence, and asset context.
    """
    # GeoIP enrichment
    if alert.src_ip:
        alert.geo_src = _lookup_geoip(alert.src_ip)
    if alert.dst_ip:
        alert.geo_dst = _lookup_geoip(alert.dst_ip)

    # Threat intelligence
    threat_matches = []
    for ip in [alert.src_ip, alert.dst_ip]:
        if ip:
            ti = _lookup_threat_intel(ip)
            if ti and ti.get("confidence", 0) > 0:
                threat_matches.append({"ip": ip, **ti})

    if threat_matches:
        alert.threat_intel = {
            "matches": threat_matches,
            "max_confidence": max(m["confidence"] for m in threat_matches),
            "threat_types": list(set(m["threat_type"] for m in threat_matches)),
        }
        # Bump severity if threat intel matches
        if alert.threat_intel["max_confidence"] > 0.8:
            if alert.severity < Severity.HIGH:
                alert.severity = Severity.HIGH
                alert.tags.append("threat-intel-match")

    # Asset context
    for ip in [alert.src_ip, alert.dst_ip]:
        if ip and ip in _ASSET_DB:
            alert.asset_context = _ASSET_DB[ip]
            if _ASSET_DB[ip].get("criticality") == "critical":
                alert.tags.append("critical-asset")
                if alert.severity < Severity.HIGH:
                    alert.severity = Severity.HIGH

    return alert


def _lookup_geoip(ip: str) -> dict[str, str]:
    """Mock GeoIP lookup."""
    if ip in _GEOIP_DB:
        return _GEOIP_DB[ip]
    # Check if private
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            return {"country": "INTERNAL", "city": "RFC1918", "asn": "N/A", "org": "Internal Network"}
    except ValueError:
        pass
    return {"country": "UNKNOWN", "city": "Unknown", "asn": "N/A", "org": "Unknown"}


def _lookup_threat_intel(ip: str) -> dict[str, Any]:
    """Mock threat intelligence lookup."""
    # Direct match
    if ip in _THREAT_INTEL_DB:
        return _THREAT_INTEL_DB[ip]
    # CIDR match
    try:
        addr = ipaddress.ip_address(ip)
        for cidr, info in _THREAT_INTEL_DB.items():
            if "/" in cidr:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return info
    except ValueError:
        pass
    return {}
