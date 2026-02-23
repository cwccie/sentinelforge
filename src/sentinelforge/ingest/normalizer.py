"""
OCSF normalization — converts parsed fields into OCSFAlert objects.
"""

from __future__ import annotations

from sentinelforge.schemas import OCSFAlert, Severity


_SEVERITY_MAP = {
    "INFO": Severity.INFO,
    "INFORMATIONAL": Severity.INFO,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
    "EMERGENCY": Severity.CRITICAL,
    "ALERT": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "NOTICE": Severity.LOW,
    "DEBUG": Severity.INFO,
}


def normalize(parsed: dict) -> OCSFAlert:
    """
    Convert a parsed log dictionary into a normalized OCSFAlert.

    Maps vendor-specific field names to OCSF fields and resolves severity.
    """
    alert = OCSFAlert()

    # Direct field mappings
    simple_fields = [
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "username", "hostname", "domain", "process_name",
        "category", "class_name", "activity", "source_format",
        "raw_log",
    ]
    for field_name in simple_fields:
        if field_name in parsed and parsed[field_name]:
            setattr(alert, field_name, parsed[field_name])

    # Timestamp
    if "timestamp" in parsed and parsed["timestamp"]:
        alert.timestamp = str(parsed["timestamp"])

    # Severity resolution
    severity_hint = parsed.get("severity_hint", "MEDIUM")
    if isinstance(severity_hint, str):
        alert.severity = _SEVERITY_MAP.get(severity_hint.upper(), Severity.MEDIUM)
    elif isinstance(severity_hint, int):
        try:
            alert.severity = Severity(severity_hint)
        except ValueError:
            alert.severity = Severity.MEDIUM

    # Derive category from activity/class_name if not set
    if not alert.category and alert.activity:
        alert.category = _infer_category(alert.activity, alert.class_name)

    # Store extensions in enrichments
    if "extensions" in parsed:
        alert.enrichments["original_fields"] = parsed["extensions"]

    return alert


def _infer_category(activity: str, class_name: str) -> str:
    """Infer alert category from activity description."""
    text = f"{activity} {class_name}".lower()
    categories = [
        (["login", "logon", "auth", "password", "credential", "sshd", "pam"], "Authentication"),
        (["dns", "query", "resolve", "nxdomain"], "DNS Activity"),
        (["firewall", "drop", "deny", "block", "reject", "iptables"], "Firewall"),
        (["malware", "virus", "trojan", "ransomware", "exploit"], "Malware"),
        (["connection", "connect", "syn", "tcp", "udp", "port"], "Network Activity"),
        (["file", "write", "read", "create", "delete", "modify"], "File Activity"),
        (["process", "exec", "spawn", "cmd", "powershell", "bash"], "Process Activity"),
        (["privilege", "sudo", "admin", "elevat", "escalat"], "Privilege Escalation"),
        (["email", "smtp", "phish", "spam"], "Email"),
        (["exfil", "upload", "transfer", "leak"], "Data Exfiltration"),
    ]
    for keywords, category in categories:
        if any(kw in text for kw in keywords):
            return category
    return "Security Alert"
