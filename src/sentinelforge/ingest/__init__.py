"""
Multi-format log ingestion pipeline.

Supports: syslog (RFC 5424/3164), CEF, LEEF, JSON, Windows Event XML.
All formats are normalized to OCSF schema and enriched with contextual data.
"""

from sentinelforge.ingest.parsers import parse_log, parse_cef, parse_leef, parse_syslog, parse_json_alert, parse_windows_xml
from sentinelforge.ingest.normalizer import normalize
from sentinelforge.ingest.enrichment import enrich
from sentinelforge.ingest.pipeline import ingest_log, ingest_batch

__all__ = [
    "parse_log", "parse_cef", "parse_leef", "parse_syslog",
    "parse_json_alert", "parse_windows_xml",
    "normalize", "enrich", "ingest_log", "ingest_batch",
]
