"""
Ingestion pipeline — orchestrates parse -> normalize -> enrich -> store.
"""

from __future__ import annotations

from sentinelforge.ingest.parsers import parse_log
from sentinelforge.ingest.normalizer import normalize
from sentinelforge.ingest.enrichment import enrich
from sentinelforge.schemas import OCSFAlert
from sentinelforge.store import alert_store


def ingest_log(raw: str, auto_store: bool = True) -> OCSFAlert:
    """
    Full ingestion pipeline for a single raw log line.

    1. Parse (auto-detect format)
    2. Normalize to OCSF
    3. Enrich with context
    4. Store in alert store
    """
    parsed = parse_log(raw)
    alert = normalize(parsed)
    alert = enrich(alert)
    if auto_store:
        alert_store.add(alert)
    return alert


def ingest_batch(logs: list[str], auto_store: bool = True) -> list[OCSFAlert]:
    """Ingest a batch of raw log lines."""
    return [ingest_log(log, auto_store=auto_store) for log in logs]
