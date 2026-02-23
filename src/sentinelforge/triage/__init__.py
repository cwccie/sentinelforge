"""
LLM-based alert triage agent.

Provides severity classification, MITRE ATT&CK mapping, confidence scoring,
and auto-close logic for known benign patterns.
"""

from sentinelforge.triage.agent import TriageAgent, triage_alert

__all__ = ["TriageAgent", "triage_alert"]
