"""
Event correlation engine — groups related alerts into incidents.
"""

from sentinelforge.correlate.engine import CorrelationEngine, correlate_alerts

__all__ = ["CorrelationEngine", "correlate_alerts"]
