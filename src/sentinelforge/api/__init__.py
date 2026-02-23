"""
REST API for SentinelForge — alert submission, incident management, playbook control.
"""

from sentinelforge.api.routes import create_api_app

__all__ = ["create_api_app"]
