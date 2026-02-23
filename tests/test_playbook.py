"""Tests for the playbook engine."""

import os
import pytest
from sentinelforge.playbook.engine import (
    Playbook, PlaybookStep, PlaybookEngine, PlaybookExecution, StepStatus,
    load_playbook,
)
from sentinelforge.schemas import OCSFAlert, Severity


@pytest.fixture
def sample_playbook():
    return Playbook(
        name="Test Playbook",
        description="A test playbook",
        steps=[
            PlaybookStep(name="Step 1", action="block_ip", description="Block attacking IP"),
            PlaybookStep(name="Step 2", action="send_notification", description="Notify SOC"),
            PlaybookStep(name="Step 3", action="isolate_host", description="Isolate host", requires_approval=True),
        ],
    )


class TestPlaybookEngine:
    def test_execute_auto_approve(self, sample_playbook):
        engine = PlaybookEngine(auto_approve=True)
        alert = OCSFAlert(src_ip="1.2.3.4", hostname="test-host")
        execution = engine.execute(sample_playbook, alert=alert)
        assert execution.status == "completed"
        assert execution.steps_completed == 3

    def test_execute_with_approval_gate(self, sample_playbook):
        engine = PlaybookEngine(auto_approve=False)
        alert = OCSFAlert(src_ip="1.2.3.4", hostname="test-host")
        execution = engine.execute(sample_playbook, alert=alert)
        assert execution.status == "awaiting_approval"
        assert execution.steps_completed == 2  # Only non-approval steps

    def test_execution_log(self, sample_playbook):
        engine = PlaybookEngine(auto_approve=True)
        execution = engine.execute(sample_playbook, alert=OCSFAlert())
        assert len(execution.log) == 3
        assert all("step" in entry for entry in execution.log)

    def test_step_results(self, sample_playbook):
        engine = PlaybookEngine(auto_approve=True)
        execution = engine.execute(sample_playbook, alert=OCSFAlert(src_ip="1.2.3.4"))
        completed = [e for e in execution.log if e.get("status") == "completed"]
        assert len(completed) == 3
        assert any("[SIMULATED]" in e.get("result", "") for e in completed)

    def test_action_block_ip(self):
        pb = Playbook(name="Test", steps=[PlaybookStep(name="Block", action="block_ip")])
        engine = PlaybookEngine(auto_approve=True)
        execution = engine.execute(pb, alert=OCSFAlert(src_ip="1.2.3.4"))
        assert "BLOCK" in execution.log[0]["result"]

    def test_action_disable_account(self):
        pb = Playbook(name="Test", steps=[PlaybookStep(name="Disable", action="disable_account")])
        engine = PlaybookEngine(auto_approve=True)
        execution = engine.execute(pb, alert=OCSFAlert(username="baduser"))
        assert "baduser" in execution.log[0]["result"]

    def test_to_dict(self, sample_playbook):
        engine = PlaybookEngine(auto_approve=True)
        execution = engine.execute(sample_playbook, alert=OCSFAlert())
        d = execution.to_dict()
        assert d["playbook_name"] == "Test Playbook"
        assert d["status"] == "completed"


class TestPlaybookLoading:
    def test_load_playbook_from_yaml(self):
        playbook_dir = os.path.join(os.path.dirname(__file__), "..", "playbooks")
        if os.path.isdir(playbook_dir):
            for fname in os.listdir(playbook_dir):
                if fname.endswith(".yml"):
                    pb = load_playbook(os.path.join(playbook_dir, fname))
                    if pb:
                        assert pb.name
                        break

    def test_load_nonexistent(self):
        result = load_playbook("/nonexistent/path.yml")
        assert result is None

    def test_from_dict(self):
        data = {
            "name": "Test",
            "description": "Test playbook",
            "steps": [
                {"name": "Step 1", "action": "block_ip", "requires_approval": False},
                {"name": "Step 2", "action": "isolate_host", "requires_approval": True},
            ],
        }
        pb = Playbook.from_dict(data)
        assert pb.name == "Test"
        assert len(pb.steps) == 2
        assert pb.steps[1].requires_approval is True
