# ================================================================
# TESTS: core telemetry bus
# ================================================================

import pytest
from unittest.mock import MagicMock
from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.telemetry import TelemetryType, TelemetryLevel

def test_execution_context_telemetry_emission():
    """Verify that ExecutionContext helper methods emit structured events."""
    mock_workspace = MagicMock()
    mock_provider = MagicMock()
    mock_provider.provider_name = "aws"
    
    events = []
    def callback(ev):
        events.append(ev)
        
    ctx = ExecutionContext(
        workspace=mock_workspace,
        credential_id=1,
        provider=mock_provider,
        session=None,
        technique_id="test/tech",
        on_event=callback
    )
    
    # 1. Test info()
    ctx.info("hello world", data={"foo": "bar"})
    assert events[-1].event_type == TelemetryType.LOG
    assert events[-1].level == TelemetryLevel.INFO
    assert events[-1].message == "hello world"
    assert events[-1].data["foo"] == "bar"
    
    # 2. Test success()
    ctx.success("done")
    assert events[-1].level == TelemetryLevel.SUCCESS
    
    # 3. Test discovery()
    ctx.discovery("bucket", "my-bucket")
    assert events[-1].event_type == TelemetryType.DISCOVERY
    assert events[-1].data["asset_type"] == "bucket"
    
    # 4. Test finding()
    ctx.finding("Critical Hole", "critical")
    assert events[-1].event_type == TelemetryType.FINDING
    assert events[-1].level == TelemetryLevel.ERROR
