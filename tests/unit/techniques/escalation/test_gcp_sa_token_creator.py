"""
Unit tests for escalation/gcp_sa_token_creator.

Generated scaffold — fill in the mocks and assertions per cloud.
"""
from unittest.mock import MagicMock

import pytest

from quantum_mechanic.techniques.escalation.gcp_sa_token_creator import execute


# ---------------------------------------------------------------------------
# Happy path — one stub per provider
# ---------------------------------------------------------------------------
def test_gcp_success():
    ctx = MagicMock()
    ctx.provider_name = 'gcp'
    # TODO: configure ctx mocks for the gcp path
    # execute(ctx)
    # ctx.finding.assert_called_once()
    pytest.skip("not implemented yet — fill in mocks")


