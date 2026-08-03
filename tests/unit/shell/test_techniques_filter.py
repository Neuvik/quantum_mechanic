"""Tests for `techniques` filtering / search."""
from unittest.mock import MagicMock, patch

from quantum_mechanic.shell.commands import cmd_techniques


def _meta(tid, tactic, providers, safe=True, description=""):
    """Build a fake TechniqueMetadata."""
    m = MagicMock()
    m.id = tid
    m.tactic = tactic
    m.providers = providers
    m.safe = safe
    m.description = description or tid
    return m


def _make_state(techniques):
    state = MagicMock()
    state.transport.list_techniques.return_value = techniques
    state.active_credential_id = None  # no active filter
    state._extra_providers = set()
    return state


def test_techniques_no_args_uses_active_provider():
    """OUTCOME: With no args and an active credential, filters to that provider."""
    state = _make_state([])
    state.active_credential_id = 1
    state.transport.list_credentials.return_value = [{"id": 1, "provider": "azure"}]
    with patch("quantum_mechanic.shell.commands.formatters"):
        cmd_techniques(state, [])
    state.transport.list_techniques.assert_called_with(provider="azure")


def test_techniques_all_flag_overrides_provider_filter():
    """OUTCOME: --all ignores active provider, lists all techniques."""
    state = _make_state([_meta("discovery/whoami", "discovery", ["aws"]),
                         _meta("discovery/x", "discovery", ["azure"])])
    state.active_credential_id = 1
    state.transport.list_credentials.return_value = [{"id": 1, "provider": "aws"}]
    with patch("quantum_mechanic.shell.commands.formatters"):
        cmd_techniques(state, ["--all"])
    state.transport.list_techniques.assert_called_with(provider=None)


def test_techniques_tactic_flag_filters_by_tactic():
    """OUTCOME: --tactic discovery → only discovery techniques."""
    techs = [
        _meta("discovery/whoami", "discovery", ["aws"]),
        _meta("escalation/x", "escalation", ["aws"]),
    ]
    state = _make_state(techs)
    with patch("quantum_mechanic.shell.commands.formatters") as mock_fmt:
        cmd_techniques(state, ["--all", "--tactic", "discovery"])
    rendered = mock_fmt.format_techniques_list.call_args.args[0]
    ids = [t.metadata.id for t in rendered]
    assert ids == ["discovery/whoami"]


def test_techniques_safe_flag_filters_to_safe_only():
    """OUTCOME: --safe → only safe techniques."""
    techs = [
        _meta("discovery/whoami", "discovery", ["aws"], safe=True),
        _meta("escalation/x", "escalation", ["aws"], safe=False),
    ]
    state = _make_state(techs)
    with patch("quantum_mechanic.shell.commands.formatters") as mock_fmt:
        cmd_techniques(state, ["--all", "--safe"])
    rendered = mock_fmt.format_techniques_list.call_args.args[0]
    ids = [t.metadata.id for t in rendered]
    assert ids == ["discovery/whoami"]


def test_techniques_unsafe_flag_filters_to_unsafe_only():
    """OUTCOME: --unsafe → only state-changing techniques."""
    techs = [
        _meta("discovery/whoami", "discovery", ["aws"], safe=True),
        _meta("escalation/x", "escalation", ["aws"], safe=False),
    ]
    state = _make_state(techs)
    with patch("quantum_mechanic.shell.commands.formatters") as mock_fmt:
        cmd_techniques(state, ["--all", "--unsafe"])
    rendered = mock_fmt.format_techniques_list.call_args.args[0]
    ids = [t.metadata.id for t in rendered]
    assert ids == ["escalation/x"]


def test_techniques_positional_substring_matches_id_and_description():
    """OUTCOME: `techniques whoami` matches both id and description."""
    techs = [
        _meta("discovery/whoami", "discovery", ["aws"], description="Identify principal"),
        _meta("discovery/enum_iam", "discovery", ["aws"], description="Whoami-like IAM dump"),
        _meta("escalation/x", "escalation", ["aws"], description="something else"),
    ]
    state = _make_state(techs)
    with patch("quantum_mechanic.shell.commands.formatters") as mock_fmt:
        cmd_techniques(state, ["--all", "whoami"])
    rendered = mock_fmt.format_techniques_list.call_args.args[0]
    ids = [t.metadata.id for t in rendered]
    assert set(ids) == {"discovery/whoami", "discovery/enum_iam"}


def test_techniques_combined_filters_intersect():
    """OUTCOME: --tactic discovery --safe whoami all apply (AND semantics)."""
    techs = [
        _meta("discovery/whoami", "discovery", ["aws"], safe=True),
        _meta(
            "discovery/dangerous", "discovery", ["aws"], safe=False, description="whoami imitator"
        ),
        _meta("escalation/whoami_abuse", "escalation", ["aws"], safe=False),
    ]
    state = _make_state(techs)
    with patch("quantum_mechanic.shell.commands.formatters") as mock_fmt:
        cmd_techniques(state, ["--all", "--tactic", "discovery", "--safe", "whoami"])
    rendered = mock_fmt.format_techniques_list.call_args.args[0]
    ids = [t.metadata.id for t in rendered]
    assert ids == ["discovery/whoami"]
