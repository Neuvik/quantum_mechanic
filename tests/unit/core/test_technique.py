# ================================================================
# TESTS: quantum_mechanic.core.technique
# ----------------------------------------------------------------
# WHAT:   Tests the @technique decorator and TechniqueMetadata
#         dataclass — the contract every technique module must satisfy.
#
# WHY:    The decorator is the foundation of the entire technique
#         registry. If metadata attachment or wrapping breaks, no
#         technique can be discovered or executed.
#
# ANTI-GAMIFICATION: We test observable behaviour — attribute access,
#   function call-through, metadata field values, and edge cases.
# ================================================================

from __future__ import annotations

import pytest

from quantum_mechanic.core.technique import TechniqueMetadata, technique


# ================================================================
# TechniqueMetadata dataclass
# ================================================================

class TestTechniqueMetadata:
    def test_required_fields(self):
        """TechniqueMetadata stores id, tactic, and providers."""
        m = TechniqueMetadata(
            id="discovery/whoami",
            tactic="discovery",
            providers=["aws", "azure"],
        )
        assert m.id == "discovery/whoami"
        assert m.tactic == "discovery"  # TechniqueMetadata stores raw — normalization is in @technique
        assert m.providers == ["aws", "azure"]

    def test_default_severity_is_info(self):
        """Severity defaults to 'info'."""
        m = TechniqueMetadata(id="x/y", tactic="t", providers=["aws"])
        assert m.severity == "info"

    def test_default_safe_is_true(self):
        """Techniques are safe by default."""
        m = TechniqueMetadata(id="x/y", tactic="t", providers=["aws"])
        assert m.safe is True

    def test_default_exploit_pack_is_false(self):
        """exploit_pack is False by default."""
        m = TechniqueMetadata(id="x/y", tactic="t", providers=["aws"])
        assert m.exploit_pack is False

    def test_frozen_prevents_mutation(self):
        """TechniqueMetadata is frozen — attribute mutation raises."""
        m = TechniqueMetadata(id="x/y", tactic="t", providers=["aws"])
        with pytest.raises((AttributeError, TypeError)):
            m.severity = "critical"  # type: ignore[misc]

    def test_equality(self):
        """Two metadata instances with identical fields are equal."""
        a = TechniqueMetadata(id="x/y", tactic="t", providers=["aws"])
        b = TechniqueMetadata(id="x/y", tactic="t", providers=["aws"])
        assert a == b

    def test_all_optional_fields(self):
        """All optional fields can be set."""
        m = TechniqueMetadata(
            id="escalation/assume",
            tactic="privilege-escalation",
            providers=["aws"],
            severity="high",
            mitre_id="T1548",
            safe=False,
            description="Assumes a role via trust policy.",
            safe_mode_available=True,
            exploit_pack=True,
        )
        assert m.severity == "high"
        assert m.mitre_id == "T1548"
        assert m.safe is False
        assert m.safe_mode_available is True
        assert m.exploit_pack is True
        assert "Assumes" in m.description


# ================================================================
# @technique decorator
# ================================================================

class TestTechniqueDecorator:
    def test_attaches_technique_attribute(self):
        """Decorated function gets a __technique__ attribute."""
        @technique(
            technique_id="discovery/test",
            tactic="discovery",
            providers=["aws"],
        )
        def execute(ctx):
            return {}

        assert hasattr(execute, "__technique__")

    def test_metadata_values_match_decorator_args(self):
        """__technique__ metadata reflects the decorator arguments."""
        @technique(
            technique_id="discovery/enum_iam",
            tactic="discovery",
            providers=["aws", "gcp"],
            severity="medium",
            mitre_id="T1087",
            safe=True,
            description="Enumerate IAM permissions.",
        )
        def execute(ctx):
            return {}

        m = execute.__technique__
        assert m.id == "discovery/enum_iam"
        assert m.tactic == "Discovery"  # @technique normalizes to Title Case
        assert m.providers == ["aws", "gcp"]
        assert m.severity == "medium"
        assert m.mitre_id == "T1087"
        assert m.safe is True
        assert "Enumerate" in m.description

    def test_decorated_function_is_callable(self):
        """The decorated function can still be called normally."""
        @technique(
            technique_id="discovery/test",
            tactic="discovery",
            providers=["aws"],
        )
        def execute(ctx):
            return {"called": True}

        result = execute("fake_ctx")
        assert result == {"called": True}

    def test_functools_wraps_preserves_name(self):
        """@functools.wraps preserves __name__ and __doc__."""
        @technique(
            technique_id="discovery/test",
            tactic="discovery",
            providers=["aws"],
        )
        def execute(ctx):
            """My technique docstring."""
            return {}

        assert execute.__name__ == "execute"
        assert "My technique docstring" in (execute.__doc__ or "")

    def test_multiple_decorations_are_independent(self):
        """Two decorated functions have independent metadata."""
        @technique(
            technique_id="discovery/a",
            tactic="discovery",
            providers=["aws"],
        )
        def func_a(ctx):
            return {}

        @technique(
            technique_id="escalation/b",
            tactic="privilege-escalation",
            providers=["azure"],
            severity="critical",
        )
        def func_b(ctx):
            return {}

        assert func_a.__technique__.id == "discovery/a"
        assert func_b.__technique__.id == "escalation/b"
        assert func_a.__technique__.severity == "info"
        assert func_b.__technique__.severity == "critical"

    def test_exploit_pack_flag_propagates(self):
        """exploit_pack=True is stored in metadata."""
        @technique(
            technique_id="initial_access/example_exploit",
            tactic="initial-access",
            providers=["any"],
            exploit_pack=True,
        )
        def execute(ctx):
            return {}

        assert execute.__technique__.exploit_pack is True

    def test_safe_mode_available_flag_propagates(self):
        """safe_mode_available=True is stored in metadata."""
        @technique(
            technique_id="discovery/check_only",
            tactic="discovery",
            providers=["aws"],
            safe_mode_available=True,
        )
        def execute(ctx):
            return {}

        assert execute.__technique__.safe_mode_available is True

    def test_decorated_function_passes_args_through(self):
        """Arguments are forwarded correctly to the original function."""
        calls = []

        @technique(
            technique_id="discovery/test",
            tactic="discovery",
            providers=["aws"],
        )
        def execute(ctx, *, flag=False):
            calls.append((ctx, flag))
            return ctx

        result = execute("my_ctx", flag=True)
        assert result == "my_ctx"
        assert calls == [("my_ctx", True)]
