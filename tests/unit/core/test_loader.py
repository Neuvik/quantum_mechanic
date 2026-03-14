# ================================================================
# TESTS: quantum_mechanic.core.loader + technique decorator
# ----------------------------------------------------------------
# WHAT:   Tests the @technique decorator and the module loader
#         that discovers technique functions.
#
# WHY:    The module system is how techniques plug in. If the
#         decorator doesn't attach metadata or the loader can't
#         find techniques, no attacks will run.
# ================================================================


import unittest.mock

from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.core.technique import TechniqueMetadata, technique


class TestTechniqueDecorator:
    """Test the @technique decorator."""

    def test_decorator_attaches_metadata(self):
        """The decorator sets __technique__ attribute on the function."""

        @technique(
            technique_id="test/example",
            tactic="discovery",
            providers=["aws"],
        )
        def my_technique(ctx):
            pass

        assert hasattr(my_technique, "__technique__")
        assert isinstance(my_technique.__technique__, TechniqueMetadata)

    def test_metadata_fields(self):
        """All metadata fields are preserved on the decorated function."""

        @technique(
            technique_id="privesc/assume-role",
            tactic="privilege_escalation",
            providers=["aws", "azure"],
            severity="high",
            mitre_id="T1548",
            safe=False,
            description="Escalate via role assumption",
            safe_mode_available=True,
        )
        def escalate(ctx):
            pass

        meta = escalate.__technique__
        assert meta.id == "privesc/assume-role"
        assert meta.tactic == "privilege_escalation"
        assert meta.providers == ["aws", "azure"]
        assert meta.severity == "high"
        assert meta.mitre_id == "T1548"
        assert meta.safe is False
        assert meta.safe_mode_available is True

    def test_decorator_preserves_function(self):
        """The decorated function is still callable and works."""

        @technique(
            technique_id="test/callable",
            tactic="discovery",
            providers=["aws"],
        )
        def returns_value(ctx):
            return "hello"

        assert returns_value("fake_ctx") == "hello"

    def test_defaults(self):
        """Default values for optional fields."""

        @technique(
            technique_id="test/defaults",
            tactic="discovery",
            providers=["aws"],
        )
        def minimal(ctx):
            pass

        meta = minimal.__technique__
        assert meta.severity == "info"
        assert meta.safe is True
        assert meta.mitre_id is None
        assert meta.description == ""


class TestTechniqueLoader:
    """Test the module loader that discovers techniques."""

    def test_load_discovers_whoami(self):
        """The loader finds the discovery/whoami technique."""
        loader = TechniqueLoader()
        count = loader.load_all()
        assert count >= 1

        whoami = loader.get("discovery/whoami")
        assert whoami is not None
        assert whoami.metadata.id == "discovery/whoami"
        assert whoami.metadata.tactic == "Discovery"

    def test_list_all(self):
        """list_all returns all discovered techniques."""
        loader = TechniqueLoader()
        loader.load_all()
        techniques = loader.list_all()
        assert len(techniques) >= 1
        ids = [t.metadata.id for t in techniques]
        assert "discovery/whoami" in ids

    def test_get_missing_returns_none(self):
        """Getting a nonexistent technique returns None."""
        loader = TechniqueLoader()
        loader.load_all()
        assert loader.get("nonexistent/technique") is None

    def test_list_by_tactic(self):
        """Filtering by tactic returns only matching techniques."""
        loader = TechniqueLoader()
        loader.load_all()
        discovery = loader.list_by_tactic("Discovery")
        assert len(discovery) >= 1
        assert all(t.metadata.tactic == "Discovery" for t in discovery)

    def test_list_by_provider(self):
        """Filtering by provider returns techniques supporting it."""
        loader = TechniqueLoader()
        loader.load_all()
        aws_techniques = loader.list_by_provider("aws")
        assert len(aws_techniques) >= 1
        assert all("aws" in t.metadata.providers for t in aws_techniques)

    def test_technique_is_callable(self):
        """Discovered technique functions are callable."""
        loader = TechniqueLoader()
        loader.load_all()
        whoami = loader.get("discovery/whoami")
        assert callable(whoami.function)

    def test_load_all_no_techniques_package(self):
        """If quantum_mechanic.techniques package does not exist, returns 0."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "quantum_mechanic.techniques":
                raise ImportError("No module named quantum_mechanic.techniques")
            return original_import(name, *args, **kwargs)

        with unittest.mock.patch('builtins.__import__', side_effect=mock_import):
            loader = TechniqueLoader()
            count = loader.load_all()
            assert count == 0

    @unittest.mock.patch('importlib.import_module')
    def test_load_all_handles_import_errors(self, mock_import):
        """Module import failures are caught gracefully and skipped."""
        mock_import.side_effect = Exception("broken module")
        loader = TechniqueLoader()
        # This shouldn't crash
        count = loader.load_all()
        assert count == 0
