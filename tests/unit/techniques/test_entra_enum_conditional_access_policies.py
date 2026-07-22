# ================================================================
# TESTS: quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies
# ================================================================

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies import (
    execute,
    tbl_data,
)

def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=1)

def _make_token(token_type: str = "access_token", foci: bool = False) -> EntraToken:
    return EntraToken(
        token_type=token_type,
        value="eyJ.fake",
        resource=GRAPH,
        tenant_id="t",
        client_id=FOCI_DEFAULT_CLIENT,
        expires_at=_future(),
        foci=foci,
    )

def _make_store(token: EntraToken | None = None) -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="t")
    if token:
        store.add_token(token)
    return store

def _build_ctx(store: EntraTokenStore) -> MagicMock:
    ctx = MagicMock(spec=ExecutionContext)
    ctx.provider_name = "entra"
    ctx.session = store
    ctx.log_api_call = MagicMock()
    ctx.info = MagicMock()
    return ctx

class TestNoToken:
    def test_returns_error(self):
        store = _make_store()
        ctx = _build_ctx(store)
        result = execute(ctx)
        assert "error" in result

class TestFociExpansion:
    def test_error_when_expansion_fails(self):
        store = _make_store(_make_token("refresh_token", foci=True))
        ctx = _build_ctx(store)
        with patch("quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies.foci_expand", return_value=None):
            result = execute(ctx)
        assert "error" in result

    def test_uses_expanded_token(self):
        store = _make_store(_make_token("refresh_token", foci=True))
        ctx = _build_ctx(store)
        expanded = _make_token("access_token")
        
        mock_policies = [
            {
                "id": "policy-1",
                "displayName": "MFA Policy",
                "state": "enabled",
                "grantControls": {"builtInControls": ["mfa"]},
                "conditions": {
                    "users": {
                        "includeUsers": ["All"],
                        "excludeUsers": ["user-exclude-1"]
                    }
                }
            }
        ]
        
        def _mock_graph_list(http, url, headers):
            if "roleDefinitions" in url:
                return []
            if "namedLocations" in url:
                return []
            return mock_policies

        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies.foci_expand",
            return_value=expanded,
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies.graph_list",
            side_effect=_mock_graph_list
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies.resolve_directory_objects",
            return_value={"user-exclude-1": "Resolved User 1"}
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies.httpx.Client",
            return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
        ):
            result = execute(ctx)
        
        assert result["status"] == "success"
        assert result["provider"] == "entra"
        assert len(result["policies"]) == 1
        assert result["policies"][0]["display_name"] == "MFA Policy"
        assert result["policies"][0]["excluded_users"] == "Resolved User 1"

class TestSuccess:
    def test_enumerates_conditional_access_policies(self):
        store = _make_store(_make_token("access_token"))
        ctx = _build_ctx(store)

        mock_policies = [
            {
                "id": "policy-1",
                "displayName": "MFA Policy",
                "state": "enabled",
                "grantControls": {"builtInControls": ["mfa"]},
                "conditions": {
                    "users": {
                        "includeUsers": ["All"],
                        "excludeUsers": ["user-exclude-1"],
                        "includeGroups": ["group-include-1"],
                        "excludeGroups": ["group-exclude-1"],
                        "includeRoles": ["role-include-1"],
                        "excludeRoles": ["role-exclude-1"]
                    }
                }
            }
        ]

        def _mock_graph_list(http, url, headers):
            if "roleDefinitions" in url:
                return [
                    {"templateId": "role-include-1", "id": "instantiated-role-1", "displayName": "Resolved Role 1"},
                    {"templateId": "role-exclude-1", "id": "instantiated-role-2", "displayName": "Resolved Role 2"}
                ]
            if "namedLocations" in url:
                return []
            return mock_policies

        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies.graph_list",
            side_effect=_mock_graph_list
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies.resolve_directory_objects",
            return_value={
                "user-exclude-1": "Resolved User 1",
                "group-include-1": "Resolved Group 1",
                "group-exclude-1": "Resolved Group 2"
            }
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies.httpx.Client",
            return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
        ):
            result = execute(ctx)

        assert result["status"] == "success"
        assert result["provider"] == "entra"
        assert len(result["policies"]) == 1
        
        p = result["policies"][0]
        assert p["display_name"] == "MFA Policy"
        assert p["state"] == "enabled"
        assert p["grant_controls"] == "mfa"
        assert p["included_users"] == "All"
        assert p["excluded_users"] == "Resolved User 1"
        assert p["included_groups"] == "Resolved Group 1"
        assert p["excluded_groups"] == "Resolved Group 2"
        assert p["included_roles"] == "Resolved Role 1"
        assert p["excluded_roles"] == "Resolved Role 2"

    def test_tbl_data_helper(self):
        parsed = [
            {
                "display_name": "MFA Policy",
                "state": "enabled",
                "grant_controls": "mfa",
                "included_users": "All",
                "excluded_users": "Resolved User 1",
                "included_groups": "Resolved Group 1",
                "excluded_groups": "Resolved Group 2",
                "included_roles": "Resolved Role 1",
                "excluded_roles": "Resolved Role 2",
                "id": "policy-1"
            }
        ]
        
        transformed = tbl_data(parsed)
        assert len(transformed) == 1
        row = transformed[0]
        assert row["included_users"] == "All"
        assert row["excluded_users"] == "Resolved User 1"
        assert row["included_groups"] == "1"
        assert row["excluded_groups"] == "Resolved Group 2"
        assert row["included_roles"] == "Resolved Role 1"
        assert row["excluded_roles"] == "Resolved Role 2"

class TestResolveDirectoryObjects:
    def test_resolves_via_post_request(self):
        from quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies import resolve_directory_objects
        
        mock_http = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "value": [
                {"id": "guid-1", "userPrincipalName": "user1@target-org.example"},
                {"id": "guid-2", "displayName": "Group 2"}
            ]
        }
        mock_http.request.return_value = mock_resp
        
        res = resolve_directory_objects(mock_http, {}, ["guid-1", "guid-2"])
        assert res["guid-1"] == "user1@target-org.example"
        assert res["guid-2"] == "Group 2"

    def test_resolves_via_fallbacks(self):
        from quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies import resolve_directory_objects
        
        mock_http = MagicMock()
        
        # 1st call (POST getByIds) fails with 403 Forbidden to trigger individual fallbacks
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 403
        
        # Responses for GET requests:
        # group-1 -> 200 Group Name
        # user-1 -> 404 (not group), then 200 User Name
        # sp-1 -> 404, 404, 200 SP Name
        # do-1 -> 404, 404, 404, 200 DO Name
        # dr-1 -> 404, 404, 404, 404, 200 DR Name
        # rd-1 -> 404, 404, 404, 404, 404, 200 RD Name
        # dev-1 -> 404, 404, 404, 404, 404, 404, 200 Device Name
        
        calls = []
        def mock_request(method, url, **kwargs):
            calls.append((method, url))
            resp = MagicMock()
            if method == "POST":
                resp.status_code = 403
            else:
                resp.status_code = 404
                if "groups/guid-group" in url:
                    resp.status_code = 200
                    resp.json.return_value = {"displayName": "Fallback Group"}
                elif "users/guid-user" in url:
                    resp.status_code = 200
                    resp.json.return_value = {"userPrincipalName": "fallback_user@target-org.example"}
                elif "servicePrincipals/guid-sp" in url:
                    resp.status_code = 200
                    resp.json.return_value = {"displayName": "Fallback SP"}
                elif "directoryObjects/guid-do" in url:
                    resp.status_code = 200
                    resp.json.return_value = {"displayName": "Fallback DO"}
                elif "directoryRoles/guid-dr" in url:
                    resp.status_code = 200
                    resp.json.return_value = {"displayName": "Fallback DR"}
                elif "roleDefinitions/guid-rd" in url:
                    resp.status_code = 200
                    resp.json.return_value = {"displayName": "Fallback RD"}
                elif "devices/guid-dev" in url:
                    resp.status_code = 200
                    resp.json.return_value = {"displayName": "Fallback Device"}
                elif "directory/deletedItems/guid-del" in url:
                    resp.status_code = 200
                    resp.json.return_value = {"displayName": "Fallback Deleted Object"}
            return resp

        mock_http.request.side_effect = mock_request
        
        target_ids = ["guid-group", "guid-user", "guid-sp", "guid-do", "guid-dr", "guid-rd", "guid-dev", "guid-del"]
        res = resolve_directory_objects(mock_http, {}, target_ids)
        
        assert res["guid-group"] == "Fallback Group"
        assert res["guid-user"] == "fallback_user@target-org.example"
        assert res["guid-sp"] == "Fallback SP"
        assert res["guid-do"] == "Fallback DO"
        assert res["guid-dr"] == "Fallback DR"
        assert res["guid-rd"] == "Fallback RD"
        assert res["guid-dev"] == "Fallback Device"
        assert res["guid-del"] == "Fallback Deleted Object (Deleted)"

class TestLoadLootMappings:
    def test_loads_from_csv(self, tmp_path):
        from quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies import load_loot_mappings
        
        # Setup temporary loot files
        ws_dir = tmp_path / "test-workspace"
        ws_dir.mkdir()
        loot_dir = ws_dir / "loot"
        
        users_dir = loot_dir / "discovery" / "entra_enum_users"
        users_dir.mkdir(parents=True)
        with (users_dir / "loot.csv").open("w", encoding="utf-8") as f:
            f.write("id,userPrincipalName\n")
            f.write("user-id-1,user@target-org.example\n")
            
        groups_dir = loot_dir / "discovery" / "entra_enum_groups"
        groups_dir.mkdir(parents=True)
        with (groups_dir / "loot.csv").open("w", encoding="utf-8") as f:
            f.write("id,displayName\n")
            f.write("group-id-1,Group Test Name\n")
            
        db_path = tmp_path / "test-workspace.db"
        
        mapping = load_loot_mappings(db_path)
        assert mapping["user-id-1"] == "user@target-org.example"
        assert mapping["group-id-1"] == "Group Test Name"

    def test_loads_from_db(self, tmp_path):
        from quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies import load_loot_mappings
        import sqlite3
        import json

        db_path = tmp_path / "test-db.db"
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT,
                technique_id TEXT,
                credential_id INTEGER,
                timestamp TEXT,
                output_json TEXT
            )
            """
        )
        # Insert entra_enum_users output
        users_data = {
            "users": [
                {"id": "db-user-id-1", "userPrincipalName": "db-user@target-org.example"}
            ]
        }
        cursor.execute(
            "INSERT INTO evidence (technique_id, output_json) VALUES (?, ?)",
            ("discovery/entra_enum_users", json.dumps(users_data))
        )
        # Insert unified_enum_groups output
        groups_data = {
            "groups": [
                {"id": "db-group-id-1", "name": "DB Group Name"}
            ]
        }
        cursor.execute(
            "INSERT INTO evidence (technique_id, output_json) VALUES (?, ?)",
            ("discovery/unified_enum_groups", json.dumps(groups_data))
        )
        conn.commit()
        conn.close()

        mapping = load_loot_mappings(db_path)
        assert mapping.get("db-user-id-1") == "db-user@target-org.example"
        assert mapping.get("db-group-id-1") == "DB Group Name"

    def test_loads_from_workspace(self):
        from quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies import load_loot_mappings
        from quantum_mechanic.core.workspace import Workspace
        import json

        mock_workspace = MagicMock(spec=Workspace)
        mock_workspace.db_path = "/fake/path/db.db"

        # Mock list_principals
        from dataclasses import dataclass
        @dataclass
        class MockPrincipal:
            id: str
            friendly_name: str
        mock_workspace.list_principals.return_value = [
            MockPrincipal(id="principal-id-123", friendly_name="John Doe")
        ]

        # Mock list_evidence
        mock_workspace.list_evidence.return_value = [
            {
                "technique_id": "discovery/entra_enum_users",
                "output_json": json.dumps({
                    "users": [
                        {"id": "user-id-abc", "userPrincipalName": "abc@target-org.example"}
                    ]
                })
            },
            {
                "technique_id": "discovery/entra_enum_group_members",
                "output_json": json.dumps({
                    "members": [
                        {
                            "groupId": "group-id-xyz",
                            "groupName": "My Group",
                            "memberId": "member-id-def",
                            "memberName": "Jane Smith"
                        }
                    ]
                })
            }
        ]

        mapping = load_loot_mappings(mock_workspace)
        assert mapping.get("principal-id-123") == "John Doe"
        assert mapping.get("user-id-abc") == "abc@target-org.example"
        assert mapping.get("group-id-xyz") == "My Group"
        assert mapping.get("member-id-def") == "Jane Smith"

class TestConditionalAccessControls:
    def test_parses_grant_and_session_controls(self):
        store = _make_store(_make_token("access_token"))
        ctx = _build_ctx(store)

        mock_policies = [
            {
                "id": "policy-session-controls",
                "displayName": "Session Control Policy",
                "state": "enabled",
                "grantControls": {
                    "builtInControls": ["mfa"],
                    "authenticationStrength": {
                        "id": "00000000-0000-0000-0000-000000000004",
                        "displayName": "Phishing-Resistant MFA"
                    },
                    "termsOfUse": ["tou-id-1"],
                    "customAuthenticationFactors": ["caf-id-1"]
                },
                "sessionControls": {
                    "persistentBrowser": {
                        "isEnabled": True,
                        "mode": "never"
                    },
                    "signInFrequency": {
                        "isEnabled": True,
                        "value": 4,
                        "type": "hours"
                    },
                    "applicationEnforcedRestrictions": {
                        "isEnabled": True
                    },
                    "cloudAppSecurity": {
                        "isEnabled": True,
                        "cloudAppSecurityType": "blockDownloads"
                    },
                    "continuousAccessEvaluation": {
                        "mode": "strictEnforcement"
                    },
                    "disableResilienceDefaults": True,
                    "secureSignInSession": {
                        "isEnabled": True
                    },
                    "globalSecureAccessFilteringProfile": {
                        "profileType": "privateAccess"
                    }
                },
                "conditions": {
                    "users": {
                        "includeUsers": ["All"]
                    }
                }
            }
        ]

        def _mock_graph_list(http, url, headers):
            if "roleDefinitions" in url or "namedLocations" in url:
                return []
            return mock_policies

        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies.graph_list",
            side_effect=_mock_graph_list
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies.resolve_directory_objects",
            return_value={}
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies.httpx.Client",
            return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
        ):
            result = execute(ctx)

        assert result["status"] == "success"
        p = result["policies"][0]
        assert p["display_name"] == "Session Control Policy"
        controls = p["grant_controls"]
        
        # Verify all expected controls are in the string
        assert "mfa" in controls
        assert "authStrength(Phishing-Resistant MFA)" in controls
        assert "termsOfUse(tou-id-1)" in controls
        assert "customAuth(caf-id-1)" in controls
        assert "persistentBrowser(never)" in controls
        assert "signInFrequency(4 hours)" in controls
        assert "applicationEnforcedRestrictions" in controls
        assert "cloudAppSecurity(blockDownloads)" in controls
        assert "continuousAccessEvaluation(strictEnforcement)" in controls
        assert "disableResilienceDefaults(true)" in controls
        assert "secureSignInSession" in controls
        assert "globalSecureAccess(privateAccess)" in controls

class TestLootMetadata:
    def test_loot_metadata_configured(self):
        meta = getattr(execute, "__technique__", None)
        assert meta is not None
        assert meta.loot_items_key == "policies"
        schema = meta.loot_schema
        assert isinstance(schema, list)
        assert len(schema) > 0
        assert schema[0][0] == "display_name"


class TestExplainControls:
    def test_explain_various_controls(self):
        from quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies import explain_controls

        # Test persistentBrowser
        assert "persistentBrowser(never): Persistent browser sessions are disabled" in "\n".join(explain_controls("persistentBrowser(never)"))
        assert "persistentBrowser(always): Persistent browser sessions are enabled/enforced" in "\n".join(explain_controls("persistentBrowser(always)"))
        
        # Test signInFrequency
        assert "signInFrequency(12 hours): Limits the lifetime of the authentication session" in "\n".join(explain_controls("signInFrequency(12 hours)"))
        
        # Test authStrength
        assert "authStrength(Phishing-resistant MFA): Enforces a specific set of authentication methods" in "\n".join(explain_controls("authStrength(Phishing-resistant MFA)"))
        
        # Test other session / grant controls
        assert "mfa: Requires standard Multifactor Authentication" in "\n".join(explain_controls("mfa"))
        assert "block: Explicitly blocks access" in "\n".join(explain_controls("block"))
        assert "passwordChange: User must change their password" in "\n".join(explain_controls("passwordChange"))
        
        # Test multiple controls combined
        combined = explain_controls("mfa, persistentBrowser(never), signInFrequency(4 hours)")
        assert len(combined) == 3
        assert "mfa" in combined[0]
        assert "persistentBrowser(never)" in combined[1]
        assert "signInFrequency(4 hours)" in combined[2]

        # Test empty input
        assert explain_controls("") == []
        assert explain_controls(None) == []

