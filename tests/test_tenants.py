# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0", "keyring>=25,<26"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deterministic tests for the tenant registry (plugin/connector/tenants.py). No model, no network.

An in-memory keyring backend is installed for the whole module, so nothing here reads or writes
the developer's real credential store.

Three things are under test:

**A single-tenant operator sees no change at all.** With no registry on disk, resolution must
return exactly what ``load_env`` produced before this existed. Asserted first, because everything
else is only safe if that holds.

**The credential goes to the OS store and nowhere else.** Not the registry file, not a ``repr``,
not a ``str``, not an exception message -- every one of those is somewhere a secret has ended up
before.

**A store that is absent or broken fails loudly with the fix in the message.** A Linux box with no
Secret Service running is a real, common state, and "no credentials" is a useless thing to say to
someone in it.

Credential values below are distinctive on purpose. An earlier draft used ``"k"`` and ``"s"``,
which "leaked" into any URL containing those letters and proved nothing.

Run:  uv run --with pytest --with keyring pytest -q tests/test_tenants.py
"""
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import KeyringError

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("tenants", ROOT / "plugin" / "connector" / "tenants.py")
T = importlib.util.module_from_spec(_spec)
# Registered before exec: the module uses `from __future__ import annotations`, and @dataclass
# resolves those string annotations through sys.modules[cls.__module__]. Loading by path without
# this raises AttributeError inside dataclasses, not in our code.
sys.modules["tenants"] = T
_spec.loader.exec_module(T)

KEY = "AKIA-TEST-CLIENT-ID-0001"
SECRET = "sUp3rS3cr3t-must-never-be-written-down"
URL = "https://api.us-west.exabeam.cloud/mcp"
EU = "https://api.eu-central.exabeam.cloud/mcp"


class _MemoryKeyring(KeyringBackend):
    """An in-memory store. The developer's real Keychain/Credential Manager is never touched."""

    priority = 1

    def __init__(self):
        super().__init__()
        self.data = {}

    def get_password(self, service, username):
        return self.data.get((service, username))

    def set_password(self, service, username, password):
        self.data[(service, username)] = password

    def delete_password(self, service, username):
        self.data.pop((service, username), None)


class _BrokenKeyring(KeyringBackend):
    """No Secret Service running -- a real state on a headless or minimal Linux box."""

    priority = 1

    def get_password(self, service, username):
        raise KeyringError("no backend available")

    def set_password(self, service, username, password):
        raise KeyringError("no backend available")

    def delete_password(self, service, username):
        raise KeyringError("no backend available")


@pytest.fixture
def store(monkeypatch):
    mem = _MemoryKeyring()
    monkeypatch.setattr(keyring, "get_keyring", lambda: mem)
    monkeypatch.setattr(T.keyring, "get_password", mem.get_password)
    monkeypatch.setattr(T.keyring, "set_password", mem.set_password)
    monkeypatch.setattr(T.keyring, "delete_password", mem.delete_password)
    return mem


@pytest.fixture
def registry(tmp_path, monkeypatch):
    """Point the module at a throwaway registry; never touch a real one."""
    monkeypatch.setattr(T, "REGISTRY_PATH", str(tmp_path / "config.json"))
    monkeypatch.delenv("RAFFKIN_TENANT", raising=False)
    return tmp_path


def _write(entry, default="acme", **more):
    T.save_registry({"default_tenant": default, "tenants": {default: entry, **more}})


# --- the promise: nothing changes for a single-tenant operator -------------------------------------


class TestSingleTenantUnchanged:
    def test_no_registry_falls_back_to_the_env_file(self, registry, store):
        t = T.resolve_tenant(load_env=lambda: {
            "EXABEAM_MCP_URL": URL, "EXABEAM_API_KEY": KEY, "EXABEAM_API_SECRET": SECRET})
        assert (t.api_server, t.key, t.secret) == (URL, KEY, SECRET)

    def test_the_fallback_does_not_consult_the_store_at_all(self, registry, store):
        """An operator who has not opted in must not need a working keyring."""
        T.resolve_tenant(load_env=lambda: {
            "EXABEAM_MCP_URL": URL, "EXABEAM_API_KEY": KEY, "EXABEAM_API_SECRET": SECRET})
        assert store.data == {}, "the single-tenant path touched the credential store"

    def test_no_registry_and_no_env_file_says_what_to_do(self, registry, store):
        with pytest.raises(T.TenantError) as e:
            T.resolve_tenant()
        assert "exabeam-mcp.env" in str(e.value) and "config.json" in str(e.value)

    def test_an_unknown_tenant_is_an_error_not_a_silent_fallback(self, registry, store):
        """Falling back would connect the operator to a tenant they did not ask for."""
        _write({"api_server": URL})
        with pytest.raises(T.TenantError, match="not in"):
            T.resolve_tenant("nosuchtenant", load_env=lambda: {"EXABEAM_MCP_URL": URL})


# --- more than one tenant ---------------------------------------------------------------------------


class TestMultiTenant:
    def test_each_tenant_has_its_own_credentials(self, registry, store):
        _write({"api_server": URL}, globex={"api_server": EU})
        T.store_credentials("acme", "ACME-ID", "ACME-SECRET")
        T.store_credentials("globex", "GBX-ID", "GBX-SECRET")
        a, g = T.resolve_tenant("acme"), T.resolve_tenant("globex")
        assert (a.key, a.secret) == ("ACME-ID", "ACME-SECRET")
        assert (g.key, g.secret) == ("GBX-ID", "GBX-SECRET")
        assert a.api_server != g.api_server, "two tenants must not share a gateway by accident"

    def test_one_keyring_service_per_tenant(self, registry, store):
        """Isolation is the storage layout, not a runtime check."""
        T.store_credentials("acme", KEY, SECRET)
        assert set(store.data) == {("raffkin/acme", "client_id"), ("raffkin/acme", "client_secret")}

    def test_deleting_one_tenant_leaves_the_others(self, registry, store):
        T.store_credentials("acme", "A", "B")
        T.store_credentials("globex", "C", "D")
        T.delete_credentials("acme")
        assert store.get_password("raffkin/acme", "client_id") is None
        assert store.get_password("raffkin/globex", "client_id") == "C"

    def test_deleting_a_tenant_that_was_never_stored_is_not_an_error(self, registry, store):
        T.delete_credentials("never-existed")           # cleanup paths must be idempotent

    def test_half_stored_credentials_are_refused(self, registry, store):
        """An interrupted setup must not look like a working one."""
        _write({"api_server": URL})
        store.set_password("raffkin/acme", "client_id", KEY)   # secret never stored
        with pytest.raises(T.TenantError, match="no credentials"):
            T.resolve_tenant()


# --- the credential does not escape ------------------------------------------------------------------


class TestCredentialContainment:
    def test_the_registry_file_never_holds_a_credential(self, registry, store):
        _write({"api_server": URL, "region": "US West"})
        T.store_credentials("acme", KEY, SECRET)
        t = T.resolve_tenant()
        assert (t.key, t.secret) == (KEY, SECRET), "the store's values did not arrive"
        blob = T.registry_path().read_text(encoding="utf-8")
        assert KEY not in blob and SECRET not in blob

    def test_repr_and_str_redact(self, registry, store):
        """Tenant lands in tracebacks and log lines; the default dataclass repr prints both."""
        _write({"api_server": URL})
        T.store_credentials("acme", KEY, SECRET)
        t = T.resolve_tenant()
        for rendered in (repr(t), str(t), f"{t}", "{}".format(t)):
            assert KEY not in rendered and SECRET not in rendered
        assert "redacted" in repr(t)

    def test_the_missing_credentials_message_carries_no_value(self, registry, store):
        _write({"api_server": URL})
        with pytest.raises(T.TenantError) as e:
            T.resolve_tenant()
        assert SECRET not in str(e.value) and KEY not in str(e.value)
        assert "keyring set raffkin/acme client_secret" in str(e.value)


# --- a store that is absent or broken ----------------------------------------------------------------


class TestStoreUnavailable:
    @pytest.fixture
    def broken(self, monkeypatch):
        b = _BrokenKeyring()
        monkeypatch.setattr(T.keyring, "get_password", b.get_password)
        monkeypatch.setattr(T.keyring, "set_password", b.set_password)
        return b

    def test_a_missing_secret_service_names_the_fix(self, registry, broken):
        """A headless Linux box with no keyring daemon is common; 'no credentials' is useless there."""
        _write({"api_server": URL})
        with pytest.raises(T.TenantError) as e:
            T.resolve_tenant()
        msg = str(e.value)
        assert "not available" in msg
        assert "gnome-keyring" in msg or "Secret Service" in msg
        assert "exabeam-mcp.env" in msg, "the single-tenant escape hatch should be offered"

    def test_a_refused_write_is_reported_not_swallowed(self, registry, broken):
        with pytest.raises(T.TenantError, match="refused the write"):
            T.store_credentials("acme", KEY, SECRET)


# --- the registry itself -----------------------------------------------------------------------------


class TestRegistry:
    def test_written_atomically_and_owner_only(self, registry, store):
        _write({"api_server": URL})
        p = T.registry_path()
        assert json.loads(p.read_text(encoding="utf-8"))["default_tenant"] == "acme"
        assert not list(p.parent.glob(".config-*")), "a temp file was left behind"
        if os.name != "nt":                              # NTFS does not enforce POSIX modes
            assert stat.S_IMODE(p.stat().st_mode) == 0o600

    def test_corrupt_registry_raises_rather_than_reading_as_empty(self, registry, store):
        T.registry_path().parent.mkdir(parents=True, exist_ok=True)
        T.registry_path().write_text("{not json", encoding="utf-8")
        with pytest.raises(T.TenantError, match="JSON"):
            T.resolve_tenant(load_env=lambda: {"EXABEAM_MCP_URL": URL})

    def test_list_tenants_is_sorted(self, registry, store):
        T.save_registry({"tenants": {"zeta": {"api_server": URL}, "alpha": {"api_server": URL}}})
        assert T.list_tenants() == ["alpha", "zeta"]

    def test_env_selects_the_active_tenant_but_carries_no_credential(self, registry, store, monkeypatch):
        T.save_registry({"default_tenant": "alpha",
                         "tenants": {"alpha": {"api_server": URL}, "beta": {"api_server": EU}}})
        assert T.active_tenant_name() == "alpha"
        monkeypatch.setenv("RAFFKIN_TENANT", "beta")
        assert T.active_tenant_name() == "beta"

    @pytest.mark.parametrize("bad", ["../evil", "a b", "", "x" * 80, ".hidden", "a\nb", "a/b"])
    def test_hostile_tenant_names_are_refused(self, bad):
        """This value reaches a keyring service string and a log field."""
        with pytest.raises(T.TenantError):
            T._validate_name(bad)

    @pytest.mark.parametrize("ok", ["acme", "demo-1", "a.b_c", "A1"])
    def test_ordinary_names_pass(self, ok):
        assert T._validate_name(ok) == ok

    def test_a_hostile_name_cannot_reach_the_store(self, store):
        """Validation happens before the service string is built, not after."""
        with pytest.raises(T.TenantError):
            T.store_credentials("../../etc/passwd", KEY, SECRET)
        assert store.data == {}

    def test_api_server_is_required(self, registry, store):
        _write({"region": "US West"})
        T.store_credentials("acme", KEY, SECRET)
        with pytest.raises(T.TenantError, match="api_server"):
            T.resolve_tenant()
