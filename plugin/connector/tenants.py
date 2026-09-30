# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tenant registry -- more than one Exabeam tenant, with the secret in the OS credential store.

Raffkin was single-tenant by construction: EXABEAM_MCP_URL, EXABEAM_API_KEY and
EXABEAM_API_SECRET were module constants read once at import, so working a second tenant meant
editing ``~/.exabeam-mcp.env`` and restarting the host. Anyone with a book of clients -- an MSSP
analyst, a partner, someone moving between demo and customer environments -- could not use it.

Going multi-tenant on the old design would have made #102 worse rather than better. That issue
(external assessment F-15) records that the key and secret sit in a plaintext file whose
``chmod 600`` "stops other users on the machine reading the file. That is all it does." N tenants
would have meant N such files. So the two are answered together.

**The split.** A plaintext registry at ``~/.raffkin/config.json`` holds only what is not a secret
-- per tenant: ``api_server``, and optionally ``fqdn`` and ``region``. The credential lives in the
**OS credential store**, two entries per tenant under service ``raffkin/<tenant>``: Windows
Credential Manager (DPAPI), macOS Keychain, or the Linux Secret Service. Encrypted at rest,
unlocked by the OS login. No cryptography is implemented here; it is delegated to the platform.

**On the dependency.** ``keyring`` is declared in this script's PEP-723 header and pinned in its
lock, because ``.mcp.json`` launches the bridge with ``uv run --locked`` and an undeclared import
cannot resolve. #102 weighed exactly this -- "a small, well-established dependency … this adds a
runtime dependency, which touches the lock-file discipline in #71; worth weighing rather than
assuming" -- and deferred it. The weighing, now that it is being done: on Windows there is no
built-in secret CLI, so every alternative that reaches a credential store needs this same library
anyway, installed by hand and unpinned. Declaring it puts it under the lock and the dependency
audit instead of outside them.

**What it buys, stated honestly.** Moving the key out of a file removes the ways it leaks by
accident: a backup or sync agent sweeping ``$HOME``, a crash dump, an accidental ``cat`` on a
shared screen, a ``grep -r`` for secrets. It does **not** stop malware already running as the
analyst, which can ask the same keychain the same question. #102's reasoning is right about that.
This narrows the accidental exposure, not the targeted one.

**Nothing changes for an existing single-tenant operator.** With no registry on disk, resolution
returns exactly what ``load_env()`` produced before, from the same file, and the tenant tools are
not offered.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import keyring
from keyring.errors import KeyringError

#: Where the non-secret registry lives. Overridable so tests never touch a real one.
REGISTRY_PATH = os.environ.get("RAFFKIN_CONFIG", "~/.raffkin/config.json")

#: Keyring service per tenant. Two entries under it: client_id and client_secret.
KEYRING_SERVICE = "raffkin/{tenant}"

#: Tenant names become keyring services, file paths and log fields. Keep them boring.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class TenantError(Exception):
    """Registry, name or credential-store failure. The message is safe to show a human: it names
    what failed and what to fix, and never carries a secret."""


@dataclass(frozen=True)
class Tenant:
    """One tenant, resolved. ``key``/``secret`` live here and nowhere else.

    ``__repr__`` is overridden because this object lands in tracebacks and log lines, and the
    default dataclass repr would print the credential in both.
    """

    name: str
    api_server: str
    key: str = field(repr=False, default="")
    secret: str = field(repr=False, default="")
    fqdn: str = ""
    region: str = ""

    def __repr__(self) -> str:
        return f"Tenant(name={self.name!r}, api_server={self.api_server!r}, credentials=<redacted>)"


def _validate_name(name: str) -> str:
    """A tenant name, or raise. Rejects traversal, whitespace and control characters outright --
    this value reaches a keyring service string and a log field."""
    n = (name or "").strip()
    if not _NAME_RE.match(n):
        raise TenantError(
            f"tenant name {name!r} is not usable: letters, digits, dot, dash and underscore only, "
            "up to 64 characters, and it may not start with a separator."
        )
    return n


def registry_path() -> Path:
    return Path(os.path.expanduser(REGISTRY_PATH))


def load_registry() -> dict:
    """The registry, or an empty one. A corrupt file is an error, not a silent empty registry --
    silently falling back would connect the operator to a tenant they did not choose."""
    p = registry_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise TenantError(f"{p} could not be read as JSON ({e}). Fix or remove it.") from e
    if not isinstance(data, dict) or not isinstance(data.get("tenants", {}), dict):
        raise TenantError(f"{p} must be an object with a 'tenants' object in it.")
    return data


def save_registry(data: dict) -> None:
    """Write the registry atomically, owner-only where the OS enforces it.

    tmp+rename so a crash mid-write cannot truncate the file the bridge reads on every connect.

    0600 is requested and honoured on macOS and Linux. On Windows/NTFS ``os.chmod`` only toggles
    the read-only bit, so the mode is advisory there -- the same caveat ``installation.md`` already
    makes about ``chmod 600`` under Git Bash. Tolerable *here* precisely because this file holds no
    credentials: the worst it discloses is which tenants an operator works.
    """
    p = registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".config-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:      # closes fd on every path
            fh.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def service_for(tenant: str) -> str:
    return KEYRING_SERVICE.format(tenant=tenant)


def store_credentials(tenant: str, client_id: str, client_secret: str) -> None:
    """Put a tenant's credentials in the OS store. Nothing here writes them anywhere else."""
    name = _validate_name(tenant)
    try:
        keyring.set_password(service_for(name), "client_id", client_id)
        keyring.set_password(service_for(name), "client_secret", client_secret)
    except KeyringError as e:
        raise TenantError(f"tenant {name!r}: the OS credential store refused the write ({e}).") from e


def delete_credentials(tenant: str) -> None:
    """Remove a tenant's credentials. Missing entries are not an error -- this is used for cleanup."""
    name = _validate_name(tenant)
    for part in ("client_id", "client_secret"):
        try:
            keyring.delete_password(service_for(name), part)
        except KeyringError:                              # not present, or no backend: nothing to undo
            pass


def _secret_pair(name: str) -> tuple[str, str]:
    """(client_id, client_secret) from the OS credential store, or a message saying how to put
    them there. The error names the exact commands rather than pointing at a manual."""
    svc = service_for(name)
    try:
        key = keyring.get_password(svc, "client_id")
        secret = keyring.get_password(svc, "client_secret")
    except KeyringError as e:
        raise TenantError(
            f"tenant {name!r}: the OS credential store is not available ({e}). On Linux this "
            "usually means no Secret Service is running -- start gnome-keyring or KWallet, or "
            "keep using ~/.exabeam-mcp.env for a single tenant."
        ) from e
    if not (key and secret):
        raise TenantError(
            f"tenant {name!r}: no credentials in the OS store under {svc!r}. Add them with:\n"
            f"  keyring set {svc} client_id\n"
            f"  keyring set {svc} client_secret\n"
            "(the value is prompted for, never passed on the command line or left in shell history)"
        )
    return key, secret


def list_tenants() -> list[str]:
    """Registry tenant names, sorted. Never a secret, so this is safe to print."""
    return sorted(load_registry().get("tenants", {}))


def active_tenant_name(registry: dict | None = None) -> str | None:
    """Which tenant is active: ``RAFFKIN_TENANT`` wins, else the registry's ``default_tenant``.

    The variable names a tenant; it never carries a credential.
    """
    reg = load_registry() if registry is None else registry
    return (os.environ.get("RAFFKIN_TENANT") or "").strip() or reg.get("default_tenant") or None


def resolve_tenant(name: str | None = None, *, load_env=None) -> Tenant:
    """The tenant to connect as.

    Registry first; with no registry (or no entry), fall back to ``load_env`` -- the existing
    single-tenant file -- so an operator who has not opted in sees no change whatsoever.
    """
    reg = load_registry()
    tenants = reg.get("tenants", {})
    wanted = _validate_name(name) if name else active_tenant_name(reg)

    if not tenants or not wanted or wanted not in tenants:
        if wanted and tenants:
            raise TenantError(
                f"tenant {wanted!r} is not in {registry_path()}. Known: "
                f"{', '.join(sorted(tenants)) or '(none)'}"
            )
        if load_env is None:
            raise TenantError(
                f"no tenant configured. Add one to {registry_path()}, or keep using "
                "~/.exabeam-mcp.env for a single tenant."
            )
        cfg = load_env()
        return Tenant(
            name=(wanted or "default"),
            api_server=cfg.get("EXABEAM_MCP_URL", ""),
            key=cfg.get("EXABEAM_API_KEY", ""),
            secret=cfg.get("EXABEAM_API_SECRET", ""),
        )

    entry = tenants[wanted]
    if not isinstance(entry, dict):
        raise TenantError(f"tenant {wanted!r} must be an object in {registry_path()}.")
    url = (entry.get("api_server") or "").strip()
    if not url:
        raise TenantError(f"tenant {wanted!r} has no api_server in {registry_path()}.")
    key, secret = _secret_pair(wanted)
    return Tenant(
        name=wanted,
        api_server=url,
        key=key,
        secret=secret,
        fqdn=(entry.get("fqdn") or "").strip(),
        region=(entry.get("region") or "").strip(),
    )


def _warn(msg: str) -> None:
    sys.stderr.write(f"bridge: {msg}\n")
