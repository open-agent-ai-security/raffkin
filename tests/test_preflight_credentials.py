# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""preflight.sh's credentials check mirrors the bridge's transport rule (#174): https required, plain http
to a loopback host tolerated, anything else is a FAIL that names the value -- before the bridge is started.
Deterministic: the function is sourced and called with a temp credentials file; nothing is connected to."""
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PREFLIGHT = ROOT / "plugin" / "preflight.sh"


def _check(tmp_path, url):
    env = tmp_path / "creds.env"
    env.write_text(f"EXABEAM_MCP_URL={url}\nEXABEAM_API_KEY=k\nEXABEAM_API_SECRET=s\n")
    script = textwrap.dedent(f"""
        source '{PREFLIGHT}'
        ok()   {{ echo "OK: $1"; }}
        warn() {{ echo "WARN: $1"; }}
        fail() {{ echo "FAIL: $1"; }}
        ENV_FILE='{env}'
        check_credentials
        echo "CREDS_OK=$CREDS_OK"
    """)
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout


@pytest.mark.parametrize("url", [
    "https://api.us-west.exabeam.cloud/mcp",
    "https://mcp.internal.example:8443/mcp",
    "http://127.0.0.1:8765/mcp",
    "http://localhost:8765/mcp",
    "http://[::1]:8765/mcp",
])
def test_preflight_accepts_https_and_loopback_http(tmp_path, url):
    out = _check(tmp_path, url)
    assert "CREDS_OK=1" in out and "OK: Credentials" in out and "FAIL" not in out, out


@pytest.mark.parametrize("url, expect", [
    ("http://api.us-west.exabeam.cloud/mcp", "in the clear"),
    ("http://127.0.0.1.evil.example/mcp", "in the clear"),
    ("ftp://api.us-west.exabeam.cloud/mcp", "must start with https://"),
    ("api.us-west.exabeam.cloud/mcp", "must start with https://"),
])
def test_preflight_fails_cleartext_before_the_bridge_starts(tmp_path, url, expect):
    out = _check(tmp_path, url)
    assert "CREDS_OK=0" in out and "FAIL: EXABEAM_MCP_URL" in out and expect in out, out


def _preflight_with_fake_uv(tmp_path, version_line):
    """preflight.sh --platform none with a `uv` on PATH that only answers --version."""
    import os, subprocess
    bin_ = tmp_path / "bin"; bin_.mkdir(exist_ok=True)
    (bin_ / "uv").write_text(f"#!/bin/sh\ncase \"$1\" in --version) echo '{version_line}' ;; *) exit 1 ;; esac\n")
    (bin_ / "uv").chmod(0o755)
    env = dict(os.environ, HOME=str(tmp_path), PATH=str(bin_) + os.pathsep + os.environ.get("PATH", ""))
    return subprocess.run(["bash", str(PREFLIGHT), "--platform", "none", "--skip-connectivity", "--no-color"],
                          capture_output=True, text=True, env=env)


def test_preflight_fails_a_uv_below_the_lock_floor_and_accepts_the_floor(tmp_path):
    """#248: below uv 0.5.23 `uv run --locked` does not honor (or even accept) the script lock, so the
    bridge would not start; preflight says so as a failure with the upgrade command. At and above the
    floor, including a two-digit minor, it reads ok."""
    old = _preflight_with_fake_uv(tmp_path, "uv 0.5.16 (fake)")
    assert "older than 0.5.23" in old.stdout and "uv self update" in old.stdout and old.returncode == 1, old.stdout
    for v in ("uv 0.5.23 (fake)", "uv 0.6.0 (fake)", "uv 0.11.24 (Homebrew 2026-06-23 aarch64-apple-darwin)"):
        r = _preflight_with_fake_uv(tmp_path, v)
        assert "uv present" in r.stdout and "older than" not in r.stdout, (v, r.stdout)
