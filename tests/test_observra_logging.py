# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0", "observra", "typing_extensions"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deterministic tests for the structured agent-telemetry shim (plugin/connector/observra_logging.py).

Four things matter and all are tested without a network:
  * DEFAULT ON — logging runs unless explicitly RAFFKIN_OBSERVRA=off. A production agent keeps an audit trail.
  * FAIL-OPEN — a missing/misconfigured backend disables logging silently; no recording call ever raises.
    Telemetry must never break an investigation.
  * PRIVACY BY CONSTRUCTION — events carry the gated action's IDs/enums + guardrail COUNTS/CLASSES, never
    the raw free-text note / value / payload the guardrails neutralize.
  * BOUNDED — the jsonl backend rotates, so the audit log never grows without limit.

The real-emit tests importorskip observra; the enable/disable-logic tests run with or without it.

Run:  uv run --with pytest --with observra --with typing_extensions pytest -q tests/test_observra_logging.py
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "plugin" / "connector"))


def _fresh(monkeypatch, env):
    """Import a pristine copy of the shim under a controlled environment (its on/off decision is cached
    per-module, so each scenario needs its own module instance)."""
    for key in ("RAFFKIN_OBSERVRA", "RAFFKIN_OBSERVRA_PATH", "RAFFKIN_OBSERVRA_MAX_BYTES", "RAFFKIN_OBSERVRA_BACKUPS"):
        monkeypatch.delenv(key, raising=False)
    for key, val in env.items():
        monkeypatch.setenv(key, val)
    spec = importlib.util.spec_from_file_location(
        f"obslog_{abs(hash(frozenset(env.items())))}", ROOT / "plugin" / "connector" / "observra_logging.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---- default-on / off-switch / fail-open ------------------------------------------------------------

def test_enabled_by_default(monkeypatch, tmp_path):
    # No RAFFKIN_OBSERVRA set at all -> logging is ON (jsonl). Assurance is the default posture.
    pytest.importorskip("observra")
    t = _fresh(monkeypatch, {"RAFFKIN_OBSERVRA_PATH": str(tmp_path / "t.jsonl")})
    assert t.enabled() is True


@pytest.mark.parametrize("val", ["off", "0", "false", "none", "disabled"])
def test_explicit_off_disables(monkeypatch, val):
    t = _fresh(monkeypatch, {"RAFFKIN_OBSERVRA": val})
    assert t.enabled() is False


def test_unknown_backend_fails_open(monkeypatch):
    # A bad backend name must disable telemetry, not crash the bridge.
    t = _fresh(monkeypatch, {"RAFFKIN_OBSERVRA": "definitely-not-a-backend"})
    assert t.enabled() is False


def test_missing_observra_fails_open_even_on_default(monkeypatch):
    # Default-on, but observra not importable (sys.modules[...]=None makes `import observra` raise) ->
    # the shim disables silently rather than propagate. No file is written.
    t = _fresh(monkeypatch, {})
    monkeypatch.setitem(sys.modules, "observra", None)
    assert t.enabled() is False


def test_recording_calls_never_raise_when_disabled(monkeypatch):
    t = _fresh(monkeypatch, {"RAFFKIN_OBSERVRA": "off"})
    t.session_start()
    t.tool_start("exabeam_search_alerts")
    t.tool_end("exabeam_update_alert", 12.3, defang_notes=[{"type": "formula"}],
               hygiene_removed=[{"cp": "U+200B"}], action_fields={"alertId": "a-1", "alertStatus": "closed"})
    t.tool_error("exabeam_update_case", 4.0, ValueError("boom"))
    t.session_end()


# ---- real emit + audit record + privacy (needs observra) --------------------------------------------

def _read_events(monkeypatch, tmp_path):
    pytest.importorskip("observra")
    out = tmp_path / "telemetry.jsonl"
    t = _fresh(monkeypatch, {"RAFFKIN_OBSERVRA": "jsonl", "RAFFKIN_OBSERVRA_PATH": str(out)})
    assert t.enabled() is True

    t.session_start()
    t.tool_start("exabeam_search_events")
    # a read that carried smuggled invisibles -> input canonicalizer stripped them
    t.tool_end("exabeam_search_events", 1804.2,
               hygiene_removed=[{"cp": "U+200B", "name": "ZERO WIDTH SPACE"},
                                {"cp": "U+200B", "name": "ZERO WIDTH SPACE"},
                                {"cp": "U+202E", "name": "RIGHT-TO-LEFT OVERRIDE"}])
    # the gated suppression: update_alert closing alert 4471 as false-positive, whose note field carried
    # a formula + phishing link the output neutralizer defanged. The DECISION (id + disposition) is logged;
    # the raw note is NOT.
    t.tool_start("exabeam_update_alert")
    t.tool_end("exabeam_update_alert", 143.2,
               defang_notes=[{"type": "formula", "original": '=HYPERLINK("https://evil.example/x")'},
                             {"type": "link", "original": "https://sso-reset.evil.example"}],
               action_fields={"alertId": "4471", "alertStatus": "closed", "disposition": "false_positive"})
    t.tool_error("exabeam_get_mitre_coverage", 7.0, TimeoutError("upstream"))
    t.session_end()

    t._state["observra"]._worker._shutdown()   # drain the background worker to the file
    return out.read_text(), [json.loads(l) for l in out.read_text().splitlines() if l.strip()]


def test_emits_expected_mcp_events(monkeypatch, tmp_path):
    _raw, events = _read_events(monkeypatch, tmp_path)
    by_type = {e["event_type"]: e for e in events}
    for et in ("mcp_session_start", "tool_start", "tool_end", "tool_error", "mcp_session_end"):
        assert et in by_type, f"missing {et}; saw {sorted(by_type)}"
    end = by_type["tool_end"]
    assert end["framework"] == "mcp" and end["skill_name"] == "soc-investigate"


def test_gated_action_decision_is_recorded(monkeypatch, tmp_path):
    # The audit-grade part: the write's IDs + disposition are captured as the decision record.
    _raw, events = _read_events(monkeypatch, tmp_path)
    write = next(e for e in events if e.get("tool_name") == "exabeam_update_alert"
                 and e["event_type"] == "tool_end")
    data = write["data"]
    assert data["action.alertId"] == "4471"
    assert data["action.alertStatus"] == "closed"
    assert data["action.disposition"] == "false_positive"
    # guardrail firing on that same write is recorded too
    assert data["defang_formula"] == 1 and data["defang_link"] == 1


def test_guardrail_metadata_is_counts_and_classes(monkeypatch, tmp_path):
    _raw, events = _read_events(monkeypatch, tmp_path)
    read = next(e for e in events if e.get("tool_name") == "exabeam_search_events"
                and e["event_type"] == "tool_end")["data"]
    assert read["hygiene_stripped"] == 3
    assert read["hygiene_classes"] == "U+200B,U+202E"     # distinct code-point IDs, order-stable


def test_privacy_no_raw_payload_in_log(monkeypatch, tmp_path):
    # THE invariant: the neutralized free-text content never appears -- only metadata + safe IDs/enums.
    raw, _events = _read_events(monkeypatch, tmp_path)
    assert "evil.example" not in raw
    assert "HYPERLINK" not in raw
    assert "sso-reset" not in raw
    assert "4471" in raw                                  # ...but the decision record IS present


def test_jsonl_rotation_is_bounded(monkeypatch, tmp_path):
    # A tiny max_bytes forces rotation; a backup file must appear, proving the log is bounded.
    pytest.importorskip("observra")
    out = tmp_path / "telemetry.jsonl"
    t = _fresh(monkeypatch, {"RAFFKIN_OBSERVRA": "jsonl", "RAFFKIN_OBSERVRA_PATH": str(out),
                             "RAFFKIN_OBSERVRA_MAX_BYTES": "2048", "RAFFKIN_OBSERVRA_BACKUPS": "3"})
    assert t.enabled() is True
    for i in range(200):
        t.tool_end("exabeam_search_events", float(i))
    t._state["observra"]._worker._shutdown()
    rotated = list(tmp_path.glob("telemetry.jsonl.*"))
    assert rotated, "expected at least one rotated backup file under the tiny size cap"
    assert len(rotated) <= 3, f"backup_count not honored: {sorted(p.name for p in rotated)}"


def test_single_emit_failure_does_not_disable_the_whole_trail(monkeypatch, tmp_path):
    """A transient per-event emit fault (queue burst, one bad value) must drop THAT event only — never
    switch off the mandatory audit log for the rest of the session (code-review PR #39, round 2, #1)."""
    pytest.importorskip("observra")
    out = tmp_path / "telemetry.jsonl"
    t = _fresh(monkeypatch, {"RAFFKIN_OBSERVRA": "jsonl", "RAFFKIN_OBSERVRA_PATH": str(out)})
    assert t.enabled() is True

    real_emit = t._state["emit"]
    calls = {"n": 0}

    def flaky_emit(event_type, **kw):       # raises on the first call, delegates after
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient emit fault")
        real_emit(event_type, **kw)

    t._state["emit"] = flaky_emit
    t.tool_start("exabeam_search_alerts")   # this emit fails...
    assert t.enabled() is True              # ...but logging is NOT disabled
    t.tool_end("exabeam_search_alerts", 5.0)  # a later emit still lands
    t._state["observra"]._worker._shutdown()

    events = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    assert any(e["event_type"] == "tool_end" for e in events), "later event lost — trail was disabled"


def test_session_start_attests_backend_and_destination_and_tool_end_carries_kept_and_screen_failed(monkeypatch, tmp_path):
    """Praxen PRAX-2026-09-05-006/-007: the audit trail records WHERE it ships (resolved destination, not the
    backend keyword), the bridge's configuration facts, the flagged-but-kept invisibles, and a screening
    fail-open — instead of stderr lines the analyst never sees."""
    pytest.importorskip("observra")
    out = tmp_path / "telemetry.jsonl"
    t = _fresh(monkeypatch, {"RAFFKIN_OBSERVRA": "jsonl", "RAFFKIN_OBSERVRA_PATH": str(out)})
    assert t.enabled() is True
    t.session_start(dry_run=True, plugin_version="0.8.5", gate_log="~/.raffkin/gate.jsonl")
    t.tool_end("exabeam_search_events", 3.0, hygiene_kept=[{"cp": "U+200D", "name": "ZERO WIDTH JOINER"},
                                                           {"cp": "U+200F", "name": "RIGHT-TO-LEFT MARK"},
                                                           {"cp": "U+200D", "name": "ZERO WIDTH JOINER"}],
               screen_failed=True)
    t.tool_error("exabeam_update_alert", 1.0, ValueError("neutralizer"), stage="neutralize")
    t._shutdown()
    ev = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    start = next(e for e in ev if e["event_type"] == "mcp_session_start")["data"]
    assert start["telemetry_backend"] == "jsonl" and start["telemetry_destination"] == str(out)
    assert start["dry_run"] is True and start["plugin_version"] == "0.8.5" and start["gate_log"].endswith("gate.jsonl")
    end = next(e for e in ev if e["event_type"] == "tool_end")["data"]
    assert end["hygiene_kept"] == 3 and end["hygiene_kept_classes"] == "U+200D,U+200F" and end["hygiene_screen_failed"] is True
    err = next(e for e in ev if e["event_type"] == "tool_error")["data"]
    assert err["stage"] == "neutralize" and err["guardrail_refused"] is True


def test_destination_is_scheme_and_host_never_the_path_or_query(monkeypatch):
    t = _fresh(monkeypatch, {})
    assert t._destination("webhook", {"url": "https://hooks.example.com/services/T0/B0/secret"}) == "https://hooks.example.com"
    assert t._destination("otel", {"endpoint": "http://collector:4318/v1/traces"}) == "http://collector:4318"
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "https://dt.example/api/v2/otlp/v1/logs?token=x")
    assert t._destination("otel_log", {}) == "https://dt.example"
    assert t._destination("jsonl", {"path": "/tmp/t.jsonl"}) == "/tmp/t.jsonl"
    assert "no EXABEAM_ENDPOINT" in t._destination("exabeam", {}) or t._destination("exabeam", {}).startswith("https://")


def test_session_start_attests_even_when_it_is_the_first_telemetry_call(monkeypatch, tmp_path):
    """The bridge calls session_start() before anything else; it must configure first, then attest.
    Review 2026-09-05: evaluating _state before enabled() recorded an empty backend/destination."""
    pytest.importorskip("observra")
    out = tmp_path / "t.jsonl"
    t = _fresh(monkeypatch, {"RAFFKIN_OBSERVRA": "jsonl", "RAFFKIN_OBSERVRA_PATH": str(out)})
    t.session_start(dry_run=False)                      # no enabled() call first, deliberately
    t.session_start(telemetry_backend="caller-wins", event_type="y")    # colliding keys must not raise
    t._shutdown()
    starts = [json.loads(l)["data"] for l in out.read_text().splitlines() if '"mcp_session_start"' in l]
    assert starts[0]["telemetry_backend"] == "jsonl" and starts[0]["telemetry_destination"] == str(out)
    assert starts[1]["telemetry_backend"] == "caller-wins"


def test_destination_never_leaks_userinfo_or_a_raw_endpoint(monkeypatch):
    t = _fresh(monkeypatch, {})
    assert t._destination("webhook", {"url": "https://user:s3cr3t@hooks.example.com/x?token=1"}) == "https://hooks.example.com"
    assert "api-key" not in t._destination("otel", {"endpoint": "collector:4318/v1/traces?api-key=abc"})
    assert "secret" not in t._destination("webhook", {"url": "hooks.example.com/services/T0/B0/secret?token=abc"})
    assert t._destination("webhook", {}) == "(no RAFFKIN_OBSERVRA_URL set)"
    monkeypatch.setenv("EXABEAM_ENDPOINT", "https://api:tok@x.exabeam.cloud/ingest?k=1")
    assert t._destination("exabeam", {}) == "https://x.exabeam.cloud"
    assert t._destination("jsonl", {"path": "/tmp/t.jsonl"}) == "/tmp/t.jsonl"


# ---- #210 / #173: the stream contract ---------------------------------------------------------------

def test_agent_name_comes_from_identity_json_with_raffkin_as_the_fallback(monkeypatch, tmp_path):
    """#210: a re-keyed copy (a vendor catalog shipping this plugin as `soc`) must log under its own name,
    read from identity.json beside the connector; no file, or a broken one, means `raffkin`, never an error."""
    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
    mod = _fresh(monkeypatch, {})
    assert mod.AGENT == "raffkin", "this tree's identity.json names the plugin raffkin"
    rekeyed = tmp_path / "rekeyed"; rekeyed.mkdir()
    (rekeyed / "identity.json").write_text(json.dumps({"name": "soc", "version": "0.8.7"}))
    assert mod._agent_name(str(rekeyed)) == "soc"
    (rekeyed / "identity.json").write_text("{not json")
    assert mod._agent_name(str(rekeyed)) == "raffkin"
    assert mod._agent_name(str(tmp_path / "nowhere")) == "raffkin"
    (rekeyed / "identity.json").write_text(json.dumps({"name": "soc"}))
    # the file beside the running code wins over CLAUDE_PLUGIN_ROOT (an inherited env var can name another plugin)
    assert _fresh(monkeypatch, {"CLAUDE_PLUGIN_ROOT": str(rekeyed)}).AGENT == "raffkin"
    # with no sibling identity.json, the env var is the fallback: a copy of the shim under a bare tree
    import importlib.util, shutil
    bare = tmp_path / "bare" / "connector"; bare.mkdir(parents=True)
    shutil.copy(ROOT / "plugin" / "connector" / "observra_logging.py", bare / "observra_logging.py")
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(rekeyed))
    spec = importlib.util.spec_from_file_location("obslog_bare", bare / "observra_logging.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    assert mod.AGENT == "soc"


def test_tool_error_records_structure_never_the_upstream_message(monkeypatch, tmp_path):
    """#173: the audit record of a failed call carries the error code, HTTP status, class and retryability
    — and no message text, which quotes the request (a model-written filter is tenant content)."""
    path = tmp_path / "t.jsonl"
    mod = _fresh(monkeypatch, {"RAFFKIN_OBSERVRA": "jsonl", "RAFFKIN_OBSERVRA_PATH": str(path)})
    if not mod.enabled():
        pytest.skip("observra not installed")
    mod.tool_error("exabeam_search_alerts", 12.5, RuntimeError("Invalid filter value alert_name:\"finance user p.mensah\""),
                   stage="remote", error_type_name="HTTPStatusError", error_code="AAA_ESA_1000_400", http_status=400,
                   is_retryable=False, outcome_unknown=True, dropped_fields=["note", "tags"])
    mod._shutdown()
    rec = [json.loads(l) for l in path.read_text().splitlines() if '"tool_error"' in l][-1]
    data = rec["data"]
    assert data["error_code"] == "AAA_ESA_1000_400" and data["http_status"] == 400 and data["is_retryable"] is False
    assert data["outcome_unknown"] is True and data["dropped_fields"] == "note,tags"
    assert not data.get("error_message"), "observra's event schema carries the key; this shim never fills it"
    assert "p.mensah" not in path.read_text()


def test_the_explicit_off_switch_is_announced_on_stderr(monkeypatch, capsys, tmp_path):
    """#215: RAFFKIN_OBSERVRA=off turns the audit trail off and says so, as the gate log's switch does."""
    probe = _fresh(monkeypatch, {})
    for val in sorted(probe._OFF_VALUES):
        mod = _fresh(monkeypatch, {"RAFFKIN_OBSERVRA": val})
        assert mod.enabled() is False
        err = capsys.readouterr().err
        assert "observra logging is OFF (RAFFKIN_OBSERVRA=off)" in err and "not recorded" in err, (val, err)
    mod = _fresh(monkeypatch, {"RAFFKIN_OBSERVRA": "jsonl", "RAFFKIN_OBSERVRA_PATH": str(tmp_path / "t.jsonl")})
    if not mod.enabled():
        pytest.skip("observra not installed")
    assert "logging is OFF (RAFFKIN_OBSERVRA=off)" not in capsys.readouterr().err
