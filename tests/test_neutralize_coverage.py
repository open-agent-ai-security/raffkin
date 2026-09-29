# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Mechanical coverage of the output neutralizer's secret and formula rules (#120).

The suite used to stay green with whole rules deleted: on 2026-09-13 seven mutations of
neutralize_output.py -- the table-cell and quoted-field formula passes removed, the JWT pattern removed,
three credential keywords dropped, the weak-separator newline branch dropped, the audit note made to
re-leak the secret -- each passed all 790 tests, unchanged since the issue was filed in August. These
tests make every rule's presence OBSERVABLE:

  - every compiled secret pattern is witnessed by a bare sample that no other pattern matches, and the
    sample survives verbatim when that one pattern is removed;
  - every credential keyword is witnessed by a labeled form that only that alternative can match;
  - each formula pass (table cell, tab field, quoted field, mid-line) is witnessed by a case the other
    passes cannot see; the English-word-function no-space guard is asserted in both directions;
  - the weak-separator branches (line break, inline pipe, bullet, copula) each have a witness;
  - the audit note is checked for re-leak on every redaction path, not one;
  - the do-no-harm corpus runs through the FULL pipeline, not the redactor alone.

`scripts/mutation_check.py` deletes each rule in a scratch copy and requires this suite to fail; CI runs
it. The two phase-B shapes (DDE mid-prose, a cell reference glued to the sign) were pinned here as
strict xfails until phase B closed them; they are ordinary tests now. No model,
no creds, CI-safe.
"""
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("neut_cov", ROOT / "plugin" / "connector" / "neutralize_output.py")
N = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(N)

VAL = "Xk9mq2Lp4Zr8vQ"      # 14 chars, digits and letters: passes every shape guard (6+; 12+ with digit and letter)


# ---- 1. every secret pattern is witnessed, and only by itself -------------------------------------------

# Bare values (no label, so the labeled rules cannot help). Each must match EXACTLY one entry of
# _SECRET_PATTERNS; every entry must be matched by at least one. A pattern added without a sample here
# fails the test that enumerates the list -- the mechanical floor the #120 review asked for.
PATTERN_SAMPLES = [
    ("private-key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"),
    ("private-key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"),
    ("aws-key", "AKIAIOSFODNN7EXAMPLE"),
    ("aws-key", "ASIAIOSFODNN7EXAMPLE"),
    ("jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
    ("token", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
    ("token", "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
    ("token", "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
    ("token", "github_pat_11ABCDEFG0123456789abcdefghijklmnop"),
    # Vendor tokens are assembled from parts: a token-shaped literal in source trips GitHub's push
    # protection (as it should), and these are witnesses of the SHAPE, not credentials.
    ("token", "xox" + "b-" + "1234567890-abcdefghijklmnop"),
    ("token", "xox" + "p-" + "1234567890-abcdefghijklmnop"),
    ("token", "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"),
    ("token", "pk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"),
    ("token", "rk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"),
    ("token", "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"),
    ("token", "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"),
    ("token", "glp" + "at-" + "xR7kQ2mN9vB4cL8wZ1tY"),
    ("token", "sk" + "-" + "Qx7mN2vL9kR4wZ8tY1cP5bH3jD6fG0aT3BlbkFJs2Ue4Wq8Ro"),
    ("token", "sk" + "-proj-" + "Ab3dE5fG7hJ9kL2mN4pQ6rS8tU0vW"),
    ("token", "sk" + "-ant-api03-" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg"),
    ("ssn", "456-78-9012"),
]


def _matching_patterns(sample):
    return [i for i, (_k, rx) in enumerate(N._SECRET_PATTERNS) if rx.search(sample)]


def test_every_secret_pattern_has_a_witness():
    """Enumerates the shipped list: a pattern nobody wrote a sample for fails here, by name."""
    witnessed = {i for _k, s in PATTERN_SAMPLES for i in _matching_patterns(s)}
    missing = [f"{k}: {rx.pattern[:70]}" for i, (k, rx) in enumerate(N._SECRET_PATTERNS) if i not in witnessed]
    assert not missing, "secret pattern(s) with no positive sample in PATTERN_SAMPLES: " + "; ".join(missing)


@pytest.mark.parametrize("kind, sample", PATTERN_SAMPLES, ids=[s[:24] for _k, s in PATTERN_SAMPLES])
def test_secret_pattern_witness_is_unique_and_load_bearing(monkeypatch, kind, sample):
    hits = _matching_patterns(sample)
    assert len(hits) == 1, f"a witness must match exactly one pattern, {sample[:30]!r} matched {hits}"
    assert N._SECRET_PATTERNS[hits[0]][0] == kind
    out, notes = N.redact_secrets(sample, []), []
    assert f"[REDACTED:{kind}]" in out and sample not in out
    # remove THAT pattern and nothing else: the sample must now survive verbatim -- so deleting the
    # pattern is visible to the suite (mutation 3 of #120, generalized to every pattern)
    monkeypatch.setattr(N, "_SECRET_PATTERNS", [p for i, p in enumerate(N._SECRET_PATTERNS) if i != hits[0]])
    assert sample in N.redact_secrets(sample, notes), f"{kind} witness was caught by something other than its pattern"


# ---- 2. every credential keyword is witnessed, and only by itself ---------------------------------------

def _top_level_alternatives(pattern):
    out, cur, depth = [], [], 0
    for ch in pattern:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "|" and depth == 0:
            out.append("".join(cur)); cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


# alternative source -> a label that ONLY this alternative matches (the underscore forms defeat the bare
# `secret` / `token` alternatives: `_` is a word character, so \bsecret\b does not fire inside
# client_secret). Keyed by source so a changed or added alternative fails loudly, not silently.
KEYWORD_SAMPLES = {
    r"passwo?r?d": "password",
    r"passwd": "passwd",
    r"pwd": "pwd",
    r"pass[\s_-]?phrase": "passphrase",
    r"secret[\s_-]?(?:access[\s_-]?)?key": "secret_access_key",
    r"access[\s_-]?key(?:[\s_-]?id)?": "access_key_id",
    r"api[\s_-]?(?:key|token|secret)": "api_key",
    r"auth(?:orization)?[\s_-]?token": "authorization_token",
    r"client[\s_-]?secret": "client_secret",
    r"secret": "secret",
    r"token": "token",
    r"bearer": "bearer",
    r"credential": "credential",
    r"passcode": "passcode",
}
# `passwo?r?d` already matches "passwd" (both optionals absent), so the `passwd` alternative is redundant
# by construction. And since `_` became a separator at the keyword's edges (#118 review: compound keys
# like aws_secret_access_key), the compound alternatives whose last word is itself a keyword are reached
# by that word alone -- `client_secret` by `secret`, `authorization_token` by `token`,
# `secret_access_key` by `access_key`. Recorded rather than removed: the test below proves each label
# stays covered without its alternative. Anything else listed here is a bug.
REDUNDANT_ALTERNATIVES = {r"passwd", r"auth(?:orization)?[\s_-]?token", r"client[\s_-]?secret", r"secret[\s_-]?(?:access[\s_-]?)?key"}


def test_keyword_sample_table_matches_the_shipped_alternation():
    alts = _top_level_alternatives(N._KEYWORD)
    assert set(alts) == set(KEYWORD_SAMPLES), (
        f"missing samples: {sorted(set(alts) - set(KEYWORD_SAMPLES))}; stale samples: {sorted(set(KEYWORD_SAMPLES) - set(alts))}")


@pytest.mark.parametrize("alt", list(KEYWORD_SAMPLES), ids=list(KEYWORD_SAMPLES.values()))
def test_keyword_alternative_is_load_bearing(monkeypatch, alt):
    label = KEYWORD_SAMPLES[alt]
    text = f"{label}: {VAL}"
    assert VAL not in N.redact_secrets(text, []), f"{label!r} is not redacted at all"
    reduced = "|".join(a for a in _top_level_alternatives(N._KEYWORD) if a != alt)
    monkeypatch.setattr(N, "_LABELED_SECRET_RE", re.compile(N._LABELED_SECRET_RE.pattern.replace(N._KEYWORD, reduced)))
    out = N.redact_secrets(text, [])
    if alt in REDUNDANT_ALTERNATIVES:
        assert VAL not in out, f"{alt!r} was recorded as redundant but the label is uncovered without it"
    else:
        assert VAL in out, f"{label!r} is still redacted with the {alt!r} alternative removed -- something else catches it"


# ---- 2a. `_` separates at the keyword's edges -- compound keys (#118 review) --------------------------------

V40 = "Kq7ZnP2xLm9vRt4bYw8cHs3dFj6gTu1aQe5oIu0N"


@pytest.mark.parametrize("text", [
    f'"aws_secret_access_key": "{V40}"',        # no AKIA nearby: the label, not the proximity rule, must carry it
    f"service_password: {V40}",
    f"my_api_key={V40}",
    f"oauth_token_secret: {V40}",
    f"x-api-key: {V40}",
    f"user.password: {V40}",
    f"| aws_secret_access_key | {V40} |",       # table form
    f"API_TOKEN\n{V40}",                       # weak separator
    f"--service_password {V40}",               # space flag
], ids=["json-aws", "service_password", "my_api_key", "oauth_token_secret", "hyphen", "dot", "table", "newline", "flag"])
def test_compound_keys_with_underscores_are_redacted(text):
    """Environment variables, config keys, Terraform state, Kubernetes secrets: the keyword sits at the end
    of an underscore-joined key. `\\b` treated `_` as a word character, so there was no boundary before it
    and the label never matched. Mutation: the boundary reverted to `\\b`."""
    out = N.redact_secrets(text, [])
    assert V40 not in out and "[REDACTED:secret]" in out, out


@pytest.mark.parametrize("prose", [
    "password_reset_count: 12345678",          # the keyword is not at the key's end: not a label
    "token_bucket_size: 500000",
    "the on_call rotation is weekly",
    "secret_santa: organiser",
])
def test_compound_keys_do_no_harm(prose):
    assert N.redact_secrets(prose, []) == prose


# ---- 2b. a quoted label -- JSON / raw-field dumps (#118) ----------------------------------------------------

@pytest.mark.parametrize("text, expect", [
    ('{"client_secret": "Xk9mq2Lp4Zr8vQ", "scope": "read"}', '{"client_secret": "[REDACTED:secret]", "scope": "read"}'),
    ('{"password":"Hunter2-prod-2026"}', '{"password":"[REDACTED:secret]"}'),
    ("dump: {'api_key': 'Xk9mq2Lp4Zr8vQ'}", "dump: {'api_key': '[REDACTED:secret]'}"),
    ('`token`: `Xk9mq2Lp4Zr8vQ`', '`token`: `[REDACTED:secret]`'),
], ids=["json-double", "json-tight", "python-single", "backticks"])
def test_quoted_label_forms_are_redacted(text, expect):
    """A JSON or raw-field dump puts a closing quote between the keyword and the separator; the value's
    own quotes are peeled and handed back so the structure survives. Mutation: drop the optional quote."""
    assert N.redact_secrets(text, []) == expect


@pytest.mark.parametrize("prose", [
    'the "token" field is documented below',            # quoted keyword, no separator: prose
    "password: n/a",                                      # under the 6-char floor
    '"password": "none"',                                  # quoted label, value under the 6-char floor
])
def test_quoted_label_does_no_harm(prose):
    assert N.redact_secrets(prose, []) == prose


# ---- 3. each formula pass has a witness the other passes cannot see -------------------------------------

F = "=SUM(1+1)*2"      # a generic sign+name+( formula: NOT on the mid-line allowlist, so only a
                       # position-keyed pass (cell, tab field, quoted field) can catch it


def test_table_cell_formula_pass_is_load_bearing():
    out = N.neutralize_output(f"| user | {F} | ok |")[0]
    assert f"| '{F} |" in out, out


def test_tab_field_formula_pass_is_load_bearing():
    out = N.neutralize_output(f"user\t{F}\tok")[0]
    assert f"\t'{F}\t" in out, out


def test_quoted_field_formula_pass_is_load_bearing():
    out = N.neutralize_output(f'exported as "{F}" from the sheet')[0]
    assert f'"\'{F}"' in out, out


def test_mid_line_pass_needs_a_known_name_and_the_position_passes_do_not():
    """The mid-line pass catches an allowlisted name in prose; a generic name in prose is left alone --
    the two passes are different rules, and this pins which one is which."""
    assert "'=HYPERLINK" in N.neutralize_output('field: =HYPERLINK("https://evil.example/x")')[0]
    assert N.neutralize_output(f"the score {F} was fine")[0] == f"the score {F} was fine"


@pytest.mark.parametrize("name", ["EXEC", "CALL", "REGISTER", "RTD"])
def test_english_word_function_needs_the_paren_attached(name):
    """Both directions of the guard: attached paren is a macro call and is quoted; a space before the
    paren is prose and is not (mutation 5 of #120 loosened the guard and the suite stayed green)."""
    assert f"'={name}(" in N.neutralize_output(f"note: ={name}(calc)")[0]
    prose = f"note: ={name} (see runbook)"
    assert N.neutralize_output(prose)[0] == prose


# ---- 4. the weak separators, branch by branch -----------------------------------------------------------

@pytest.mark.parametrize("text", [
    f"API token\n{VAL}",              # bare line break
    f"token\n- {VAL}",                # line break then a bullet marker
    f"token | {VAL}",                 # inline pipe (NOT a table row: no leading |)
    f"the secret was {VAL}",          # copula
    f"credential is {VAL}",
], ids=["newline", "newline-bullet", "inline-pipe", "was", "is"])
def test_weak_separator_branches_each_catch_a_secret_shaped_value(text):
    out = N.redact_secrets(text, [])
    assert VAL not in out and "[REDACTED:secret]" in out, out


# ---- 5. the audit note never carries the secret, on any path --------------------------------------------

NOTE_PATHS = [
    ("labeled", f"password: {VAL}"),
    ("labeled-quoted", f"token = `{VAL}`"),
    ("table-row", f"| password | {VAL} |"),
    ("weak-newline", f"token\n{VAL}"),
    ("weak-was", f"the secret was {VAL}"),
    ("space-flag", f"--secret-key {VAL}"),
] + [(f"pattern:{k}", s) for k, s in PATTERN_SAMPLES]


@pytest.mark.parametrize("path, text", NOTE_PATHS, ids=[p for p, _ in NOTE_PATHS])
def test_audit_note_never_contains_the_secret_on_any_path(path, text):
    notes = []
    out = N.redact_secrets(text, notes)
    assert notes, f"{path}: nothing was redacted"
    secret = VAL if VAL in text else text.split("\n")[1] if "\n" in text else text
    probe = secret[:10]
    assert probe not in out, f"{path}: the secret survived into the output"
    assert all(probe not in str(n) for n in notes), f"{path}: the audit note re-leaks the secret: {notes}"


# ---- 6. the do-no-harm corpus through the FULL pipeline -------------------------------------------------

_sr = importlib.util.spec_from_file_location("test_secret_redaction", ROOT / "tests" / "test_secret_redaction.py")
_srm = importlib.util.module_from_spec(_sr); _sr.loader.exec_module(_srm)


@pytest.mark.parametrize("text", _srm.FP_SAFE)
def test_do_no_harm_corpus_survives_the_full_pipeline(text):
    """FP_SAFE was asserted against the redactor alone; a link or formula pass that mangled analyst prose
    was invisible to it. Every entry now has to come out of neutralize_output() byte-identical."""
    out, notes = N.neutralize_output(text)
    assert out == text and not notes, f"full pipeline changed legitimate text: {text!r} -> {out!r} {notes}"


# ---- #120 items 3 and 4 (phase B): DDE channel references mid-prose; a cell reference glued to the sign --

@pytest.mark.parametrize("line", [
    "The cell contained: =cmd|'/C calc'!A0 and nothing else",
    "field: =MSEXCEL|'\\..\\..\\Windows\\System32\\cmd.exe /c calc.exe'!A1",
    "seen +cmd|' /C calc'!'A1' in the export",
    "value: @SUM(cmd|' /C calc'!A0)",                          # a function wrapper around the channel
    "note: =DDE(\"cmd\",\"/C calc\",\"A0\")",                  # the named form was already covered; keep it
])
def test_mid_line_dde_channel_reference_is_neutralized(line):
    out = N.neutralize_output(line)[0]
    assert "'=" in out or "'+" in out or "'@" in out, out


@pytest.mark.parametrize("line", [
    'B2=HYPERLINK("https://evil.example/x")',
    'see A1=WEBSERVICE("https://evil.example/api") in the sheet',
    "cell ZZ9999=EXEC(calc)",
])
def test_cell_reference_glued_to_the_sign_is_neutralized(line):
    out = N.neutralize_output(line)[0]
    assert "'" in out and "https://evil.example" not in out, out


@pytest.mark.parametrize("prose", [
    "on-call|pager!escalate now",                  # sign glued to a word: still prose
    "the ratio = a|b!c is odd",                    # space after the sign: not a formula
    "score=high|low!important",                    # sign glued to a word: the lookbehind holds even with the channel shape
    "status=ok (see B2=summary(final))",           # cell-ref prefix with a non-allowlisted name
    "grep 'x|y' file.txt! done",                   # pipe and bang without a sign-led name
    "Q3=CALL (see runbook)",                       # cell-ref prefix, English-word function, space before (
])
def test_new_mid_line_forms_do_no_harm(prose):
    assert N.neutralize_output(prose)[0] == prose, N.neutralize_output(prose)[0]


@pytest.mark.parametrize("benign", [
    "sk-learn-preprocessing-pipeline", "risk-assessment-for-the-quarter",
    "host sk-prd-db-0001-replica-a", "web-sk-prod01-eu-west-1a-node",
    "branch feature/sk-1234-fix-login-timeout-bug", "sk-2024-11-audit-report",
    "ALERT-sk-8f3a2b1c-4d5e-6f70-8192-a3b4c5d6e7f8",
])
def test_sk_rule_leaves_hostnames_and_branch_names_alone(benign):
    """PRAX-2026-09-24-003 review: hostnames, branches and IDs are evidence; only key-shaped sk- values redact."""
    assert N.redact_secrets(benign, []) == benign


def test_sk_rule_stays_linear_on_a_repeated_prefix():
    """A run of sk-sk-sk-... must not make each start rescan the whole run (the lookaheads are bounded)."""
    import time
    t = time.perf_counter()
    N.neutralize_output("sk-" * 16000)
    assert time.perf_counter() - t < 1.0

