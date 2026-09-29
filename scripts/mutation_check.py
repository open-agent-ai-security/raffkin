#!/usr/bin/env python3
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Mutation gate for the output neutralizer (#120): delete a rule, the suite must notice.

Each entry below removes or loosens one rule of plugin/connector/neutralize_output.py in a scratch copy
of the repository and runs the neutralizer-facing tests there. A mutation the suite still passes has
SURVIVED -- the rule has no witness -- and this script exits 1. Run in CI; run locally after adding a
guard to the control, and add a mutation for that guard here (CONTRIBUTING, "Making a change").

The anchors are exact source strings: a refactor that moves one is a loud failure ("anchor not found"),
never a silently skipped mutation. Nothing outside the scratch copy is touched.

Usage:  uv run --with pytest --with jsonschema scripts/mutation_check.py [--list] [--only NAME]
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = Path("plugin/connector/neutralize_output.py")
TESTS = ["tests/test_neutralize_coverage.py", "tests/test_neutralize_output.py", "tests/test_neutralize_html.py",
         "tests/test_secret_redaction.py", "tests/test_bridge_wiring.py", "tests/test_redteam_corpus.py"]

# (name, exact source to find, replacement). Raw strings: these are regex sources, backslashes included.
MUTATIONS = [
    ("table-cell formula pass deleted",
     '        if "|" in core:                                     # markdown-table cells',
     '        if False:                                         # MUTATED'),
    ("quoted-field formula pass deleted",
     "        core = _QUOTED_FORMULA_RE.sub(_q, core)\n",
     "        pass  # MUTATED\n"),
    ("tab-field formula pass deleted",
     "            if _is_formula(stripped):\n                found = True\n",
     "            if False:\n                found = True\n"),
    ("jwt pattern deleted",
     r'    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),' + "\n",
     ""),
    ("private-key pattern deleted",
     r'    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", re.S)),' + "\n",
     ""),
    ("ssn pattern deleted",
     r'    ("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),' + "\n",
     ""),
    ("audit note re-leaks the labeled secret",
     '            lead, _core, tail = trimmed\n            _note("secret")\n',
     '            lead, _core, tail = trimmed\n            ns.append({"type": "redact:secret", "original": _core})  # MUTATED\n'),
    ("EXEC/CALL/REGISTER/RTD accept a space before (",
     r"(?:EXEC|CALL|REGISTER|RTD)\(|",
     r"(?:EXEC|CALL|REGISTER|RTD)\s*\(|"),
    ("bearer/passcode/client-secret keywords dropped",
     r'    r"secret|token|bearer|credential|passcode")',
     r'    r"secret|token|credential")'),
    ("weak-separator newline/pipe branch dropped",
     r'    r"(\s+(?:is|was)\s+|\s*[\r\n|]+\s*[-*|]?\s*)"' + "\n",
     r'    r"(\s+(?:is|was)\s+)"' + "\n"),
    ("aws secret-by-proximity pass off",
     "    if had_aws_key:\n",
     "    if False:  # MUTATED\n"),
    ("inline markdown link defang off",
     "    text = _defang_md_inline_links(text, allowed, notes)\n",
     "    pass  # MUTATED\n"),
    ("mid-line DDE channel alternative removed",
     "{1,200}![\\w'$.]{1,20})\",     # DDE channel: prog|topic!item\n",
     "{1,200}(?!x)x)\",     # MUTATED\n"),
    ("quoted-label separator dropped (JSON / raw-field dumps leak)",
     '    r"([\\"\'`]?\\s*[:=]\\s*)"\n',
     '    r"(\\s*[:=]\\s*)"\n'),
    ("keyword boundary reverted to \\b (underscore-joined keys leak)",
     '_KW_L, _KW_R = r"(?<![A-Za-z0-9])", r"(?![A-Za-z0-9])"',
     '_KW_L, _KW_R = r"\\b", r"\\b"'),
    ("cell-reference prefix removed from the mid-line pass",
     r'_CELL_REF = r"(?:[A-Za-z]{1,3}\d{1,7})?"',
     r'_CELL_REF = r""'),
]

IGNORE = shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".DS_Store", ".venv", "guide", "results", "transcripts")


def run_tests(tree):
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *TESTS],
                       cwd=tree, capture_output=True, text=True)
    summary = next((l for l in reversed(r.stdout.splitlines()) if "passed" in l or "failed" in l or "error" in l), r.stdout[-200:])
    return r.returncode, summary


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--only", help="run one mutation by (a substring of) its name")
    a = ap.parse_args(argv)
    if a.list:
        for name, _o, _n in MUTATIONS:
            print(name)
        return 0
    src = (ROOT / TARGET).read_text()
    missing = [name for name, old, _new in MUTATIONS if old not in src]
    if missing:
        print("anchor not found (the control changed; update the mutation set):\n  " + "\n  ".join(missing), file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="raffkin-mut-") as tmp:
        tree = Path(tmp) / "tree"
        shutil.copytree(ROOT, tree, ignore=IGNORE)
        rc, summary = run_tests(tree)
        if rc != 0:
            print(f"baseline is not green, refusing to grade mutations: {summary}", file=sys.stderr)
            return 2
        print(f"baseline: {summary}")
        survived = []
        for name, old, new in MUTATIONS:
            if a.only and a.only not in name:
                continue
            (tree / TARGET).write_text(src.replace(old, new, 1))
            rc, summary = run_tests(tree)
            verdict = "killed  " if rc != 0 else "SURVIVED"
            print(f"  {verdict}  {name}  ({summary})")
            if rc == 0:
                survived.append(name)
        (tree / TARGET).write_text(src)
    if survived:
        print(f"\n{len(survived)} mutation(s) survived -- the suite does not witness these rules:", file=sys.stderr)
        for s in survived:
            print(f"  - {s}", file=sys.stderr)
        return 1
    print(f"\nall {len(MUTATIONS) if not a.only else 1} mutation(s) killed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
