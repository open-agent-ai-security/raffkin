#!/usr/bin/env python3
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Merge Raffkin's governance permissions snippet into a Claude Code settings.json.

For organizations that push the plugin's tiers as host policy (#226): the gate itself is
the bundled hook, active on install, and nothing in the install path runs this. It is a
maintained tool for generating a merged settings file from the published snippet, run by
an operator who asks for it.

Design rules, all of them load-bearing:

* **Additive only.** Snippet entries are appended to their tier. The operator's own
  rules are never removed, reordered, or rewritten. Merging is a union, not a reset.
* **Tier conflicts abort the whole merge.** If a rule the snippet wants in `ask`
  already sits in the operator's `allow` (or vice versa), that is either deliberate
  operator intent or a mis-merge a human should look at — either way, silently
  *moving* it would be us overriding a human decision about a safety control. We stop
  and report every conflict instead, and write nothing.
* **Backup before write, restore on failure.** The target is the operator's real
  settings file; a half-written settings.json breaks Claude Code entirely.
* **Idempotent.** Re-running detects an already-merged gate and changes nothing.
  Callers verify by re-reading the settings file afterwards rather than trusting our
  exit code.

Note that a merge can be a no-op for the `ask` tier and still have real work to do:
an operator who hand-copied only the two dismiss/close lines has a gate that reads ON
while the entire containment `deny` list is missing. So "gate is on" is not a reason
to skip the merge — only "every snippet entry is already in its tier" is.

Exit codes (deliberately not 0/1 so an unhandled traceback's exit 1 can never be
mistaken for a real answer):

    0   changes applied  (or, with --dry-run, changes are pending)
    10  already merged — nothing to do
    20  tier conflict — operator must resolve; nothing written
    30  error (unreadable/malformed input, write failure) — nothing written

Usage:
    merge_permissions.py --snippet PATH --settings PATH [--dry-run]
"""
import argparse
import json
import os
import shutil
import stat
import sys
import tempfile
import time

EXIT_APPLIED = 0
EXIT_NOOP = 10
EXIT_CONFLICT = 20
EXIT_ERROR = 30

TIERS = ("allow", "ask", "deny")


class MergeError(Exception):
    """Anything that means 'we cannot safely proceed' — always exits 30, never writes."""


def load_json(path, what):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise MergeError("%s not found: %s" % (what, path))
    except json.JSONDecodeError as exc:
        raise MergeError("%s is not valid JSON (%s): %s" % (what, exc, path))
    except OSError as exc:
        raise MergeError("could not read %s (%s): %s" % (what, exc, path))


def snippet_permissions(snippet):
    """Extract {tier: [rules]} from the snippet, rejecting shapes we don't understand.

    A snippet that parses but has the wrong shape must not read as 'nothing to merge'
    — that would report a green no-op while installing no gate at all.
    """
    if not isinstance(snippet, dict):
        raise MergeError("snippet is not a JSON object")
    perms = snippet.get("permissions")
    if not isinstance(perms, dict):
        raise MergeError("snippet has no `permissions` object")
    out = {}
    for tier in TIERS:
        rules = perms.get(tier, [])
        if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
            raise MergeError("snippet `permissions.%s` is not a list of strings" % tier)
        out[tier] = rules
    if not any(out.values()):
        raise MergeError("snippet declares no permission rules at all")
    return out


def settings_permissions(settings):
    """Extract the target's existing {tier: [rules]}, tolerating absent keys.

    A *missing* permissions block is normal (fresh install). A permissions block of the
    wrong type is not — we refuse rather than clobber whatever the operator has there.
    """
    if not isinstance(settings, dict):
        raise MergeError("settings.json is not a JSON object")
    perms = settings.get("permissions", {})
    if not isinstance(perms, dict):
        raise MergeError("settings.json `permissions` is not an object")
    out = {}
    for tier in TIERS:
        rules = perms.get(tier, [])
        if not isinstance(rules, list):
            raise MergeError("settings.json `permissions.%s` is not a list" % tier)
        out[tier] = [r for r in rules if isinstance(r, str)]
    return out


def plan_merge(snippet_perms, current_perms):
    """Compute (additions, conflicts) without touching anything.

    additions: {tier: [rules to append]}   — preserves snippet order
    conflicts: [(rule, snippet_tier, operator_tier)]

    Conflict detection is exact-string, which is enough because the snippet already
    carries both the bundled (`mcp__plugin_raffkin_exabeam__…`) and manual
    (`mcp__exabeam__…`) spellings of the gated tools. We deliberately do not try to
    reason about wildcard rules the operator may have written: guessing at what
    `mcp__plugin_raffkin_exabeam__*` in `allow` means is exactly the kind of inference
    that produces a confidently wrong safety control.
    """
    additions = {tier: [] for tier in TIERS}
    conflicts = []
    for tier in TIERS:
        for rule in snippet_perms[tier]:
            if rule in current_perms[tier]:
                continue  # already merged
            other = [t for t in TIERS if t != tier and rule in current_perms[t]]
            if other:
                conflicts.append((rule, tier, other[0]))
                continue
            if rule not in additions[tier]:  # snippet self-duplicates are harmless
                additions[tier].append(rule)
    return additions, conflicts


def apply_merge(settings, additions):
    """Append additions into settings in place, creating containers as needed.

    Mutating the loaded object (rather than rebuilding it) is what preserves the
    operator's key order and every top-level setting we know nothing about.
    """
    perms = settings.setdefault("permissions", {})
    for tier in TIERS:
        if not additions[tier]:
            continue
        perms.setdefault(tier, []).extend(additions[tier])
    return settings


def backup_path(path):
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return "%s.raffkin-backup-%s" % (path, stamp)


def write_settings(path, settings, backup):
    """Write settings atomically, restoring from `backup` if anything goes wrong.

    Temp file lands in the same directory so os.replace() is a true atomic rename
    (across filesystems it would not be), and the original file mode is carried over
    so a 600 settings.json doesn't silently widen to the umask default.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    # Read the mode off the live file, not off the backup: shutil.copyfile() does not carry
    # permissions, so a backup-derived mode would silently widen a 600 settings.json.
    mode = None
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        pass
    tmp = None
    try:
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".raffkin-settings-", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(settings, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.chmod(tmp, mode if mode is not None else 0o600)
        os.replace(tmp, path)
        tmp = None
    except Exception as exc:
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        if backup and os.path.exists(backup):
            try:
                shutil.copyfile(backup, path)
                raise MergeError(
                    "write failed (%s) — settings.json restored from %s" % (exc, backup))
            except OSError as restore_exc:
                raise MergeError(
                    "write failed (%s) AND restore failed (%s) — your original settings "
                    "are at %s" % (exc, restore_exc, backup))
        raise MergeError("write failed (%s) — nothing was changed" % exc)


def describe(additions):
    return ", ".join("%s +%d" % (t, len(additions[t])) for t in TIERS if additions[t])


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Merge the Raffkin governance permissions snippet into settings.json")
    ap.add_argument("--snippet", required=True, help="path to settings.snippet.json")
    ap.add_argument("--settings", required=True, help="path to ~/.claude/settings.json")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would change; write nothing")
    args = ap.parse_args(argv)

    try:
        snippet_perms = snippet_permissions(load_json(args.snippet, "permissions snippet"))

        # A missing settings.json is the fresh-install case, not an error: there is
        # nothing to back up and nothing to lose, so we create it.
        creating = not os.path.exists(args.settings)
        settings = {} if creating else load_json(args.settings, "settings.json")
        current_perms = settings_permissions(settings)

        additions, conflicts = plan_merge(snippet_perms, current_perms)

        if conflicts:
            print("Tier conflict — refusing to merge. These rules already exist in a "
                  "different tier than the snippet specifies:", file=sys.stderr)
            for rule, want, have in conflicts:
                print("  %s\n      snippet wants: %s   your settings have: %s"
                      % (rule, want, have), file=sys.stderr)
            print("\nThat is either deliberate (your intent wins) or a mis-merge worth a "
                  "look. Nothing was written. Resolve those entries in %s, then re-run."
                  % args.settings, file=sys.stderr)
            return EXIT_CONFLICT

        total = sum(len(v) for v in additions.values())
        if total == 0:
            print("Permissions snippet already merged — no changes needed.")
            return EXIT_NOOP

        if args.dry_run:
            print("Would add %d rule(s) to %s (%s):"
                  % (total, args.settings, describe(additions)))
            for tier in TIERS:
                for rule in additions[tier]:
                    print("  %-5s %s" % (tier, rule))
            return EXIT_APPLIED

        backup = None
        if not creating:
            backup = backup_path(args.settings)
            try:
                # copy2, not copyfile: the backup is a verbatim copy of the operator's
                # settings and must inherit its permissions rather than land at the
                # umask default (a 600 settings.json backed up world-readable is a leak).
                shutil.copy2(args.settings, backup)
            except OSError as exc:
                raise MergeError("could not create backup %s (%s) — nothing was changed"
                                 % (backup, exc))

        write_settings(args.settings, apply_merge(settings, additions), backup)

        if creating:
            print("Created %s with %d permission rule(s) (%s)."
                  % (args.settings, total, describe(additions)))
        else:
            print("Merged %d permission rule(s) into %s (%s)."
                  % (total, args.settings, describe(additions)))
            print("Backup of your previous settings: %s" % backup)
        return EXIT_APPLIED

    except MergeError as exc:
        print("%s" % exc, file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
