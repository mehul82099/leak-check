#!/usr/bin/env python3
"""leak_check - scan source files for hardcoded secrets.

Finds the credentials that end up committed by accident: AWS access keys,
GitHub and Slack tokens, Stripe live keys, Google API keys, private key
blocks, JWTs, password-style assignments, and high-entropy strings. Matched
secrets are redacted in the output, never printed in full.

Python 3.9+, standard library only. No network.

Usage:
    python leak_check.py .                     # scan a directory tree
    python leak_check.py src/ config/app.py    # mix of dirs and files
    python leak_check.py . --json              # machine-readable output
    python leak_check.py . --strict            # warnings also give exit 1

Exit codes: 0 = no findings, 1 = errors found (or warnings with --strict),
2 = bad input (missing path, or nothing scannable).

Allowlisting: put `leak-check: allow` on a line to skip it, or list path
globs (fnmatch syntax, one per line) in a .leakcheckignore file in the
current directory.
"""

import argparse
import fnmatch
import json
import math
import os
import re
import sys

ALLOW_MARK = "leak-check: allow"
IGNORE_FILE = ".leakcheckignore"
DEFAULT_MAX_BYTES = 1000000
ENTROPY_THRESHOLD = 4.5  # bits per char; random base64 is ~6, English ~3.5-4
ENTROPY_MIN_LEN = 20

ERROR = "error"
WARNING = "warning"

RULES = [
    ("aws-access-key-id", ERROR,
     re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
     "AWS access key ID"),
    ("github-token", ERROR,
     re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}"
                r"|github_pat_[A-Za-z0-9_]{22,255})\b"),
     "GitHub token"),
    ("slack-token", ERROR,
     re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b"),
     "Slack token"),
    ("stripe-live-key", ERROR,
     re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{16,99})\b"),
     "Stripe live secret/restricted key"),
    ("stripe-test-key", WARNING,
     re.compile(r"\b((?:sk|rk)_test_[0-9A-Za-z]{16,99})\b"),
     "Stripe test key"),
    ("google-api-key", ERROR,
     re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
     "Google API key"),
    ("private-key", ERROR,
     re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?"
                r"PRIVATE KEY(?: BLOCK)?-----)"),
     "private key block"),
    ("jwt", WARNING,
     re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
                r"\.[A-Za-z0-9_-]{8,})\b"),
     "JSON Web Token"),
]

GENERIC_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|secret[_-]?key|api[_-]?key|apikey|"
    r"access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*"
    r"[\"']([^\"'\n]{8,})[\"']")

PLACEHOLDER_RES = [
    re.compile(r"^(your\S*|change[-_ ]?me|changeme|placeholder\w*|"
               r"dummy\w*|fake\w*|test\w*|example\w*|sample\w*|xxx+|\*+|"
               r"\.+|none|null|nil|todo|redacted|hidden|secret|password|"
               r"not[-_ ]?set|empty)$", re.IGNORECASE),
    re.compile(r"^(<|\$|\{|%)"),                      # <VAR>, ${VAR}, $VAR, %VAR%
    re.compile(r"(process\.env|os\.environ|getenv|ENV\[|settings\.)",
               re.IGNORECASE),
]

ENTROPY_TOKEN_RE = re.compile(r"[\"']([A-Za-z0-9+/=_-]{%d,})[\"']"
                              % ENTROPY_MIN_LEN)


def shannon_entropy(text):
    """Bits of entropy per character (Shannon 1948)."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def char_classes(text):
    classes = 0
    if any(c.islower() for c in text):
        classes += 1
    if any(c.isupper() for c in text):
        classes += 1
    if any(c.isdigit() for c in text):
        classes += 1
    if any(not c.isalnum() for c in text):
        classes += 1
    return classes


def is_placeholder(value):
    return any(r.search(value) for r in PLACEHOLDER_RES)


def redact(secret):
    """Show a prefix and length, never the full secret."""
    if len(secret) <= 4:
        return "(%d chars)" % len(secret)
    return "%s...(%d chars)" % (secret[:4], len(secret))


def scan_line(line):
    """Apply the token rules to one line. Returns (findings, matched_tokens)."""
    findings = []
    matched = []
    for rule_id, severity, pattern, label in RULES:
        for m in pattern.finditer(line):
            token = m.group(1)
            findings.append((rule_id, severity,
                             "%s: %s" % (label, redact(token))))
            matched.append(token)
    m = GENERIC_RE.search(line)
    if m and not is_placeholder(m.group(2)):
        findings.append(("generic-secret", WARNING,
                         "hardcoded %s: %s"
                         % (m.group(1).lower(), redact(m.group(2)))))
    for m in ENTROPY_TOKEN_RE.finditer(line):
        token = m.group(1)
        if any(token in t or t in token for t in matched):
            continue
        if char_classes(token) >= 3 \
                and shannon_entropy(token) >= ENTROPY_THRESHOLD:
            findings.append(("high-entropy-string", WARNING,
                             "high-entropy string (%.1f bits/char): %s"
                             % (shannon_entropy(token), redact(token))))
    return findings


def looks_binary(raw):
    return b"\x00" in raw[:8192]


def scan_file(path, max_bytes):
    """Scan one file. Returns (findings, status) where status is one of
    'scanned', 'binary', 'too-large', 'unreadable'. Findings are
    (line_number, rule_id, severity, message)."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return [], "unreadable"
    if size > max_bytes:
        return [], "too-large"
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return [], "unreadable"
    if looks_binary(raw):
        return [], "binary"
    text = raw.decode("utf-8", errors="replace")
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARK in line:
            continue
        for rule_id, severity, message in scan_line(line):
            findings.append((lineno, rule_id, severity, message))
    return findings, "scanned"


def load_ignore_globs(cwd):
    globs = []
    path = os.path.join(cwd, IGNORE_FILE)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    globs.append(line)
    except OSError:
        pass
    return globs


def ignored(relpath, globs):
    base = os.path.basename(relpath)
    return any(fnmatch.fnmatch(relpath, g) or fnmatch.fnmatch(base, g)
               for g in globs)


def collect_files(paths, globs):
    """Expand args into a sorted file list. Returns (files, fatal_error)."""
    files = []
    for path in paths:
        if not os.path.exists(path):
            return None, "no such file or directory: %s" % path
        if os.path.isdir(path):
            for root, dirnames, filenames in os.walk(path):
                dirnames[:] = [d for d in dirnames if d != ".git"]
                for name in filenames:
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, path)
                    if not ignored(rel, globs):
                        files.append(full)
        elif os.path.isfile(path):
            if not ignored(os.path.relpath(path), globs):
                files.append(path)
        else:
            return None, "not a regular file: %s" % path
    return sorted(files), None


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="leak_check",
        description="Scan source files for hardcoded secrets.")
    parser.add_argument("paths", nargs="+",
                        help="files and/or directories to scan")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 on warnings too")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help="skip files larger than this (default: %d)"
                             % DEFAULT_MAX_BYTES)
    args = parser.parse_args(argv)

    globs = load_ignore_globs(os.getcwd())
    files, fatal = collect_files(args.paths, globs)
    if fatal:
        print("leak_check: %s" % fatal, file=sys.stderr)
        return 2
    if not files:
        print("leak_check: nothing to scan", file=sys.stderr)
        return 2

    findings = []
    skipped = {"binary": 0, "too-large": 0, "unreadable": 0}
    scanned = 0
    for path in files:
        file_findings, status = scan_file(path, args.max_bytes)
        if status == "scanned":
            scanned += 1
            for lineno, rule_id, severity, message in file_findings:
                findings.append({
                    "file": path, "line": lineno, "rule": rule_id,
                    "severity": severity, "message": message})
        else:
            skipped[status] += 1

    if scanned == 0:
        print("leak_check: nothing to scan (all files skipped)",
              file=sys.stderr)
        return 2

    errors = sum(1 for f in findings if f["severity"] == ERROR)
    warnings = sum(1 for f in findings if f["severity"] == WARNING)
    if args.json:
        print(json.dumps({
            "files_scanned": scanned,
            "files_skipped": skipped,
            "errors": errors,
            "warnings": warnings,
            "findings": findings,
        }, indent=2, ensure_ascii=False))
    else:
        for f in findings:
            print("%s:%d: %s [%s] %s"
                  % (f["file"], f["line"], f["severity"], f["rule"],
                     f["message"]))
    if errors or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
