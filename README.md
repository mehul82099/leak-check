# leak-check

A small secret scanner for source trees. It finds the credentials that get committed by
accident - AWS access keys, GitHub and Slack tokens, Stripe keys, Google API keys, private
key blocks, JWTs, password-style assignments, and high-entropy strings - and prints them
redacted, never in full, so the output is safe to paste into a CI log.

Python 3.9+, standard library only. No network. MIT license.

```
python leak_check.py .                     # scan a directory tree
python leak_check.py src/ config/app.py    # mix of dirs and files
python leak_check.py . --json              # machine-readable output
python leak_check.py . --strict            # warnings also give exit code 1
python leak_check.py . --max-bytes 2000000 # change the 1 MB per-file cap
```

Output is `file:line: severity [rule] message`, with every matched secret shortened to a
4-character prefix and a length. Exit codes: `0` no findings, `1` errors found (or warnings
with `--strict`), `2` bad input (missing path, or nothing scannable).

## What it checks

| Rule id | Severity | Basis |
|---|---|---|
| `aws-access-key-id` | error | `AKIA...` / `ASIA...`, the prefixes AWS documents for long-term and temporary access key IDs (IAM identifiers) |
| `github-token` | error | the `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` and `github_pat_` prefixes from GitHub's post on its token formats |
| `slack-token` | error | `xoxb`/`xoxa`/`xoxp`/`xoxr`/`xoxs-`, the prefixes on Slack's token-types page |
| `stripe-live-key` | error | `sk_live_` / `rk_live_`, live secret and restricted keys (Stripe API keys doc) |
| `stripe-test-key` | warning | `sk_test_` / `rk_test_`: test keys are not live credentials but still should not be committed |
| `google-api-key` | error | `AIza...` (39 chars), the key format in Google Cloud's API keys doc |
| `private-key` | error | `-----BEGIN ... PRIVATE KEY-----`, the PEM textual encoding in RFC 7468 |
| `jwt` | warning | the three-base64url-part JWT structure of RFC 7519; JWTs are often examples, so this is a warning |
| `generic-secret` | warning | `password = "..."`-style assignments (also `api_key`, `client_secret`, `auth_token` and friends), 8+ chars, skipping placeholders like `changeme`, `your-...`, `${VAR}` and `process.env` references |
| `high-entropy-string` | warning | quoted 20+ char strings with Shannon entropy of 4.5 bits/char or more and at least 3 character classes. Requiring mixed classes filters out hex digests and UUIDs; matches already caught by another rule are not double-reported |

## Allowlisting

- Put `leak-check: allow` on a line to skip it (for test fixtures and documented examples).
- Put path globs (fnmatch syntax, one per line) in a `.leakcheckignore` file in the
  directory you run from. Patterns match the path relative to the scanned root, or the
  basename.

`.git` directories are always skipped. Binary files (a NUL byte in the first 8 KB) and
files over the size cap are skipped and counted in the JSON report.

## What it does not do

This is a pattern matcher, not a vault audit. It does not validate that a key is live, it
does not know every vendor's token format, and a determined secret in an unusual shape
(split across lines, encoded, low-entropy) will slip through. No findings does not mean no
secrets; rotate anything it does find rather than deleting it and recommitting.

## Tests

```
python -m unittest -v
```

60 tests cover every rule in both directions, the placeholder and hex-digest false-positive
filters, redaction (no test ever lets a full secret reach the output), the allowlist
mechanisms, binary and size skips, exit codes, and the JSON report shape. CI runs on Ubuntu
and Windows with Python 3.9 and 3.13 (see `.github/workflows/test.yml`); I have not run it
on other versions.

## Sources

- AWS, IAM identifiers (access key ID prefixes AKIA / ASIA): https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
- GitHub, Behind GitHub's new authentication token formats: https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
- Slack, Token types (xoxb / xoxp / ...): https://api.slack.com/authentication/token-types
- Stripe, API keys (sk_live / rk_live / test keys): https://docs.stripe.com/keys
- Google Cloud, Manage API keys (the `AIza` key format): https://cloud.google.com/docs/authentication/api-keys
- RFC 7468, Textual Encodings of PKIX, PKCS, and CMS Structures (PEM labels): https://www.rfc-editor.org/rfc/rfc7468
- RFC 7519, JSON Web Token (JWT): https://www.rfc-editor.org/rfc/rfc7519
- C. E. Shannon, A Mathematical Theory of Communication (1948), for Shannon entropy: https://people.math.harvard.edu/~ctm/home/text/others/shannon/entropy/entropy.pdf

## License

MIT, see `LICENSE`.
