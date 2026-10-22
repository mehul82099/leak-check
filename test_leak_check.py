import contextlib
import io
import json
import os
import tempfile
import unittest

import leak_check as lc


def run_cli(argv, cwd=None):
    out, err = io.StringIO(), io.StringIO()
    old = os.getcwd()
    if cwd:
        os.chdir(cwd)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = lc.main(argv)
    finally:
        os.chdir(old)
    return code, out.getvalue(), err.getvalue()


AWS_KEY = "AKIA" + "A1B2C3D4E5F6G7H8"
GH_TOKEN = "ghp_" + "a1B2c3D4" * 5
SLACK_TOK = "xoxb-1234-5678-abcdEFGH"
STRIPE_LIVE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
STRIPE_TEST = "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
GOOGLE_KEY = "AIza" + "SyDaGmWKa4JsXZ" + "-HjGw7ISLn_3namBGewQe"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
RANDOM_B64 = "mF9zX2vLqP8wKdN7rT4yUbG6hJ3sA1cE"


class RuleTests(unittest.TestCase):
    def hits(self, line):
        return [f[0] for f in lc.scan_line(line)]

    def test_aws_akia(self):
        self.assertIn("aws-access-key-id", self.hits('key = "%s"' % AWS_KEY))

    def test_aws_asia(self):
        tok = "ASIA" + "Z9Y8X7W6V5U4T3S2"
        self.assertIn("aws-access-key-id", self.hits('k="%s"' % tok))

    def test_aws_short_not_matched(self):
        self.assertNotIn("aws-access-key-id", self.hits("AKIA1234"))

    def test_github_classic(self):
        self.assertIn("github-token", self.hits('token = "%s"' % GH_TOKEN))

    def test_github_fine_grained(self):
        tok = "github_pat_11ABCDEFG0" + "x" * 40
        self.assertIn("github-token", self.hits('"%s"' % tok))

    def test_github_wrong_prefix_not_matched(self):
        self.assertNotIn("github-token", self.hits('ghz_' + "a1B2" * 10))

    def test_slack(self):
        self.assertIn("slack-token", self.hits('SLACK = "%s"' % SLACK_TOK))

    def test_slack_all_prefixes(self):
        for p in "baprs":
            tok = "xox%s-1234-56789" % p
            self.assertIn("slack-token", self.hits('"%s"' % tok))

    def test_stripe_live_is_error(self):
        f = lc.scan_line('key = "%s"' % STRIPE_LIVE)
        hit = [x for x in f if x[0] == "stripe-live-key"][0]
        self.assertEqual(hit[1], "error")

    def test_stripe_test_is_warning(self):
        f = lc.scan_line('key = "%s"' % STRIPE_TEST)
        hit = [x for x in f if x[0] == "stripe-test-key"][0]
        self.assertEqual(hit[1], "warning")

    def test_google_api_key(self):
        self.assertIn("google-api-key", self.hits('k="%s"' % GOOGLE_KEY))

    def test_private_key(self):
        for hdr in ("-----BEGIN PRIVATE KEY-----",
                    "-----BEGIN RSA PRIVATE KEY-----",
                    "-----BEGIN OPENSSH PRIVATE KEY-----",
                    "-----BEGIN ENCRYPTED PRIVATE KEY-----"):
            self.assertIn("private-key", self.hits(hdr))

    def test_public_key_not_matched(self):
        self.assertNotIn("private-key", self.hits("-----BEGIN PUBLIC KEY-----"))

    def test_jwt(self):
        self.assertIn("jwt", self.hits('t = "%s"' % JWT))

    def test_jwt_is_warning(self):
        f = lc.scan_line('t = "%s"' % JWT)
        hit = [x for x in f if x[0] == "jwt"][0]
        self.assertEqual(hit[1], "warning")

    def test_generic_password(self):
        self.assertIn("generic-secret",
                      self.hits('password = "sup3rsecretvalue"'))

    def test_generic_api_key(self):
        self.assertIn("generic-secret",
                      self.hits("api_key: 'xkcd-9928-abcd-wxyz'"))

    def test_generic_client_secret(self):
        self.assertIn("generic-secret",
                      self.hits('client_secret = "abcdef123456789"'))

    def test_generic_short_value_ignored(self):
        self.assertNotIn("generic-secret", self.hits('password = "abc"'))

    def test_placeholders_ignored(self):
        for val in ("your-password-here", "changeme", "CHANGEME", "example123",
                    "test1234", "xxxxxxxx", "********", "........", "None",
                    "<PASSWORD>", "${PASSWORD}", "$PASSWORD", "not-set"):
            self.assertNotIn("generic-secret",
                             self.hits('password = "%s"' % val), val)

    def test_env_reference_ignored(self):
        for val in ("process.env.DB_PASSWORD", "os.environ.get('X')"):
            self.assertNotIn("generic-secret",
                             self.hits('password = "%s"' % val), val)

    def test_high_entropy_string(self):
        self.assertIn("high-entropy-string",
                      self.hits('token = "%s"' % RANDOM_B64))

    def test_low_entropy_string_ignored(self):
        self.assertNotIn("high-entropy-string",
                         self.hits('s = "aaaaaaaaaaaaaaaaaaaaaaaa"'))

    def test_hex_digest_ignored(self):
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4" \
              "649b934ca495991b7852b855"
        self.assertNotIn("high-entropy-string", self.hits('h = "%s"' % sha))

    def test_english_sentence_ignored(self):
        self.assertNotIn(
            "high-entropy-string",
            self.hits('s = "the quick brown fox jumps over the lazy dog"'))

    def test_entropy_skips_token_already_matched(self):
        hits = self.hits('k = "%s"' % AWS_KEY)
        self.assertNotIn("high-entropy-string", hits)

    def test_clean_line(self):
        self.assertEqual(self.hits('name = "mehul jhabak"'), [])


class HelperTests(unittest.TestCase):
    def test_entropy_uniform(self):
        self.assertAlmostEqual(lc.shannon_entropy("aabb"), 1.0)

    def test_entropy_single_char(self):
        self.assertEqual(lc.shannon_entropy("aaaaaa"), 0.0)

    def test_entropy_empty(self):
        self.assertEqual(lc.shannon_entropy(""), 0.0)

    def test_redact_long(self):
        self.assertEqual(lc.redact("AKIAABCDEFGHIJ"),
                         "AKIA...(14 chars)")

    def test_redact_short(self):
        self.assertEqual(lc.redact("abc"), "(3 chars)")

    def test_char_classes(self):
        self.assertEqual(lc.char_classes("abc"), 1)
        self.assertEqual(lc.char_classes("aB1"), 3)
        self.assertEqual(lc.char_classes("aB1_"), 4)

    def test_looks_binary(self):
        self.assertTrue(lc.looks_binary(b"a\x00b"))
        self.assertFalse(lc.looks_binary(b"plain text\n"))


class FileScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def write(self, name, content, mode=None):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if mode is None:
            mode = "wb" if isinstance(content, bytes) else "w"
        with open(path, mode) as fh:
            fh.write(content)
        return path

    def test_line_numbers(self):
        path = self.write("a.py", 'x = 1\nkey = "%s"\ny = 2\n' % AWS_KEY)
        findings, status = lc.scan_file(path, 1000000)
        self.assertEqual(status, "scanned")
        self.assertEqual(findings[0][0], 2)

    def test_multiple_findings_one_line(self):
        path = self.write("a.py", 'a="%s" b="%s"' % (AWS_KEY, GH_TOKEN))
        findings, _ = lc.scan_file(path, 1000000)
        self.assertEqual(len(findings), 2)

    def test_inline_allow(self):
        path = self.write("a.py",
                          'key = "%s"  # leak-check: allow\n' % AWS_KEY)
        findings, _ = lc.scan_file(path, 1000000)
        self.assertEqual(findings, [])

    def test_binary_skipped(self):
        path = self.write("a.bin", b"\x00\x01\x02%s" % AWS_KEY.encode())
        findings, status = lc.scan_file(path, 1000000)
        self.assertEqual(findings, [])
        self.assertEqual(status, "binary")

    def test_too_large_skipped(self):
        path = self.write("big.py", 'key = "%s"\n' % AWS_KEY)
        findings, status = lc.scan_file(path, 10)
        self.assertEqual(findings, [])
        self.assertEqual(status, "too-large")

    def test_unreadable(self):
        _, status = lc.scan_file(os.path.join(self.dir, "nope.py"), 1000000)
        self.assertEqual(status, "unreadable")

    def test_non_utf8_scanned_with_replace(self):
        path = self.write("a.py",
                          ('k = "%s"\n' % AWS_KEY).encode() + b"\xff\xfe\n")
        findings, status = lc.scan_file(path, 1000000)
        self.assertEqual(status, "scanned")
        self.assertEqual(findings[0][2], "error")


class WalkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def write(self, rel, content="x = 1\n"):
        path = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        return path

    def test_walk_finds_nested(self):
        self.write("src/deep/a.py")
        files, _ = lc.collect_files([self.dir], [])
        self.assertEqual(len(files), 1)

    def test_walk_skips_dot_git(self):
        self.write(".git/hooks/x.py")
        self.write("real.py")
        files, _ = lc.collect_files([self.dir], [])
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].endswith("real.py"))

    def test_ignore_globs(self):
        self.write("keep.py")
        self.write("skip.py")
        self.write("gen/output.py")
        files, _ = lc.collect_files([self.dir],
                                    ["skip.py", "gen/*"])
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].endswith("keep.py"))

    def test_missing_path_fatal(self):
        _, fatal = lc.collect_files([os.path.join(self.dir, "nope")], [])
        self.assertIsNotNone(fatal)

    def test_ignore_file_loaded_from_cwd(self):
        self.write(lc.IGNORE_FILE, "skip.py\n# comment\n")
        globs = lc.load_ignore_globs(self.dir)
        self.assertEqual(globs, ["skip.py"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def write(self, rel, content):
        path = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        return path

    def test_clean_tree_exit_0(self):
        self.write("a.py", 'name = "mehul"\n')
        code, out, _ = run_cli([self.dir])
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_error_exit_1(self):
        self.write("a.py", 'key = "%s"\n' % AWS_KEY)
        code, out, _ = run_cli([self.dir])
        self.assertEqual(code, 1)
        self.assertIn("aws-access-key-id", out)

    def test_warning_only_exit_0(self):
        self.write("a.py", 't = "%s"\n' % JWT)
        code, out, _ = run_cli([self.dir])
        self.assertEqual(code, 0)
        self.assertIn("jwt", out)

    def test_strict_warning_exit_1(self):
        self.write("a.py", 't = "%s"\n' % JWT)
        code, _, _ = run_cli([self.dir, "--strict"])
        self.assertEqual(code, 1)

    def test_missing_path_exit_2(self):
        code, _, err = run_cli([os.path.join(self.dir, "nope")])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)

    def test_empty_dir_exit_2(self):
        code, _, err = run_cli([self.dir])
        self.assertEqual(code, 2)
        self.assertIn("nothing to scan", err)

    def test_output_format(self):
        path = self.write("sub/a.py", 'x = 1\nkey = "%s"\n' % AWS_KEY)
        _, out, _ = run_cli([self.dir])
        line = out.strip()
        self.assertRegex(line,
                         r"sub[\\/]a\.py:2: error \[aws-access-key-id\] "
                         r"AWS access key ID: AKIA\.\.\.\(20 chars\)$")

    def test_secret_redacted_in_output(self):
        self.write("a.py", 'key = "%s"\n' % AWS_KEY)
        _, out, _ = run_cli([self.dir])
        self.assertNotIn(AWS_KEY, out)

    def test_json_shape(self):
        self.write("a.py", 'key = "%s"\n' % AWS_KEY)
        code, out, _ = run_cli([self.dir, "--json"])
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["errors"], 1)
        self.assertEqual(report["warnings"], 0)
        f = report["findings"][0]
        self.assertEqual(f["rule"], "aws-access-key-id")
        self.assertEqual(f["line"], 1)

    def test_json_skipped_counts(self):
        self.write("a.bin", "")
        path = os.path.join(self.dir, "a.bin")
        with open(path, "wb") as fh:
            fh.write(b"\x00\x01")
        self.write("b.py", "x = 1\n")
        code, out, _ = run_cli([self.dir, "--json"])
        report = json.loads(out)
        self.assertEqual(report["files_skipped"]["binary"], 1)
        self.assertEqual(report["files_scanned"], 1)

    def test_ignore_file_respected(self):
        self.write(lc.IGNORE_FILE, "skip.py\n")
        self.write("skip.py", 'key = "%s"\n' % AWS_KEY)
        self.write("keep.py", "x = 1\n")
        code, out, _ = run_cli([self.dir], cwd=self.dir)
        self.assertEqual(code, 0)
        self.assertNotIn("aws-access-key-id", out)

    def test_max_bytes_flag(self):
        self.write("big.py", 'key = "%s"\n' % AWS_KEY)
        code, _, err = run_cli([self.dir, "--max-bytes", "10"])
        self.assertEqual(code, 2)
        self.assertIn("all files skipped", err)

    def test_mixed_files_and_dirs(self):
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        self.write("a.py", "x = 1\n")
        with open(os.path.join(other.name, "b.py"), "w") as fh:
            fh.write('key = "%s"\n' % AWS_KEY)
        code, out, _ = run_cli([self.dir, other.name])
        self.assertEqual(code, 1)
        self.assertIn("b.py:1", out)

    def test_generic_redacted_in_output(self):
        self.write("a.py", 'password = "sup3rsecretvalue"\n')
        _, out, _ = run_cli([self.dir])
        self.assertNotIn("sup3rsecretvalue", out)


if __name__ == "__main__":
    unittest.main()
