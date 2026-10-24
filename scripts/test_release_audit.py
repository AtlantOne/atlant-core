from pathlib import Path
import tempfile
import unittest

from release_audit import inspect_file


class ReleaseAuditTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def check(self, name, text):
        (self.root / name).write_text(text, encoding='utf-8')
        return inspect_file(self.root, name)

    def test_secret_locations_are_reported_without_values(self):
        secret = 'this-is-a-fixture-not-a-real-password'
        findings = self.check('config.json', '{"api_secret":"' + secret + '"}')
        self.assertTrue(findings)
        self.assertNotIn(secret, repr(findings))

    def test_placeholders_are_allowed(self):
        self.assertEqual(self.check('config.example.json', '{"api_secret":"YOUR_API_SECRET"}'), [])

    def test_ui_label_is_not_a_password_assignment(self):
        self.assertEqual(self.check('panel.py', 'tk.Label(frame, text="Password:").grid(sticky="e")'), [])

    def test_database_and_private_names_are_blocked(self):
        for name in ('users.json', 'accounts.db', 'accounts.db-wal', 'native.exe'):
            self.assertTrue(self.check(name, 'fixture'))

    def test_known_test_fixture_exception_is_explicit(self):
        self.assertEqual(self.check('parser_test.go', 'pbk = "known-test-key"'), [])

    def test_changed_upstream_example_key_is_not_exempt(self):
        p=self.root/'third_party/utls/testdata/example-key.pem';p.parent.mkdir(parents=True)
        p.write_text('-----BEGIN PRIVATE KEY-----\nnot-the-public-fixture')
        self.assertTrue(inspect_file(self.root,'third_party/utls/testdata/example-key.pem'))

    def test_changed_quic_fixture_keys_are_not_exempt(self):
        for name in ('third_party/quic-go/internal/testdata/priv.key',
                     'third_party/quic-go/http3/internal/testdata/priv.key'):
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('-----BEGIN PRIVATE KEY-----\nnot-the-public-fixture')
            self.assertTrue(inspect_file(self.root, name))


if __name__ == '__main__':
    unittest.main()
