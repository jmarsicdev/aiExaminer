"""Extended YARA scanner tests — covers scan_file() and edge-case branches."""
import os
import tempfile
import unittest

_SIMPLE_RULE = 'rule TestRule { strings: $a = "EICAR" condition: $a }'


class TestYARAScannerScanFile(unittest.TestCase):

    def _scanner(self):
        from src.ai.yara_scanner import YARAScanner
        return YARAScanner()

    def test_scan_file_finds_match(self):
        sc = self._scanner()
        sc.load_rules_from_string(_SIMPLE_RULE)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'This file contains EICAR marker for testing')
            path = f.name
        try:
            results = sc.scan_file(path)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].rule_name, 'TestRule')
            self.assertEqual(results[0].file_path, path)
        finally:
            os.unlink(path)

    def test_scan_file_no_match(self):
        sc = self._scanner()
        sc.load_rules_from_string(_SIMPLE_RULE)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Nothing interesting here at all.')
            path = f.name
        try:
            results = sc.scan_file(path)
            self.assertEqual(results, [])
        finally:
            os.unlink(path)

    def test_scan_file_missing_path_returns_empty(self):
        sc = self._scanner()
        sc.load_rules_from_string(_SIMPLE_RULE)
        results = sc.scan_file('/nonexistent/path/file.bin')
        self.assertEqual(results, [])

    def test_scan_file_no_rules_returns_empty(self):
        sc = self._scanner()
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'EICAR')
            path = f.name
        try:
            results = sc.scan_file(path)
            self.assertEqual(results, [])
        finally:
            os.unlink(path)


class TestYARAScannerStringsWithoutInstances(unittest.TestCase):
    """Cover the `else: strings.append((0, s.identifier, b""))` branch.

    yara-python's match.strings can contain StringMatch objects whose
    .instances list is empty if the string was in the condition but not
    found (can happen with 'any of them' or 'filesize' conditions).
    We test the branch by mocking the match object directly.
    """

    def test_string_with_no_instances_appended_as_empty(self):
        from unittest.mock import MagicMock, patch
        from src.ai.yara_scanner import YARAScanner, YARAMatch

        sc = YARAScanner()

        # Build a fake yara match with a string that has no instances
        fake_string = MagicMock()
        fake_string.identifier = '$a'
        fake_string.instances = []   # empty → triggers the else branch

        fake_match = MagicMock()
        fake_match.rule = 'FakeRule'
        fake_match.tags = []
        fake_match.strings = [fake_string]

        fake_rules = MagicMock()
        fake_rules.match.return_value = [fake_match]
        sc._rules = fake_rules

        results = sc.scan_bytes('/fake/path', b'data')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].rule_name, 'FakeRule')
        # The string tuple should be (0, '$a', b"")
        self.assertEqual(results[0].strings, [(0, '$a', b'')])

    def test_scan_bytes_exception_returns_empty(self):
        from unittest.mock import MagicMock
        from src.ai.yara_scanner import YARAScanner

        sc = YARAScanner()
        bad_rules = MagicMock()
        bad_rules.match.side_effect = RuntimeError('yara exploded')
        sc._rules = bad_rules

        results = sc.scan_bytes('/f', b'data')
        self.assertEqual(results, [])


if __name__ == '__main__':
    unittest.main()
