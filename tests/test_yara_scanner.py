"""
Tests for YARAScanner — forensic YARA rule matching.
Uses real yara-python with small inline rule strings; no .yar files needed for most tests.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_SIMPLE_RULE = 'rule TestRule { strings: $a = "EICAR" condition: $a }'
_TWO_RULES   = (
    'rule RuleA { strings: $a = "EICAR" condition: $a } '
    'rule RuleB { strings: $b = "VIRUS" condition: $b }'
)


class TestYARAScannerInterface(unittest.TestCase):

    def _scanner(self):
        from src.ai.yara_scanner import YARAScanner
        return YARAScanner()

    def test_rules_not_loaded_initially(self):
        sc = self._scanner()
        self.assertFalse(sc.rules_loaded)

    def test_rules_loaded_after_load(self):
        sc = self._scanner()
        sc.load_rules_from_string(_SIMPLE_RULE)
        self.assertTrue(sc.rules_loaded)

    def test_scan_without_rules_returns_empty(self):
        sc = self._scanner()
        result = sc.scan_bytes("/path/to/file", b"EICAR data")
        self.assertEqual(result, [])

    def test_scan_matching_data_returns_matches(self):
        sc = self._scanner()
        sc.load_rules_from_string(_SIMPLE_RULE)
        result = sc.scan_bytes("/f", b"This contains EICAR string")
        self.assertGreater(len(result), 0)

    def test_scan_non_matching_data_returns_empty(self):
        sc = self._scanner()
        sc.load_rules_from_string(_SIMPLE_RULE)
        result = sc.scan_bytes("/f", b"Nothing matching here")
        self.assertEqual(result, [])

    def test_match_has_correct_rule_name(self):
        sc = self._scanner()
        sc.load_rules_from_string(_SIMPLE_RULE)
        result = sc.scan_bytes("/f", b"EICAR")
        self.assertEqual(result[0].rule_name, "TestRule")

    def test_match_file_path_preserved(self):
        sc = self._scanner()
        sc.load_rules_from_string(_SIMPLE_RULE)
        result = sc.scan_bytes("/evidence/malware.exe", b"EICAR")
        self.assertEqual(result[0].file_path, "/evidence/malware.exe")

    def test_corrupt_data_no_crash(self):
        sc = self._scanner()
        sc.load_rules_from_string(_SIMPLE_RULE)
        result = sc.scan_bytes("/f", b"")
        self.assertIsInstance(result, list)

    def test_returns_list(self):
        sc = self._scanner()
        sc.load_rules_from_string(_SIMPLE_RULE)
        result = sc.scan_bytes("/f", b"no match")
        self.assertIsInstance(result, list)


class TestYARAScannerMatchStructure(unittest.TestCase):

    def _scanner_with_match(self):
        from src.ai.yara_scanner import YARAScanner
        sc = YARAScanner()
        sc.load_rules_from_string(_SIMPLE_RULE)
        matches = sc.scan_bytes("/f", b"EICAR")
        return matches[0]

    def test_match_is_yaramatch_dataclass(self):
        from src.ai.yara_scanner import YARAMatch
        m = self._scanner_with_match()
        self.assertIsInstance(m, YARAMatch)

    def test_match_tags_is_list(self):
        m = self._scanner_with_match()
        self.assertIsInstance(m.tags, list)

    def test_match_strings_is_list(self):
        m = self._scanner_with_match()
        self.assertIsInstance(m.strings, list)

    def test_multiple_rules_multiple_matches(self):
        from src.ai.yara_scanner import YARAScanner
        sc = YARAScanner()
        sc.load_rules_from_string(_TWO_RULES)
        matches = sc.scan_bytes("/f", b"EICAR and VIRUS are both here")
        rule_names = {m.rule_name for m in matches}
        self.assertIn("RuleA", rule_names)
        self.assertIn("RuleB", rule_names)


class TestYARAScannerLoadRulesFromFile(unittest.TestCase):

    def test_load_from_file(self):
        from src.ai.yara_scanner import YARAScanner
        sc = YARAScanner()
        with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False) as f:
            f.write(_SIMPLE_RULE)
            path = f.name
        try:
            sc.load_rules(path)
            self.assertTrue(sc.rules_loaded)
            matches = sc.scan_bytes("/f", b"EICAR")
            self.assertEqual(len(matches), 1)
        finally:
            os.unlink(path)

    def test_invalid_rule_syntax_raises(self):
        from src.ai.yara_scanner import YARAScanner
        sc = YARAScanner()
        with self.assertRaises(Exception):
            sc.load_rules_from_string("invalid syntax {{{")

    def test_load_rules_twice_replaces_not_accumulates(self):
        """Loading a second ruleset must replace the first — not union them."""
        from src.ai.yara_scanner import YARAScanner
        _VIRUS_ONLY = 'rule VirusOnly { strings: $a = "VIRUS" condition: $a }'
        sc = YARAScanner()
        # Load EICAR rule first
        sc.load_rules_from_string(_SIMPLE_RULE)
        self.assertTrue(sc.rules_loaded)
        # Overwrite with VIRUS-only rule
        sc.load_rules_from_string(_VIRUS_ONLY)
        # EICAR must no longer match (first ruleset replaced)
        eicar_matches = sc.scan_bytes("/f", b"EICAR")
        self.assertEqual(eicar_matches, [],
                         "First ruleset should be replaced, not accumulated")
        # VIRUS must match (second ruleset active)
        virus_matches = sc.scan_bytes("/f", b"VIRUS")
        self.assertEqual(len(virus_matches), 1)
        self.assertEqual(virus_matches[0].rule_name, "VirusOnly")


if __name__ == "__main__":
    unittest.main(verbosity=2)
