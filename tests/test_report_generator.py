"""Tests for src/utils/report.py — HTML forensic report generation."""
import os
import tempfile
import unittest

from src.db.manager import DatabaseManager
from src.utils import report as report_mod


def _make_db():
    """Create an in-memory-style temp-file DB with a case and evidence."""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    db = DatabaseManager(path)
    return db, path


class TestReportGenerate(unittest.TestCase):

    def setUp(self):
        self.db, self.db_path = _make_db()
        self.case_id = self.db.create_case('CASE-001', 'Examiner A', 'Test case')
        self.ev_id = self.db.add_evidence(self.case_id, '/evidence/disk.dd')
        self.out_fd, self.out_path = tempfile.mkstemp(suffix='.html')
        os.close(self.out_fd)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
        if os.path.exists(self.out_path):
            os.unlink(self.out_path)

    def test_generate_creates_file(self):
        report_mod.generate(self.db, self.case_id, self.out_path)
        self.assertTrue(os.path.exists(self.out_path))
        self.assertGreater(os.path.getsize(self.out_path), 0)

    def test_generated_file_is_html(self):
        report_mod.generate(self.db, self.case_id, self.out_path)
        with open(self.out_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('<!DOCTYPE html>', content)

    def test_report_contains_case_number(self):
        report_mod.generate(self.db, self.case_id, self.out_path)
        with open(self.out_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('CASE-001', content)

    def test_report_contains_examiner(self):
        report_mod.generate(self.db, self.case_id, self.out_path)
        with open(self.out_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('Examiner A', content)

    def test_report_contains_evidence_path(self):
        report_mod.generate(self.db, self.case_id, self.out_path)
        with open(self.out_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('disk.dd', content)

    def test_report_without_artifacts(self):
        report_mod.generate(self.db, self.case_id, self.out_path,
                            include_artifacts=False)
        with open(self.out_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('<!DOCTYPE html>', content)

    def test_report_without_bookmarks(self):
        report_mod.generate(self.db, self.case_id, self.out_path,
                            include_bookmarks=False)
        with open(self.out_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('<!DOCTYPE html>', content)

    def test_report_without_iocs(self):
        report_mod.generate(self.db, self.case_id, self.out_path,
                            include_iocs=False)
        with open(self.out_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('<!DOCTYPE html>', content)

    def test_missing_case_raises(self):
        with self.assertRaises(Exception):
            report_mod.generate(self.db, 99999, self.out_path)

    def test_report_with_bookmark(self):
        self.db.add_bookmark(self.ev_id, '/evidence/disk.dd/secret.txt',
                             tag_name='Key Evidence', tag_color='#b71c1c', notes='Important')
        report_mod.generate(self.db, self.case_id, self.out_path)
        with open(self.out_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('Key Evidence', content)

    def test_report_with_artifact(self):
        self.db.add_artifact(self.ev_id, '/evidence/disk.dd/malware.exe',
                             'abc123', 'def456', 'NLP', 'found malware')
        report_mod.generate(self.db, self.case_id, self.out_path)
        with open(self.out_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('malware.exe', content)

    def test_report_stat_boxes_present(self):
        report_mod.generate(self.db, self.case_id, self.out_path)
        with open(self.out_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('Evidence Items', content)

    def test_case_description_included(self):
        report_mod.generate(self.db, self.case_id, self.out_path)
        with open(self.out_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('Test case', content)


class TestSectionRenderers(unittest.TestCase):
    """Unit-test the private section renderers with mock objects."""

    def _make_mock_evidence(self, path='/e/disk.dd', added='2024-01-01'):
        import types
        return types.SimpleNamespace(image_path=path, added_at=added, id=1)

    def _make_mock_artifact(self, fp='/e/file.txt', atype='NLP',
                             md5_val='abc', sha256_val='def'):
        import types
        return types.SimpleNamespace(
            file_path=fp, analysis_type=atype,
            md5=md5_val, sha256=sha256_val,
            analyzed_at='2024-01-01', results=None,
        )

    def _make_mock_bookmark(self, path='/e/key.txt', tag='Key Evidence',
                             color='#b71c1c', note='Note'):
        import types
        return types.SimpleNamespace(
            file_path=path, tag_name=tag,
            tag_color=color, notes=note,
            created_at='2024-01-01',
        )

    def test_render_evidence_empty_returns_empty_string(self):
        result = report_mod._render_evidence([])
        self.assertEqual(result, '')

    def test_render_evidence_with_items(self):
        result = report_mod._render_evidence([self._make_mock_evidence()])
        self.assertIn('disk.dd', result)
        self.assertIn('<table', result)

    def test_render_artifacts_empty_returns_empty_string(self):
        result = report_mod._render_artifacts([])
        self.assertEqual(result, '')

    def test_render_artifacts_with_items(self):
        result = report_mod._render_artifacts([self._make_mock_artifact()])
        self.assertIn('file.txt', result)

    def test_render_bookmarks_empty_returns_empty_string(self):
        result = report_mod._render_bookmarks([])
        self.assertEqual(result, '')

    def test_render_bookmarks_with_items(self):
        result = report_mod._render_bookmarks([self._make_mock_bookmark()])
        self.assertIn('Key Evidence', result)

    def test_render_iocs_empty_returns_empty_string(self):
        result = report_mod._render_iocs({})
        self.assertEqual(result, '')

    def test_render_iocs_with_data(self):
        iocs = {'Email': ['alice@evil.com'], 'IPv4': ['10.0.0.1']}
        result = report_mod._render_iocs(iocs)
        self.assertIn('alice@evil.com', result)
        self.assertIn('10.0.0.1', result)

    def test_aggregate_iocs_empty_artifacts(self):
        result = report_mod._aggregate_iocs([])
        self.assertEqual(result, {})

    def test_aggregate_iocs_skips_none_results(self):
        a = self._make_mock_artifact()  # results=None by default
        result = report_mod._aggregate_iocs([a])
        self.assertEqual(result, {})

    def test_aggregate_iocs_parses_json(self):
        import json
        import types
        a = types.SimpleNamespace(
            file_path='/e/f.txt', analysis_type='NLP',
            md5='abc', sha256='def', analyzed_at='2024-01-01',
            results=json.dumps({
                'entities': [
                    {'kind': 'Email', 'value': 'x@y.com'},
                    {'kind': 'IPv4', 'value': '1.2.3.4'},
                ]
            }),
        )
        result = report_mod._aggregate_iocs([a])
        self.assertIn('Email', result)
        self.assertIn('x@y.com', result['Email'])

    def test_aggregate_iocs_skips_bad_json(self):
        import types
        a = types.SimpleNamespace(
            file_path='/e/f.txt', analysis_type='NLP',
            md5='abc', sha256='def', analyzed_at='2024-01-01',
            results='NOT_JSON{',
        )
        result = report_mod._aggregate_iocs([a])
        self.assertEqual(result, {})


if __name__ == '__main__':
    unittest.main()
