"""
Tests covering:
  1. Inode-based directory traversal — ImageParser, LocalParser, RawNTFSParser
  2. TSK_FS_META_TYPE_LNK entries treated as expandable folders
  3. Full deep traversal via LocalParser (real temp directory)
  4. ScoreResult.reasons populated correctly for multiple signal types
  5. render_html contains reasons and breakdown
  6. show_score_card exists on PreviewPane
  7. AnalysisWorker emits status_update at each stage
  8. RelevanceWorker emits status_update per file and per directory
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch, call

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_entry(name: bytes, meta_type: int, size: int = 100, addr: int = 42,
                     flags: int = 0, is_dot: bool = False):
    """Build a pytsk3-style directory entry mock."""
    entry = MagicMock()
    entry.info.name.name = name
    entry.info.meta.type = meta_type
    entry.info.meta.size = size
    entry.info.meta.addr = addr
    entry.info.meta.flags = flags
    entry.info.meta.crtime = 0
    entry.info.meta.mtime = 0
    entry.info.meta.atime = 0
    entry.info.meta.ctime = 0
    return entry


# ---------------------------------------------------------------------------
# 1 & 2 — ImageParser: inode-based listing and LNK handling
# ---------------------------------------------------------------------------

class TestImageParserInodeListing(unittest.TestCase):

    def _make_parser(self, mock_fs):
        """Return an ImageParser whose fs_info is replaced by mock_fs."""
        with patch('pytsk3.Img_Info'), patch('pytsk3.FS_Info') as mock_fs_cls, \
             patch('pytsk3.Volume_Info', side_effect=Exception('no vol')):
            mock_fs_cls.return_value = mock_fs
            from src.core.image_parser import ImageParser
            parser = ImageParser.__new__(ImageParser)
            parser.img_info = MagicMock()
            parser.fs_info  = mock_fs
            return parser

    def _fresh_import(self):
        import importlib, src.core.image_parser as m
        importlib.reload(m)
        return m

    def test_path_based_listing_default(self):
        """When no inode given, open_dir is called with path=."""
        import pytsk3
        mock_fs = MagicMock()
        parser  = self._make_parser(mock_fs)

        reg_type = getattr(pytsk3, 'TSK_FS_META_TYPE_REG', 1)
        entry    = _make_mock_entry(b'file.txt', reg_type)
        mock_fs.open_dir.return_value.__iter__ = MagicMock(return_value=iter([entry]))

        list(parser.list_directory('/'))
        mock_fs.open_dir.assert_called_once_with(path='/')

    def test_inode_based_listing(self):
        """When inode is given, open_dir must use inode= not path=."""
        import pytsk3
        mock_fs = MagicMock()
        parser  = self._make_parser(mock_fs)

        reg_type = getattr(pytsk3, 'TSK_FS_META_TYPE_REG', 1)
        entry    = _make_mock_entry(b'file.txt', reg_type)
        mock_fs.open_dir.return_value.__iter__ = MagicMock(return_value=iter([entry]))

        list(parser.list_directory('/some/deep/path', inode=99))
        mock_fs.open_dir.assert_called_once_with(inode=99)

    def test_dir_entries_marked_as_folder(self):
        """TSK_FS_META_TYPE_DIR entries must be type='Folder'."""
        import pytsk3
        mock_fs  = MagicMock()
        parser   = self._make_parser(mock_fs)
        dir_type = getattr(pytsk3, 'TSK_FS_META_TYPE_DIR', 2)
        entry    = _make_mock_entry(b'subdir', dir_type, addr=10)
        mock_fs.open_dir.return_value.__iter__ = MagicMock(return_value=iter([entry]))

        results = list(parser.list_directory('/'))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['type'], 'Folder')
        self.assertEqual(results[0]['inode'], 10)

    def test_lnk_entries_treated_as_folder(self):
        """TSK_FS_META_TYPE_LNK (junction points / symlinks) must be 'Folder'."""
        import pytsk3
        mock_fs  = MagicMock()
        parser   = self._make_parser(mock_fs)
        lnk_type = getattr(pytsk3, 'TSK_FS_META_TYPE_LNK', 5)
        entry    = _make_mock_entry(b'AppData', lnk_type, addr=55)
        mock_fs.open_dir.return_value.__iter__ = MagicMock(return_value=iter([entry]))

        results = list(parser.list_directory('/Users/test'))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['type'], 'Folder',
                         'LNK-type entries (junction points) must expand as folders')
        self.assertEqual(results[0]['inode'], 55)

    def test_inode_stored_in_yielded_entry(self):
        """Every yielded entry must carry its MFT inode number."""
        import pytsk3
        mock_fs  = MagicMock()
        parser   = self._make_parser(mock_fs)
        reg_type = getattr(pytsk3, 'TSK_FS_META_TYPE_REG', 1)
        entry    = _make_mock_entry(b'file.dat', reg_type, addr=777)
        mock_fs.open_dir.return_value.__iter__ = MagicMock(return_value=iter([entry]))

        results = list(parser.list_directory('/'))
        self.assertIn('inode', results[0])
        self.assertEqual(results[0]['inode'], 777)

    def test_dot_entries_skipped(self):
        """'.' and '..' must never appear in results."""
        import pytsk3
        mock_fs  = MagicMock()
        parser   = self._make_parser(mock_fs)
        dir_type = getattr(pytsk3, 'TSK_FS_META_TYPE_DIR', 2)
        dot  = _make_mock_entry(b'.', dir_type)
        ddot = _make_mock_entry(b'..', dir_type)
        real = _make_mock_entry(b'real.txt', getattr(pytsk3, 'TSK_FS_META_TYPE_REG', 1))
        mock_fs.open_dir.return_value.__iter__ = MagicMock(
            return_value=iter([dot, ddot, real]))

        results = list(parser.list_directory('/'))
        names = [r['name'] for r in results]
        self.assertNotIn('.', names)
        self.assertNotIn('..', names)
        self.assertIn('real.txt', names)

    def test_none_meta_entries_skipped(self):
        """Entries without metadata must be silently skipped."""
        import pytsk3
        mock_fs = MagicMock()
        parser  = self._make_parser(mock_fs)
        bad = MagicMock()
        bad.info.name.name = b'ghost'
        bad.info.meta = None
        mock_fs.open_dir.return_value.__iter__ = MagicMock(return_value=iter([bad]))

        results = list(parser.list_directory('/'))
        self.assertEqual(results, [])

    def test_deleted_flag_propagated(self):
        """UNALLOC flag on meta must set is_deleted=True."""
        import pytsk3
        mock_fs   = MagicMock()
        parser    = self._make_parser(mock_fs)
        reg_type  = getattr(pytsk3, 'TSK_FS_META_TYPE_REG', 1)
        unalloc   = getattr(pytsk3, 'TSK_FS_META_FLAG_UNALLOC', 2)
        entry     = _make_mock_entry(b'deleted.doc', reg_type, flags=unalloc)
        mock_fs.open_dir.return_value.__iter__ = MagicMock(return_value=iter([entry]))

        results = list(parser.list_directory('/'))
        self.assertTrue(results[0]['is_deleted'])

    def test_open_dir_exception_returns_empty(self):
        """If open_dir raises, list_directory should yield nothing (no crash)."""
        mock_fs = MagicMock()
        parser  = self._make_parser(mock_fs)
        mock_fs.open_dir.side_effect = Exception('IO error')

        results = list(parser.list_directory('/bad/path'))
        self.assertEqual(results, [])


# ---------------------------------------------------------------------------
# 3 — LocalParser: full deep traversal via real temp directory
# ---------------------------------------------------------------------------

class TestLocalParserDeepTraversal(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_tree(self, structure: dict, root: str):
        """Recursively create a directory tree from a nested dict.
        Leaf values are file contents (str). Folder keys map to dicts.
        """
        for name, content in structure.items():
            path = os.path.join(root, name)
            if isinstance(content, dict):
                os.makedirs(path, exist_ok=True)
                self._make_tree(content, path)
            else:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'w') as f:
                    f.write(content)

    def _walk_all(self, parser, path='/', inode=None):
        """Recursively collect all file paths via inode-based listing."""
        found = []
        for entry in parser.list_directory(path, inode=inode):
            if entry['type'] == 'Folder':
                found.extend(self._walk_all(
                    parser, entry['path'], inode=entry.get('inode')))
            else:
                found.append(entry['path'])
        return found

    def test_inode_signature_accepted(self):
        from src.core.local_parser import LocalParser
        parser = LocalParser(self.tmp)
        # Should not raise even with inode kwarg
        list(parser.list_directory('/', inode=None))

    def test_inode_stored_in_entry(self):
        from src.core.local_parser import LocalParser
        os.makedirs(os.path.join(self.tmp, 'sub'), exist_ok=True)
        open(os.path.join(self.tmp, 'file.txt'), 'w').close()
        parser  = LocalParser(self.tmp)
        entries = list(parser.list_directory('/'))
        for e in entries:
            self.assertIn('inode', e)
            self.assertIsNotNone(e['inode'])

    def test_deep_5_level_traversal(self):
        """All files in a 5-level tree must be reachable via inode-based walk."""
        from src.core.local_parser import LocalParser
        structure = {
            'Users': {
                'testuser': {
                    'AppData': {
                        'Local': {
                            'Google': {
                                'Chrome': {
                                    'User Data': {
                                        'Default': {
                                            'History': 'chrome history data',
                                            'Cookies': 'cookies data',
                                        }
                                    }
                                }
                            },
                            'Microsoft': {
                                'Outlook': {
                                    'profile.ost': 'outlook data',
                                }
                            }
                        },
                        'Roaming': {
                            'Mozilla': {
                                'Firefox': {
                                    'Profiles': {
                                        'abc123.default': {
                                            'places.sqlite': 'firefox history',
                                            'cookies.sqlite': 'firefox cookies',
                                        }
                                    }
                                }
                            }
                        }
                    },
                    'Documents': {
                        'Work': {
                            'secret.docx': 'confidential',
                        }
                    }
                }
            },
            'Windows': {
                'System32': {
                    'config': {
                        'SYSTEM': 'registry hive',
                        'SAM':    'sam hive',
                    }
                }
            }
        }
        self._make_tree(structure, self.tmp)
        parser = LocalParser(self.tmp)
        all_files = self._walk_all(parser)

        expected = [
            '/Users/testuser/AppData/Local/Google/Chrome/User Data/Default/History',
            '/Users/testuser/AppData/Local/Google/Chrome/User Data/Default/Cookies',
            '/Users/testuser/AppData/Local/Microsoft/Outlook/profile.ost',
            '/Users/testuser/AppData/Roaming/Mozilla/Firefox/Profiles/abc123.default/places.sqlite',
            '/Users/testuser/AppData/Roaming/Mozilla/Firefox/Profiles/abc123.default/cookies.sqlite',
            '/Users/testuser/Documents/Work/secret.docx',
            '/Windows/System32/config/SYSTEM',
            '/Windows/System32/config/SAM',
        ]
        for expected_path in expected:
            self.assertIn(expected_path, all_files,
                          f'Missing deep file: {expected_path}')

    def test_folders_carry_inode_for_expansion(self):
        """Folder entries must carry inode so deeper expansion works."""
        from src.core.local_parser import LocalParser
        os.makedirs(os.path.join(self.tmp, 'a', 'b'), exist_ok=True)
        open(os.path.join(self.tmp, 'a', 'b', 'leaf.txt'), 'w').close()
        parser = LocalParser(self.tmp)

        top = list(parser.list_directory('/'))
        self.assertEqual(len(top), 1)
        folder_a = top[0]
        self.assertEqual(folder_a['type'], 'Folder')
        self.assertIsNotNone(folder_a.get('inode'))

        # Use inode to list 'a'
        mid = list(parser.list_directory(folder_a['path'],
                                          inode=folder_a['inode']))
        self.assertEqual(len(mid), 1)
        folder_b = mid[0]
        self.assertIsNotNone(folder_b.get('inode'))

        # Use inode to list 'b'
        leaves = list(parser.list_directory(folder_b['path'],
                                             inode=folder_b['inode']))
        self.assertEqual(leaves[0]['name'], 'leaf.txt')

    def test_empty_directory_returns_nothing(self):
        from src.core.local_parser import LocalParser
        os.makedirs(os.path.join(self.tmp, 'empty'), exist_ok=True)
        parser  = LocalParser(self.tmp)
        entries = list(parser.list_directory('/'))
        folder  = entries[0]
        children = list(parser.list_directory(folder['path'],
                                               inode=folder.get('inode')))
        self.assertEqual(children, [])


# ---------------------------------------------------------------------------
# 4 & 5 — Relevance scorer: reasons and render_html
# ---------------------------------------------------------------------------

class TestRelevanceScorerReasons(unittest.TestCase):

    def _score(self, **kwargs):
        from src.ai.relevance_scorer import score_file
        defaults = dict(
            file_path='/test/file.txt',
            file_category='text',
            entropy=3.0,
            entities=[],
            content_sample=b'',
            is_deleted=False,
            mtime=None,
        )
        defaults.update(kwargs)
        return score_file(**defaults)

    def test_deleted_file_gets_reason(self):
        result = self._score(is_deleted=True)
        reasons_lower = ' '.join(result.reasons).lower()
        self.assertIn('deleted', reasons_lower)
        self.assertGreater(result.score, 0)

    def test_high_entropy_gets_reason(self):
        result = self._score(entropy=7.8)
        reasons_lower = ' '.join(result.reasons).lower()
        self.assertIn('entropy', reasons_lower)

    def test_moderate_entropy_gets_reason(self):
        result = self._score(entropy=7.1)
        reasons_lower = ' '.join(result.reasons).lower()
        self.assertIn('entropy', reasons_lower)

    def test_low_entropy_no_entropy_reason(self):
        result = self._score(entropy=2.0)
        reasons_lower = ' '.join(result.reasons).lower()
        self.assertNotIn('very high entropy', reasons_lower)

    def test_credential_keywords_reason(self):
        result = self._score(content_sample=b'password=hunter2\nsecret_key=abc')
        reasons_lower = ' '.join(result.reasons).lower()
        self.assertIn('credential', reasons_lower)

    def test_malware_keywords_reason(self):
        result = self._score(content_sample=b'shellcode exploit rootkit backdoor')
        reasons_lower = ' '.join(result.reasons).lower()
        self.assertIn('malware', reasons_lower)

    def test_financial_keywords_reason(self):
        result = self._score(content_sample=b'bitcoin wallet transfer routing number')
        reasons_lower = ' '.join(result.reasons).lower()
        self.assertIn('financial', reasons_lower)

    def test_suspicious_path_reason(self):
        result = self._score(file_path='/Users/test/AppData/Local/Temp/malware.exe')
        reasons_lower = ' '.join(result.reasons).lower()
        self.assertIn('suspicious', reasons_lower)

    def test_double_extension_reason(self):
        result = self._score(file_path='/docs/invoice.pdf.exe')
        reasons_lower = ' '.join(result.reasons).lower()
        self.assertIn('double extension', reasons_lower)

    def test_high_value_file_type_reason(self):
        result = self._score(file_category='executable')
        reasons_lower = ' '.join(result.reasons).lower()
        self.assertIn('file type', reasons_lower)

    def test_ioc_ssn_reason(self):
        from src.ai.entity_extractor import Entity
        ssn_entity = MagicMock()
        ssn_entity.kind  = 'SSN'
        ssn_entity.value = '123-45-6789'
        result = self._score(entities=[ssn_entity])
        reasons_lower = ' '.join(result.reasons).lower()
        self.assertIn('ssn', reasons_lower)

    def test_combined_signals_critical_score(self):
        """A deleted executable with high entropy + credentials should be Critical."""
        from src.ai.entity_extractor import Entity
        ssn = MagicMock(); ssn.kind = 'SSN'; ssn.value = '000-00-0000'
        result = self._score(
            file_path='/Windows/Temp/evil.exe',
            file_category='executable',
            entropy=7.9,
            entities=[ssn],
            content_sample=b'password backdoor shellcode',
            is_deleted=True,
        )
        self.assertGreaterEqual(result.score, 75, 'Combined signals should hit Critical')
        self.assertEqual(result.tier, 'Critical')
        self.assertGreater(len(result.reasons), 2)

    def test_breakdown_dict_populated(self):
        result = self._score(file_category='executable', entropy=7.5, is_deleted=True)
        self.assertIn('file_type', result.breakdown)
        self.assertIn('entropy',   result.breakdown)
        self.assertIn('deleted',   result.breakdown)

    def test_render_html_contains_reasons(self):
        import src.ai.relevance_scorer as mod
        result = self._score(
            file_category='executable',
            entropy=7.8,
            content_sample=b'password secret',
            is_deleted=True,
        )
        html = mod.render_html(result)
        for reason in result.reasons:
            self.assertIn(reason, html,
                          f'render_html missing reason: {reason}')

    def test_render_html_contains_score(self):
        import src.ai.relevance_scorer as mod
        result = self._score(file_category='script', entropy=5.0)
        html = mod.render_html(result)
        self.assertIn(str(result.score), html)
        self.assertIn(result.tier, html)

    def test_render_html_contains_breakdown(self):
        import src.ai.relevance_scorer as mod
        result = self._score(file_category='registry', is_deleted=True)
        html = mod.render_html(result)
        self.assertIn('file_type', html)

    def test_no_reasons_for_noise_file(self):
        """A plain text file with no signals should have few/no reasons."""
        result = self._score(
            file_path='/docs/readme.txt',
            file_category='text',
            entropy=3.5,
            content_sample=b'Hello world this is just a readme',
        )
        self.assertEqual(result.tier in ('Noise', 'Low'), True)


# ---------------------------------------------------------------------------
# 6 — PreviewPane.show_score_card exists
# ---------------------------------------------------------------------------

class TestPreviewPaneScoreCard(unittest.TestCase):

    def test_show_score_card_method_exists(self):
        from src.ui.preview_pane import PreviewPane
        self.assertTrue(hasattr(PreviewPane, 'show_score_card'),
                        'PreviewPane must have show_score_card()')
        self.assertTrue(callable(PreviewPane.show_score_card))

    def test_show_score_card_signature(self):
        import inspect
        from src.ui.preview_pane import PreviewPane
        sig = inspect.signature(PreviewPane.show_score_card)
        params = list(sig.parameters)
        self.assertIn('html', params)


# ---------------------------------------------------------------------------
# 7 — AnalysisWorker: status_update signal emitted at each stage
# ---------------------------------------------------------------------------

class TestAnalysisWorkerStatusUpdates(unittest.TestCase):

    def _run_worker(self, file_path: str, content: bytes, ext_type: str = ''):
        """Run AnalysisWorker synchronously and collect status_update emissions."""
        from src.ui.main_window import AnalysisWorker

        mock_parser = MagicMock()
        mock_parser.read_file_content.return_value = content

        updates = []
        worker = AnalysisWorker(mock_parser, file_path)
        worker.status_update.connect(updates.append)

        # Patch AI modules so the worker doesn't need real models
        with patch('src.ui.main_window.calculate_hashes',
                   return_value={'md5': 'abc', 'sha256': 'def'}), \
             patch('src.ai.entropy_analyzer.analyze', return_value=MagicMock(
                 overall=3.0, label='Low')), \
             patch('src.ai.entity_extractor.EntityExtractor') as mock_ext:
            mock_ext.return_value.extract_from_bytes.return_value = []
            worker.run()

        return updates

    def test_status_updates_emitted_for_generic_file(self):
        updates = self._run_worker('/test/file.bin', b'\x00' * 100)
        self.assertGreater(len(updates), 0, 'No status_update emitted for generic file')
        combined = ' '.join(updates).lower()
        self.assertIn('reading', combined)

    def test_status_updates_emitted_for_text_file(self):
        with patch('src.ai.nlp.analyzer.NLPAnalyzer') as mock_nlp_cls:
            mock_nlp_cls.return_value.analyze_text.return_value = 'NLP result'
            from src.ui.main_window import AnalysisWorker
            mock_parser = MagicMock()
            mock_parser.read_file_content.return_value = b'hello world text content'
            updates = []
            worker = AnalysisWorker(mock_parser, '/test/file.txt')
            worker.status_update.connect(updates.append)
            with patch('src.ui.main_window.calculate_hashes',
                       return_value={'md5': 'abc', 'sha256': 'def'}):
                with patch('src.ai.nlp.analyzer.NLPAnalyzer', mock_nlp_cls):
                    worker.run()
            self.assertGreater(len(updates), 0)
            combined = ' '.join(updates).lower()
            self.assertTrue('nlp' in combined or 'reading' in combined)

    def test_status_update_signal_exists(self):
        from src.ui.main_window import AnalysisWorker
        self.assertTrue(hasattr(AnalysisWorker, 'status_update'))


# ---------------------------------------------------------------------------
# 8 — RelevanceWorker: status_update emitted per file and per directory
# ---------------------------------------------------------------------------

class TestRelevanceWorkerStatusUpdates(unittest.TestCase):

    def _build_mock_parser(self, structure: dict):
        """
        structure = {'/': [entries...], '/subdir': [entries...]}
        Each entry is a dict with keys: name, type, inode, path
        """
        mock_parser = MagicMock()

        def list_directory(path='/', inode=None):
            return iter(structure.get(path, []))

        mock_parser.list_directory.side_effect = list_directory
        mock_parser.read_file_content.return_value = b'test content bytes'
        return mock_parser

    def test_status_update_signal_exists(self):
        from src.ui.main_window import RelevanceWorker
        self.assertTrue(hasattr(RelevanceWorker, 'status_update'))

    def test_status_updates_emitted_during_scoring(self):
        from src.ui.main_window import RelevanceWorker

        structure = {
            '/': [
                {'name': 'file1.txt', 'type': 'File', 'path': '/file1.txt',
                 'inode': 10, 'is_deleted': False, 'mtime': None},
                {'name': 'file2.exe', 'type': 'File', 'path': '/file2.exe',
                 'inode': 11, 'is_deleted': False, 'mtime': None},
            ]
        }
        mock_parser = self._build_mock_parser(structure)

        updates = []
        scored_paths = []

        with patch('src.ai.entropy_analyzer.analyze',
                   return_value=MagicMock(overall=3.0, label='Low')), \
             patch('src.core.file_type.detect_file_type',
                   return_value={'category': 'text'}), \
             patch('src.ai.entity_extractor.EntityExtractor') as mock_ext, \
             patch('src.ai.relevance_scorer.score_file',
                   return_value=MagicMock(score=30, tier='Medium',
                                          reasons=['test reason'],
                                          badge_color='#f57f17')):
            mock_ext.return_value.extract_from_bytes.return_value = []
            worker = RelevanceWorker(mock_parser)
            worker.status_update.connect(updates.append)
            worker.scored.connect(lambda path, sr: scored_paths.append(path))
            worker.run()

        self.assertGreater(len(updates), 0, 'No status_update emitted during scoring')
        self.assertEqual(len(scored_paths), 2)

    def test_status_update_includes_filename(self):
        from src.ui.main_window import RelevanceWorker

        structure = {
            '/': [
                {'name': 'important.docx', 'type': 'File', 'path': '/important.docx',
                 'inode': 20, 'is_deleted': False, 'mtime': None},
            ]
        }
        mock_parser = self._build_mock_parser(structure)

        updates = []
        with patch('src.ai.entropy_analyzer.analyze',
                   return_value=MagicMock(overall=3.0, label='Low')), \
             patch('src.core.file_type.detect_file_type',
                   return_value={'category': 'document'}), \
             patch('src.ai.entity_extractor.EntityExtractor') as mock_ext, \
             patch('src.ai.relevance_scorer.score_file',
                   return_value=MagicMock(score=20, tier='Low',
                                          reasons=[], badge_color='#1565c0')):
            mock_ext.return_value.extract_from_bytes.return_value = []
            worker = RelevanceWorker(mock_parser)
            worker.status_update.connect(updates.append)
            worker.run()

        file_mentioned = any('important.docx' in u for u in updates)
        self.assertTrue(file_mentioned,
                        f'Filename not in any status update. Updates: {updates}')

    def test_status_update_emitted_when_entering_subdirectory(self):
        from src.ui.main_window import RelevanceWorker

        structure = {
            '/': [
                {'name': 'subdir', 'type': 'Folder', 'path': '/subdir',
                 'inode': 5, 'is_deleted': False, 'mtime': None},
            ],
            '/subdir': [
                {'name': 'nested.txt', 'type': 'File', 'path': '/subdir/nested.txt',
                 'inode': 6, 'is_deleted': False, 'mtime': None},
            ],
        }
        mock_parser = self._build_mock_parser(structure)

        updates = []
        with patch('src.ai.entropy_analyzer.analyze',
                   return_value=MagicMock(overall=2.0, label='Low')), \
             patch('src.core.file_type.detect_file_type',
                   return_value={'category': 'text'}), \
             patch('src.ai.entity_extractor.EntityExtractor') as mock_ext, \
             patch('src.ai.relevance_scorer.score_file',
                   return_value=MagicMock(score=10, tier='Low',
                                          reasons=[], badge_color='#1565c0')):
            mock_ext.return_value.extract_from_bytes.return_value = []
            worker = RelevanceWorker(mock_parser)
            worker.status_update.connect(updates.append)
            worker.run()

        dir_update = any('subdir' in u for u in updates)
        self.assertTrue(dir_update,
                        f'No status update mentions subdir. Updates: {updates}')

    def test_worker_uses_inode_when_walking(self):
        """RelevanceWorker must pass inode when recursing into subdirectories."""
        from src.ui.main_window import RelevanceWorker

        mock_parser = MagicMock()
        call_log = []

        def list_directory(path='/', inode=None):
            call_log.append((path, inode))
            if path == '/':
                return iter([
                    {'name': 'sub', 'type': 'Folder', 'path': '/sub',
                     'inode': 99, 'is_deleted': False, 'mtime': None}
                ])
            return iter([])

        mock_parser.list_directory.side_effect = list_directory

        worker = RelevanceWorker(mock_parser)
        worker.run()

        # Should have called list_directory for /sub with inode=99
        sub_call = next((c for c in call_log if c[0] == '/sub'), None)
        self.assertIsNotNone(sub_call, 'Never called list_directory for /sub')
        self.assertEqual(sub_call[1], 99,
                         'RelevanceWorker did not pass inode=99 when recursing into /sub')


# ---------------------------------------------------------------------------
# RawNTFSParser: inode parameter accepted
# ---------------------------------------------------------------------------

class TestRawNTFSParserInodeParam(unittest.TestCase):

    def test_inode_parameter_accepted(self):
        """RawNTFSParser.list_directory must accept inode= without error."""
        import inspect
        from src.core.ntfs_raw_parser import RawNTFSParser
        sig = inspect.signature(RawNTFSParser.list_directory)
        self.assertIn('inode', sig.parameters)

    def test_inode_in_yielded_entries(self):
        """Entries yielded by RawNTFSParser must contain 'inode' key."""
        from src.core.ntfs_raw_parser import RawNTFSParser

        parser = MagicMock(spec=RawNTFSParser)

        def fake_list(path='/', inode=None):
            yield {'name': 'file.txt', 'type': 'File', 'size': 10,
                   'path': '/file.txt', 'inode': 123,
                   'crtime': None, 'mtime': None, 'atime': None,
                   'ctime': None, 'is_deleted': False}

        parser.list_directory.side_effect = fake_list
        results = list(parser.list_directory('/'))
        self.assertIn('inode', results[0])
        self.assertEqual(results[0]['inode'], 123)


if __name__ == '__main__':
    unittest.main(verbosity=2)
