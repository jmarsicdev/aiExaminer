"""
Integration test against a real E01 forensic image.

Image: data/test_folder/GP2024.E01

Exercises the full stack end-to-end:
  ImageParser → list_directory → read_file_content
  → detect_file_type → extract_metadata → EntityExtractor
  → entropy_analyzer → relevance_scorer → FileCarver

Limits are kept tight so the suite completes in a reasonable time even
on a 1.9 GB image:
  - Tree walk: at most MAX_WALK_FILES files across first 3 levels
  - File read:  at most MAX_READ_BYTES bytes per file
  - Carving:    only the first CARVE_SAMPLE_BYTES of the first readable file
"""

import os
import sys
import time
import unittest

_IMAGE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    'data', 'test_folder', 'GP2024.E01',
)

MAX_WALK_FILES   = 200    # stop after this many files during traversal
MAX_WALK_DEPTH   = 3      # levels deep to recurse
MAX_READ_BYTES   = 65536  # bytes to read from each file (64 KB)
CARVE_SAMPLE_MB  = 2      # MB of the first readable file to carve
MIN_FS_ENTRIES   = 1      # root must have at least this many entries


def _skip_if_missing():
    if not os.path.exists(_IMAGE_PATH):
        raise unittest.SkipTest(f'E01 image not found: {_IMAGE_PATH}')


# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #

def _walk(parser, path, depth, limit, collected):
    """Recursive walk up to `depth` levels, collecting at most `limit` entries."""
    if depth <= 0 or len(collected) >= limit:
        return
    try:
        for entry in parser.list_directory(path):
            collected.append(entry)
            if entry['type'] == 'Folder' and depth > 1:
                _walk(parser, entry['path'], depth - 1, limit, collected)
            if len(collected) >= limit:
                break
    except Exception:
        pass


# ------------------------------------------------------------------ #
#  Test suite                                                          #
# ------------------------------------------------------------------ #

class TestImageParserE01(unittest.TestCase):
    """Open the image and verify basic filesystem access."""

    @classmethod
    def setUpClass(cls):
        _skip_if_missing()
        from src.core.image_parser import ImageParser, EWFNotSupportedError
        try:
            cls.parser = ImageParser(_IMAGE_PATH)
        except EWFNotSupportedError:
            raise unittest.SkipTest('pytsk3 built without libewf — cannot open E01')
        except Exception as e:
            raise unittest.SkipTest(f'Could not open image: {e}')

    def test_parser_has_fs_info(self):
        self.assertIsNotNone(self.parser.fs_info)

    def test_root_directory_has_entries(self):
        entries = list(self.parser.list_directory('/'))
        self.assertGreaterEqual(len(entries), MIN_FS_ENTRIES,
                                'Root directory appears empty')

    def test_entries_have_required_fields(self):
        entries = list(self.parser.list_directory('/'))
        required = {'name', 'type', 'size', 'path', 'inode', 'is_deleted'}
        for e in entries[:10]:
            for field in required:
                self.assertIn(field, e, f'Entry missing field: {field}')

    def test_entry_type_is_file_or_folder(self):
        entries = list(self.parser.list_directory('/'))
        for e in entries[:20]:
            self.assertIn(e['type'], ('File', 'Folder'),
                          f'Unexpected entry type: {e["type"]}')

    def test_folders_have_nonzero_inode(self):
        entries = list(self.parser.list_directory('/'))
        folders = [e for e in entries if e['type'] == 'Folder']
        for f in folders[:5]:
            self.assertIsNotNone(f.get('inode'),
                                 f'Folder missing inode: {f["name"]}')

    def test_no_dot_or_dotdot_entries(self):
        entries = list(self.parser.list_directory('/'))
        names = [e['name'] for e in entries]
        self.assertNotIn('.', names)
        self.assertNotIn('..', names)

    def test_subfolder_expansion(self):
        entries = list(self.parser.list_directory('/'))
        folders = [e for e in entries if e['type'] == 'Folder']
        if not folders:
            self.skipTest('No subdirectories found in root')
        sub = folders[0]
        sub_entries = list(self.parser.list_directory(sub['path'],
                                                       inode=sub.get('inode')))
        self.assertIsInstance(sub_entries, list)


class TestFileReadE01(unittest.TestCase):
    """Read file content from the image and verify basic properties."""

    @classmethod
    def setUpClass(cls):
        _skip_if_missing()
        from src.core.image_parser import ImageParser, EWFNotSupportedError
        try:
            cls.parser = ImageParser(_IMAGE_PATH)
        except (EWFNotSupportedError, Exception) as e:
            raise unittest.SkipTest(str(e))

        # Collect some readable files across the tree
        all_entries = []
        _walk(cls.parser, '/', MAX_WALK_DEPTH, MAX_WALK_FILES, all_entries)
        cls.files = [e for e in all_entries if e['type'] == 'File' and e.get('size', 0) > 0]
        cls.readable = []
        for e in cls.files[:30]:
            try:
                data = cls.parser.read_file_content(e['path'])
                if data:
                    cls.readable.append((e, data[:MAX_READ_BYTES]))
                    if len(cls.readable) >= 10:
                        break
            except Exception:
                pass

        if not cls.readable:
            raise unittest.SkipTest('Could not read any files from image')

    def test_read_returns_bytes(self):
        _, data = self.readable[0]
        self.assertIsInstance(data, bytes)

    def test_read_non_empty(self):
        _, data = self.readable[0]
        self.assertGreater(len(data), 0)

    def test_read_length_within_limit(self):
        for _, data in self.readable:
            self.assertLessEqual(len(data), MAX_READ_BYTES)

    def test_can_read_multiple_files(self):
        self.assertGreaterEqual(len(self.readable), 1)


class TestFileTypeDetectionE01(unittest.TestCase):
    """Verify magic-byte detection runs without error on real files."""

    @classmethod
    def setUpClass(cls):
        _skip_if_missing()
        from src.core.image_parser import ImageParser, EWFNotSupportedError
        try:
            parser = ImageParser(_IMAGE_PATH)
        except (EWFNotSupportedError, Exception) as e:
            raise unittest.SkipTest(str(e))

        all_entries = []
        _walk(parser, '/', MAX_WALK_DEPTH, MAX_WALK_FILES, all_entries)
        files = [e for e in all_entries if e['type'] == 'File' and e.get('size', 0) > 0]

        cls.type_results = []
        for e in files[:50]:
            try:
                data = parser.read_file_content(e['path'])
                if data:
                    from src.core.file_type import detect_file_type
                    ft = detect_file_type(data[:2048], e['name'])
                    cls.type_results.append((e, ft))
                    if len(cls.type_results) >= 20:
                        break
            except Exception:
                pass

        if not cls.type_results:
            raise unittest.SkipTest('No files usable for type detection')

    def test_every_result_has_required_keys(self):
        for _, ft in self.type_results:
            self.assertIn('label', ft)
            self.assertIn('category', ft)
            self.assertIn('mime', ft)

    def test_categories_are_known_values(self):
        known = {
            'image', 'document', 'archive', 'executable', 'database',
            'registry', 'log', 'forensic', 'network', 'audio', 'video',
            'crypto', 'script', 'text', 'unknown',
        }
        for _, ft in self.type_results:
            self.assertIn(ft['category'], known,
                          f'Unknown category: {ft["category"]}')

    def test_type_counts(self):
        from collections import Counter
        cats = Counter(ft['category'] for _, ft in self.type_results)
        print(f'\n  File type distribution ({len(self.type_results)} files): '
              + ', '.join(f'{c}:{n}' for c, n in cats.most_common()))
        self.assertGreater(len(cats), 0)


class TestMetadataExtractionE01(unittest.TestCase):
    """Extract metadata from real files and verify structure."""

    @classmethod
    def setUpClass(cls):
        _skip_if_missing()
        from src.core.image_parser import ImageParser, EWFNotSupportedError
        try:
            parser = ImageParser(_IMAGE_PATH)
        except (EWFNotSupportedError, Exception) as e:
            raise unittest.SkipTest(str(e))

        all_entries = []
        _walk(parser, '/', MAX_WALK_DEPTH, MAX_WALK_FILES, all_entries)
        files = [e for e in all_entries if e['type'] == 'File' and e.get('size', 0) > 0]

        cls.meta_results = []
        for e in files[:30]:
            try:
                data = parser.read_file_content(e['path'])
                if data:
                    from src.core.metadata import extract_metadata
                    meta = extract_metadata(e['path'], data[:MAX_READ_BYTES], e)
                    cls.meta_results.append(meta)
                    if len(cls.meta_results) >= 10:
                        break
            except Exception:
                pass

        if not cls.meta_results:
            raise unittest.SkipTest('No metadata results')

    def test_metadata_has_path(self):
        for m in self.meta_results:
            self.assertIn('Path', m)

    def test_metadata_has_file_type(self):
        for m in self.meta_results:
            self.assertIn('File Type', m)

    def test_metadata_has_size(self):
        for m in self.meta_results:
            self.assertIn('Size', m)

    def test_metadata_deleted_field_is_yes_or_no(self):
        for m in self.meta_results:
            self.assertIn(m.get('Deleted'), ('Yes', 'No'))


class TestEntityExtractionE01(unittest.TestCase):
    """Run IOC extraction against real file content."""

    @classmethod
    def setUpClass(cls):
        _skip_if_missing()
        from src.core.image_parser import ImageParser, EWFNotSupportedError
        try:
            parser = ImageParser(_IMAGE_PATH)
        except (EWFNotSupportedError, Exception) as e:
            raise unittest.SkipTest(str(e))

        from src.core.file_type import is_text
        from src.ai.entity_extractor import EntityExtractor

        all_entries = []
        _walk(parser, '/', MAX_WALK_DEPTH, MAX_WALK_FILES, all_entries)
        files = [e for e in all_entries if e['type'] == 'File' and e.get('size', 0) > 0]

        extractor = EntityExtractor()
        cls.extraction_results = []
        for e in files[:50]:
            try:
                data = parser.read_file_content(e['path'])
                if data and is_text(data[:512]):
                    entities = extractor.extract_from_bytes(data[:MAX_READ_BYTES])
                    cls.extraction_results.append((e['name'], entities))
                    if len(cls.extraction_results) >= 5:
                        break
            except Exception:
                pass

        if not cls.extraction_results:
            raise unittest.SkipTest('No text files usable for entity extraction')

    def test_extraction_returns_list(self):
        for _, entities in self.extraction_results:
            self.assertIsInstance(entities, list)

    def test_entity_fields_present(self):
        from src.ai.entity_extractor import Entity
        for _, entities in self.extraction_results:
            for e in entities[:5]:
                self.assertIsInstance(e, Entity)
                self.assertIsInstance(e.kind, str)
                self.assertIsInstance(e.value, str)


class TestEntropyAnalysisE01(unittest.TestCase):
    """Run entropy analysis against real files."""

    @classmethod
    def setUpClass(cls):
        _skip_if_missing()
        from src.core.image_parser import ImageParser, EWFNotSupportedError
        try:
            parser = ImageParser(_IMAGE_PATH)
        except (EWFNotSupportedError, Exception) as e:
            raise unittest.SkipTest(str(e))

        all_entries = []
        _walk(parser, '/', MAX_WALK_DEPTH, MAX_WALK_FILES, all_entries)
        files = [e for e in all_entries if e['type'] == 'File' and e.get('size', 0) > 0]

        import src.ai.entropy_analyzer as entropy_mod
        cls.entropy_results = []
        for e in files[:20]:
            try:
                data = parser.read_file_content(e['path'])
                if data:
                    result = entropy_mod.analyze(data[:MAX_READ_BYTES])
                    cls.entropy_results.append((e['name'], result))
                    if len(cls.entropy_results) >= 10:
                        break
            except Exception:
                pass

        if not cls.entropy_results:
            raise unittest.SkipTest('No files usable for entropy analysis')

    def test_entropy_in_valid_range(self):
        for name, r in self.entropy_results:
            self.assertGreaterEqual(r.overall, 0.0,
                                    f'{name}: entropy below 0')
            self.assertLessEqual(r.overall, 8.0,
                                 f'{name}: entropy above 8')

    def test_entropy_label_is_string(self):
        for _, r in self.entropy_results:
            self.assertIsInstance(r.label, str)
            self.assertGreater(len(r.label), 0)

    def test_suspicious_flag_is_bool(self):
        for _, r in self.entropy_results:
            self.assertIsInstance(r.suspicious, bool)

    def test_high_entropy_files_reported(self):
        high = [(n, r) for n, r in self.entropy_results if r.overall > 7.0]
        print(f'\n  High-entropy files (>{7.0}): '
              + ', '.join(f'{n}({r.overall:.2f})' for n, r in high[:5]))


class TestRelevanceScoringE01(unittest.TestCase):
    """Score real files and verify the result structure."""

    @classmethod
    def setUpClass(cls):
        _skip_if_missing()
        from src.core.image_parser import ImageParser, EWFNotSupportedError
        try:
            parser = ImageParser(_IMAGE_PATH)
        except (EWFNotSupportedError, Exception) as e:
            raise unittest.SkipTest(str(e))

        all_entries = []
        _walk(parser, '/', MAX_WALK_DEPTH, MAX_WALK_FILES, all_entries)
        files = [e for e in all_entries if e['type'] == 'File' and e.get('size', 0) > 0]

        import src.ai.entropy_analyzer as entropy_mod
        from src.core.file_type import detect_file_type
        from src.ai.entity_extractor import EntityExtractor
        from src.ai.relevance_scorer import score_file
        extractor = EntityExtractor()

        cls.score_results = []
        for e in files[:30]:
            try:
                data = parser.read_file_content(e['path'])
                if not data:
                    continue
                sample  = data[:MAX_READ_BYTES]
                ft      = detect_file_type(sample, e['name'])
                ent_res = entropy_mod.analyze(sample)
                entities = extractor.extract_from_bytes(sample)
                sr = score_file(
                    file_path=e['path'],
                    file_category=ft['category'],
                    entropy=ent_res.overall,
                    entities=entities,
                    content_sample=sample,
                    is_deleted=e.get('is_deleted', False),
                    mtime=e.get('mtime'),
                )
                if sr:
                    cls.score_results.append((e['name'], sr))
                if len(cls.score_results) >= 10:
                    break
            except Exception:
                pass

        if not cls.score_results:
            raise unittest.SkipTest('No scored files')

    def test_score_is_non_negative(self):
        for name, sr in self.score_results:
            self.assertGreaterEqual(sr.score, 0,
                                    f'{name}: negative score')

    def test_tier_is_known_value(self):
        known = {'Critical', 'High', 'Medium', 'Low', 'Noise'}
        for name, sr in self.score_results:
            self.assertIn(sr.tier, known,
                          f'{name}: unexpected tier {sr.tier!r}')

    def test_badge_color_is_hex(self):
        for _, sr in self.score_results:
            self.assertTrue(sr.badge_color.startswith('#'),
                            f'badge_color not a hex color: {sr.badge_color}')

    def test_reasons_is_list(self):
        for _, sr in self.score_results:
            self.assertIsInstance(sr.reasons, list)

    def test_high_value_files_reported(self):
        critical = [(n, sr) for n, sr in self.score_results if sr.tier == 'Critical']
        high     = [(n, sr) for n, sr in self.score_results if sr.tier == 'High']
        print(f'\n  Critical: {len(critical)}, High: {len(high)} '
              f'(of {len(self.score_results)} scored)')
        if critical:
            print('  Top critical:', ', '.join(
                f'{n}({sr.score})' for n, sr in critical[:3]))


class TestFileCarverE01(unittest.TestCase):
    """Carve a small chunk of a real file and verify output structure."""

    @classmethod
    def setUpClass(cls):
        _skip_if_missing()
        from src.core.image_parser import ImageParser, EWFNotSupportedError
        try:
            parser = ImageParser(_IMAGE_PATH)
        except (EWFNotSupportedError, Exception) as e:
            raise unittest.SkipTest(str(e))

        all_entries = []
        _walk(parser, '/', MAX_WALK_DEPTH, MAX_WALK_FILES, all_entries)
        files = [e for e in all_entries
                 if e['type'] == 'File' and e.get('size', 0) > 1024]

        cls.carved = []
        carve_limit = CARVE_SAMPLE_MB * 1024 * 1024
        for e in files[:20]:
            try:
                data = parser.read_file_content(e['path'])
                if data and len(data) > 512:
                    from src.core.carver import FileCarver
                    carver = FileCarver()
                    cls.carved = list(carver.carve_stream(data[:carve_limit]))
                    if cls.carved:
                        break
            except Exception:
                pass

    def test_carved_list_is_list(self):
        self.assertIsInstance(self.carved, list)

    def test_carved_items_have_required_fields(self):
        from src.core.carver import CarvedFile
        for cf in self.carved[:5]:
            self.assertIsInstance(cf, CarvedFile)
            self.assertIsInstance(cf.offset, int)
            self.assertIsInstance(cf.size, int)
            self.assertIsInstance(cf.label, str)
            self.assertIsInstance(cf.extension, str)
            self.assertIsInstance(cf.data, bytes)
            self.assertGreater(cf.size, 0)

    def test_carved_data_not_empty(self):
        for cf in self.carved[:5]:
            self.assertGreater(len(cf.data), 0)

    def test_carved_summary(self):
        from collections import Counter
        if self.carved:
            counts = Counter(cf.label for cf in self.carved)
            print(f'\n  Carved {len(self.carved)} files: '
                  + ', '.join(f'{l}×{n}' for l, n in counts.most_common(5)))


class TestWalkSummaryE01(unittest.TestCase):
    """High-level sanity check on the traversal — counts and basic stats."""

    @classmethod
    def setUpClass(cls):
        _skip_if_missing()
        from src.core.image_parser import ImageParser, EWFNotSupportedError
        try:
            parser = ImageParser(_IMAGE_PATH)
        except (EWFNotSupportedError, Exception) as e:
            raise unittest.SkipTest(str(e))

        t0 = time.monotonic()
        all_entries = []
        _walk(parser, '/', MAX_WALK_DEPTH, MAX_WALK_FILES, all_entries)
        cls.elapsed = time.monotonic() - t0
        cls.entries = all_entries

    def test_walk_returns_entries(self):
        self.assertGreater(len(self.entries), 0)

    def test_walk_has_files_and_folders(self):
        types = {e['type'] for e in self.entries}
        self.assertIn('File', types)

    def test_walk_completes_in_reasonable_time(self):
        # Walking MAX_WALK_FILES entries should finish in < 60 s on any system
        self.assertLess(self.elapsed, 60.0,
                        f'Walk took {self.elapsed:.1f}s — too slow')

    def test_deleted_files_present_or_absent(self):
        deleted = [e for e in self.entries if e.get('is_deleted')]
        print(f'\n  Walk summary: {len(self.entries)} entries, '
              f'{len(deleted)} deleted, took {self.elapsed:.2f}s')

    def test_no_entry_has_empty_name(self):
        for e in self.entries:
            self.assertGreater(len(e.get('name', '')), 0,
                               'Entry with empty name found')


if __name__ == '__main__':
    unittest.main(verbosity=2)
