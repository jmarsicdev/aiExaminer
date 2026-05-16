"""Extended tests for src/core/local_parser.py — pushing past 80% coverage."""
import os
import tempfile
import unittest

from src.core.local_parser import LocalParser


class TestLocalParserListDirectory(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def _create_file(self, name, content=b'hello'):
        path = os.path.join(self.root, name)
        with open(path, 'wb') as f:
            f.write(content)
        return path

    def _create_dir(self, name):
        path = os.path.join(self.root, name)
        os.makedirs(path, exist_ok=True)
        return path

    def test_lists_file(self):
        self._create_file('test.txt', b'data')
        parser = LocalParser(self.root)
        entries = list(parser.list_directory('/'))
        names = [e['name'] for e in entries]
        self.assertIn('test.txt', names)

    def test_lists_directory(self):
        self._create_dir('subdir')
        parser = LocalParser(self.root)
        entries = list(parser.list_directory('/'))
        types = {e['name']: e['type'] for e in entries}
        self.assertEqual(types.get('subdir'), 'Folder')

    def test_file_entry_fields(self):
        self._create_file('data.bin', b'\x00' * 10)
        parser = LocalParser(self.root)
        entries = list(parser.list_directory('/'))
        entry = next(e for e in entries if e['name'] == 'data.bin')
        self.assertEqual(entry['type'], 'File')
        self.assertEqual(entry['size'], 10)
        self.assertIn('path', entry)
        self.assertIn('inode', entry)
        self.assertFalse(entry['is_deleted'])

    def test_mtime_string_or_none(self):
        self._create_file('ts.txt', b'x')
        parser = LocalParser(self.root)
        entries = list(parser.list_directory('/'))
        entry = next(e for e in entries if e['name'] == 'ts.txt')
        self.assertTrue(entry['mtime'] is None or isinstance(entry['mtime'], str))

    def test_crtime_always_none(self):
        self._create_file('cr.txt', b'y')
        parser = LocalParser(self.root)
        entries = list(parser.list_directory('/'))
        entry = next(e for e in entries if e['name'] == 'cr.txt')
        self.assertIsNone(entry['crtime'])

    def test_nonexistent_directory_returns_nothing(self):
        parser = LocalParser(self.root)
        entries = list(parser.list_directory('/no/such/path'))
        self.assertEqual(entries, [])

    def test_inode_parameter_accepted(self):
        self._create_file('x.txt', b'x')
        parser = LocalParser(self.root)
        entries = list(parser.list_directory('/', inode=99))
        self.assertIsInstance(entries, list)

    def test_nested_path(self):
        subdir = self._create_dir('level1')
        nested = os.path.join(subdir, 'nested.txt')
        with open(nested, 'w') as f:
            f.write('data')
        parser = LocalParser(self.root)
        entries = list(parser.list_directory('/level1'))
        names = [e['name'] for e in entries]
        self.assertIn('nested.txt', names)


class TestLocalParserReadFileContent(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def test_read_existing_file(self):
        path = os.path.join(self.root, 'file.txt')
        with open(path, 'wb') as f:
            f.write(b'hello world')
        parser = LocalParser(self.root)
        content = parser.read_file_content('/file.txt')
        self.assertEqual(content, b'hello world')

    def test_read_nonexistent_returns_none(self):
        parser = LocalParser(self.root)
        result = parser.read_file_content('/no_such_file.bin')
        self.assertIsNone(result)

    def test_read_binary_content(self):
        data = bytes(range(256))
        path = os.path.join(self.root, 'binary.bin')
        with open(path, 'wb') as f:
            f.write(data)
        parser = LocalParser(self.root)
        content = parser.read_file_content('/binary.bin')
        self.assertEqual(content, data)

    def test_read_empty_file(self):
        path = os.path.join(self.root, 'empty.txt')
        open(path, 'wb').close()
        parser = LocalParser(self.root)
        content = parser.read_file_content('/empty.txt')
        self.assertEqual(content, b'')


if __name__ == '__main__':
    unittest.main()
