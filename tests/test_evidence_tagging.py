"""
Tests for evidence tagging — DB-level bookmark CRUD operations.
Uses a fresh in-memory SQLite database per test.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fresh_db():
    from src.db.manager import DatabaseManager
    return DatabaseManager(db_path=":memory:")


def _setup(db):
    """Create a case + evidence and return (case_id, evidence_id)."""
    case_id     = db.create_case("CASE-001", "Examiner A", "Test case")
    evidence_id = db.add_evidence(case_id, "/images/disk.E01")
    return case_id, evidence_id


class TestBookmarkCRUD(unittest.TestCase):

    def test_add_bookmark_returns_id(self):
        db = _fresh_db()
        _, ev_id = _setup(db)
        bid = db.add_bookmark(ev_id, "/files/secret.txt",
                              tag_name="Key Evidence", tag_color="#b71c1c")
        self.assertIsInstance(bid, int)
        self.assertGreater(bid, 0)

    def test_get_bookmarks_returns_list(self):
        db = _fresh_db()
        _, ev_id = _setup(db)
        db.add_bookmark(ev_id, "/files/a.txt", tag_name="Reviewed")
        db.add_bookmark(ev_id, "/files/b.txt", tag_name="Excluded")
        result = db.get_bookmarks(ev_id)
        self.assertEqual(len(result), 2)

    def test_get_bookmark_by_id(self):
        db = _fresh_db()
        _, ev_id = _setup(db)
        bid = db.add_bookmark(ev_id, "/files/x.dll", tag_name="Key Evidence",
                              tag_color="#b71c1c", notes="Suspicious binary")
        b = db.get_bookmark(bid)
        self.assertEqual(b.tag_name, "Key Evidence")
        self.assertEqual(b.notes, "Suspicious binary")
        self.assertEqual(b.file_path, "/files/x.dll")

    def test_update_bookmark(self):
        db = _fresh_db()
        _, ev_id = _setup(db)
        bid = db.add_bookmark(ev_id, "/f", tag_name="Reviewed", tag_color="#1565c0")
        db.update_bookmark(bid, tag_name="Key Evidence", tag_color="#b71c1c",
                           notes="Updated note")
        b = db.get_bookmark(bid)
        self.assertEqual(b.tag_name, "Key Evidence")
        self.assertEqual(b.notes, "Updated note")

    def test_delete_bookmark(self):
        db = _fresh_db()
        _, ev_id = _setup(db)
        bid = db.add_bookmark(ev_id, "/f", tag_name="Reviewed")
        db.delete_bookmark(bid)
        self.assertIsNone(db.get_bookmark(bid))

    def test_get_bookmarks_empty_when_none(self):
        db = _fresh_db()
        _, ev_id = _setup(db)
        self.assertEqual(db.get_bookmarks(ev_id), [])


class TestGetBookmarkForFile(unittest.TestCase):

    def test_returns_none_when_no_tag(self):
        db = _fresh_db()
        _, ev_id = _setup(db)
        result = db.get_bookmark_for_file(ev_id, "/files/clean.txt")
        self.assertIsNone(result)

    def test_returns_bookmark_when_tagged(self):
        db = _fresh_db()
        _, ev_id = _setup(db)
        db.add_bookmark(ev_id, "/files/malware.exe", tag_name="Key Evidence",
                        tag_color="#b71c1c", notes="Match found")
        b = db.get_bookmark_for_file(ev_id, "/files/malware.exe")
        self.assertIsNotNone(b)
        self.assertEqual(b.tag_name, "Key Evidence")

    def test_wrong_evidence_id_returns_none(self):
        db = _fresh_db()
        case_id = db.create_case("C2", "Examiner B")
        ev1 = db.add_evidence(case_id, "/img1.E01")
        ev2 = db.add_evidence(case_id, "/img2.E01")
        db.add_bookmark(ev1, "/files/f.txt", tag_name="Reviewed")
        result = db.get_bookmark_for_file(ev2, "/files/f.txt")
        self.assertIsNone(result)

    def test_wrong_path_returns_none(self):
        db = _fresh_db()
        _, ev_id = _setup(db)
        db.add_bookmark(ev_id, "/files/a.txt", tag_name="Reviewed")
        result = db.get_bookmark_for_file(ev_id, "/files/b.txt")
        self.assertIsNone(result)


class TestDeleteBookmarkForFile(unittest.TestCase):

    def test_delete_removes_tag(self):
        db = _fresh_db()
        _, ev_id = _setup(db)
        db.add_bookmark(ev_id, "/files/f.exe", tag_name="Key Evidence")
        db.delete_bookmark_for_file(ev_id, "/files/f.exe")
        result = db.get_bookmark_for_file(ev_id, "/files/f.exe")
        self.assertIsNone(result)

    def test_delete_nonexistent_no_crash(self):
        db = _fresh_db()
        _, ev_id = _setup(db)
        db.delete_bookmark_for_file(ev_id, "/does/not/exist.txt")

    def test_delete_only_removes_matching_file(self):
        db = _fresh_db()
        _, ev_id = _setup(db)
        db.add_bookmark(ev_id, "/files/keep.txt", tag_name="Reviewed")
        db.add_bookmark(ev_id, "/files/remove.txt", tag_name="Excluded")
        db.delete_bookmark_for_file(ev_id, "/files/remove.txt")
        self.assertIsNotNone(db.get_bookmark_for_file(ev_id, "/files/keep.txt"))
        self.assertIsNone(db.get_bookmark_for_file(ev_id, "/files/remove.txt"))


class TestBookmarkTagLabels(unittest.TestCase):
    """Verify the three standard tag names round-trip cleanly."""

    def _roundtrip(self, tag_name, tag_color):
        db = _fresh_db()
        _, ev_id = _setup(db)
        db.add_bookmark(ev_id, "/f", tag_name=tag_name, tag_color=tag_color)
        b = db.get_bookmark_for_file(ev_id, "/f")
        self.assertEqual(b.tag_name, tag_name)
        self.assertEqual(b.tag_color, tag_color)

    def test_key_evidence_label(self):
        self._roundtrip("Key Evidence", "#b71c1c")

    def test_reviewed_label(self):
        self._roundtrip("Reviewed", "#1b5e20")

    def test_excluded_label(self):
        self._roundtrip("Excluded", "#424242")


if __name__ == "__main__":
    unittest.main(verbosity=2)
