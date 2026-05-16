"""Tests for src/ui/timeline.py — TimelineDialog."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import sys
import unittest
from datetime import datetime

# Ensure project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# --- QApplication must exist before importing any Qt widget ----------------
from PyQt6.QtWidgets import QApplication
_app = QApplication.instance() or QApplication(sys.argv)
# ---------------------------------------------------------------------------

from src.ui.timeline import TimelineDialog


def _entry(path, mtime, is_deleted=False, typ="File"):
    return {
        "path": path,
        "name": path.split("/")[-1],
        "type": typ,
        "mtime": mtime,
        "is_deleted": is_deleted,
    }


class TestTimelineDialogDataProcessing(unittest.TestCase):
    """Tests for _parse_dt and entry filtering — no display needed."""

    def setUp(self):
        # Create a minimal dialog instance without entries so we can
        # call helper methods without triggering the plot code.
        self._dlg = TimelineDialog.__new__(TimelineDialog)

    def test_parse_dt_standard_format(self):
        result = self._dlg._parse_dt("2023-04-15 10:23:11")
        self.assertIsInstance(result, datetime)
        self.assertEqual(result, datetime(2023, 4, 15, 10, 23, 11))

    def test_parse_dt_iso_format(self):
        result = self._dlg._parse_dt("2023-04-15T10:23:11")
        self.assertIsInstance(result, datetime)
        self.assertEqual(result, datetime(2023, 4, 15, 10, 23, 11))

    def test_parse_dt_date_only(self):
        result = self._dlg._parse_dt("2023-04-15")
        self.assertIsInstance(result, datetime)
        self.assertEqual(result, datetime(2023, 4, 15, 0, 0, 0))

    def test_parse_dt_invalid_returns_none(self):
        result = self._dlg._parse_dt("not a date")
        self.assertIsNone(result)

    def test_folders_excluded(self):
        entries = [
            _entry("/files/doc.txt", "2023-04-15 10:00:00"),
            _entry("/files/folder", "2023-04-15 11:00:00", typ="Folder"),
        ]
        dlg = TimelineDialog(entries)
        self.assertEqual(len(dlg._entries), 1)
        self.assertEqual(dlg._entries[0]["path"], "/files/doc.txt")

    def test_null_mtime_excluded(self):
        entries = [
            _entry("/files/doc.txt", "2023-04-15 10:00:00"),
            _entry("/files/no_time.txt", None),
        ]
        dlg = TimelineDialog(entries)
        self.assertEqual(len(dlg._entries), 1)
        self.assertEqual(dlg._entries[0]["path"], "/files/doc.txt")

    def test_valid_entries_kept(self):
        entries = [
            _entry("/files/a.txt", "2023-01-01 00:00:00"),
            _entry("/files/b.txt", "2023-06-15 12:30:00"),
            _entry("/files/c.txt", "2023-12-31 23:59:59"),
        ]
        dlg = TimelineDialog(entries)
        self.assertEqual(len(dlg._entries), 3)
        paths = [e["path"] for e in dlg._entries]
        self.assertIn("/files/a.txt", paths)
        self.assertIn("/files/b.txt", paths)
        self.assertIn("/files/c.txt", paths)


class TestTimelineDialogUI(unittest.TestCase):
    """Tests that require a QApplication (already created above)."""

    def test_dialog_creates_without_crash(self):
        dlg = TimelineDialog([])
        self.assertIsNotNone(dlg)

    def test_file_selected_signal_exists(self):
        dlg = TimelineDialog([])
        # pyqtSignal exposes a connect method on the bound signal
        self.assertTrue(hasattr(dlg, "file_selected"))
        self.assertTrue(hasattr(dlg.file_selected, "connect"))

    def test_empty_entries_shows_no_plot(self):
        # Should not raise even with empty list
        dlg = TimelineDialog([])
        # _sc_paths should not exist (plot was never built)
        self.assertFalse(hasattr(dlg, "_sc_paths"))

    def test_window_title(self):
        dlg = TimelineDialog([])
        self.assertEqual(dlg.windowTitle(), "File Timeline")


if __name__ == "__main__":
    unittest.main()
