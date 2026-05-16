import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import sys
import unittest

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_db_and_scores():
    from src.db.manager import DatabaseManager
    from src.ai.relevance_scorer import ScoreResult
    db = DatabaseManager(db_path=":memory:")
    cid = db.create_case("TEST-001", "Examiner")
    eid = db.add_evidence(cid, "/img.E01")
    score_map = {
        "/files/critical.exe": ScoreResult(score=85, tier="Critical", reasons=["exe"], breakdown={}),
        "/files/high.doc":     ScoreResult(score=60, tier="High",     reasons=["doc"], breakdown={}),
        "/files/noise.txt":    ScoreResult(score=5,  tier="Noise",    reasons=[],     breakdown={}),
    }
    return db, cid, eid, score_map


# Create a QApplication once for all UI tests
_app = None


def _get_app():
    global _app
    from PyQt6.QtWidgets import QApplication
    if _app is None:
        _app = QApplication.instance() or QApplication(sys.argv)
    return _app


class TestCaseDashboardConstruction(unittest.TestCase):
    """Tests that require a running QApplication."""

    @classmethod
    def setUpClass(cls):
        cls.app = _get_app()

    def setUp(self):
        db, cid, eid, score_map = _make_db_and_scores()
        from src.ui.dashboard import CaseDashboard
        self.dlg = CaseDashboard(db, cid, score_map)
        self._db = db
        self._cid = cid
        self._score_map = score_map

    def tearDown(self):
        self.dlg.close()

    def test_creates_without_crash(self):
        """CaseDashboard(db, cid, score_map) should not raise."""
        # If we got here, setUp succeeded — pass.
        from src.ui.dashboard import CaseDashboard
        db, cid, _, score_map = _make_db_and_scores()
        dlg = CaseDashboard(db, cid, score_map)
        self.assertIsNotNone(dlg)
        dlg.close()

    def test_window_title(self):
        self.assertEqual(self.dlg.windowTitle(), "Case Dashboard")

    def test_file_selected_signal_exists(self):
        self.assertTrue(hasattr(self.dlg, 'file_selected'))

    def test_table_has_correct_columns(self):
        self.assertEqual(self.dlg._table.columnCount(), 3)


class TestCaseDashboardStats(unittest.TestCase):
    """Tests for stats, sorting, and edge-cases."""

    @classmethod
    def setUpClass(cls):
        cls.app = _get_app()

    def tearDown(self):
        # Close any dialog created inside a test
        if hasattr(self, '_dlg') and self._dlg is not None:
            self._dlg.close()
            self._dlg = None

    def test_stat_card_function_returns_qframe(self):
        from PyQt6.QtWidgets import QFrame
        from src.ui.dashboard import _stat_card
        card = _stat_card("Test", "42")
        self.assertIsInstance(card, QFrame)

    def test_top_sorted_by_score(self):
        """First row in the table should be the critical file (score 85)."""
        from src.ui.dashboard import CaseDashboard
        db, cid, _, score_map = _make_db_and_scores()
        dlg = CaseDashboard(db, cid, score_map)
        self._dlg = dlg
        first_path = dlg._table.item(0, 0).text()
        self.assertEqual(first_path, "/files/critical.exe")

    def test_only_top_10_shown(self):
        """With 15 items in score_map, table should have at most 10 rows."""
        from src.ui.dashboard import CaseDashboard
        from src.ai.relevance_scorer import ScoreResult
        db, cid, _, _ = _make_db_and_scores()
        big_map = {
            f"/files/file_{i}.exe": ScoreResult(score=i * 5, tier="Low", reasons=[], breakdown={})
            for i in range(15)
        }
        dlg = CaseDashboard(db, cid, big_map)
        self._dlg = dlg
        self.assertLessEqual(dlg._table.rowCount(), 10)

    def test_empty_score_map_no_crash(self):
        """CaseDashboard with an empty score_map should not crash."""
        from src.ui.dashboard import CaseDashboard
        db, cid, _, _ = _make_db_and_scores()
        dlg = CaseDashboard(db, cid, {})
        self._dlg = dlg
        self.assertEqual(dlg._table.rowCount(), 0)

    def test_none_scores_skipped(self):
        """score_map entries with None values should be silently skipped."""
        from src.ui.dashboard import CaseDashboard
        from src.ai.relevance_scorer import ScoreResult
        db, cid, _, _ = _make_db_and_scores()
        score_map = {
            "/files/good.exe": ScoreResult(score=90, tier="Critical", reasons=[], breakdown={}),
            "/files/bad.txt":  None,
        }
        dlg = CaseDashboard(db, cid, score_map)
        self._dlg = dlg
        # Only the non-None entry should appear
        self.assertEqual(dlg._table.rowCount(), 1)
        self.assertEqual(dlg._table.item(0, 0).text(), "/files/good.exe")


if __name__ == "__main__":
    unittest.main()
