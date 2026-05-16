"""
Tests for CLIP-based image search and gallery UI.

Covers:
  1.  CLIPImageSearcher interface — output shape, sorting, progress cb, error handling
  2.  CLIPImageSearcher integration — real CLIP model against PIL-generated images
  3.  _GallerySearchWorker — Qt signals emitted correctly (mocked CLIP)
  4.  _GalleryDialog UI structure — search controls exist
  5.  _GalleryDialog._make_cell — score badge rendering for high/medium/low/no score
  6.  _GalleryDialog._rebuild_grid — sorts cells by score descending
  7.  _GalleryDialog._clear_search — restores original order, no score badges
"""

import io
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Detect optional ML dependencies ─────────────────────────────────────────

try:
    import torch as _torch  # noqa: F401
    TORCH_AVAILABLE = True
except ModuleNotFoundError:
    TORCH_AVAILABLE = False

try:
    import transformers as _transformers  # noqa: F401
    TRANSFORMERS_AVAILABLE = True
except ModuleNotFoundError:
    TRANSFORMERS_AVAILABLE = False

ML_AVAILABLE = TORCH_AVAILABLE and TRANSFORMERS_AVAILABLE

# ── Minimal pure-Python tensor stand-in (no torch required) ─────────────────
#
# Supports the exact operations that score_images performs on features:
#   feat.norm(dim=..., keepdim=...)  →  scalar 1.0 so normalization is a no-op
#   feat / scalar_feat               →  preserves the original value
#   feat @ feat.T                    →  dot-product
#   feat.item()                      →  the stored float

class _FakeTensor:
    def __init__(self, val=1.0):
        self._v = float(val)

    def norm(self, dim=None, keepdim=False):
        # Always return 1 so that dividing by norm is a no-op
        return _FakeTensor(1.0)

    def __truediv__(self, other):
        d = other._v if isinstance(other, _FakeTensor) else float(other)
        return _FakeTensor(self._v / d if d else 0.0)

    def __matmul__(self, other):
        v = other._v if isinstance(other, _FakeTensor) else float(other)
        return _FakeTensor(self._v * v)

    @property
    def T(self):
        return _FakeTensor(self._v)

    def item(self):
        return self._v


class _FakeTorchModule:
    """Minimal torch stand-in for injecting into sys.modules in interface tests."""

    class no_grad:
        def __enter__(self): return self
        def __exit__(self, *a): pass


def _ensure_fake_torch():
    """Inject _FakeTorchModule into sys.modules['torch'] if torch isn't available."""
    if 'torch' not in sys.modules:
        sys.modules['torch'] = _FakeTorchModule()


# ── Shared PIL image factory ─────────────────────────────────────────────────

def _make_jpeg(rgb=(128, 128, 128), size=(64, 64)) -> bytes:
    """Return JPEG bytes for a solid-colour image."""
    from PIL import Image as PILImage
    img = PILImage.new('RGB', size, color=rgb)
    buf = io.BytesIO()
    img.save(buf, format='JPEG', quality=85)
    return buf.getvalue()


# ── 1. CLIPImageSearcher — interface (mocked model, no GPU / download) ───────

class TestCLIPImageSearcherInterface(unittest.TestCase):
    """Fast tests that mock the CLIP model — works without torch/transformers."""

    @classmethod
    def setUpClass(cls):
        _ensure_fake_torch()

    def _make_searcher_with_mock(self, similarity_values):
        """
        Return a CLIPImageSearcher that drives score_images via _FakeTensor.

        The new score_images implementation uses:
          model.text_model(...)       → output with .pooler_output
          model.text_projection(po)  → _FakeTensor
          model.vision_model(...)    → output with .pooler_output
          model.visual_projection(po) → _FakeTensor(sim_for_this_image)
        """
        from src.ai.cv.clip_search import CLIPImageSearcher
        searcher = CLIPImageSearcher()
        searcher._model     = MagicMock()
        searcher._processor = MagicMock()

        # Text side: always returns a unit _FakeTensor (value 1.0)
        text_out_mock = MagicMock()
        text_out_mock.pooler_output = MagicMock()
        searcher._model.text_model.return_value = text_out_mock
        searcher._model.text_projection.return_value = _FakeTensor(1.0)

        # Image side: visual_projection cycles through similarity_values
        call_idx = [0]
        img_out_mock = MagicMock()
        img_out_mock.pooler_output = MagicMock()
        searcher._model.vision_model.return_value = img_out_mock

        def fake_visual_proj(_pooler):
            sim = similarity_values[call_idx[0] % len(similarity_values)]
            call_idx[0] += 1
            return _FakeTensor(sim)

        searcher._model.visual_projection.side_effect = fake_visual_proj

        # Processor returns a dict understood by both text and image paths
        searcher._processor.return_value = {
            'input_ids': MagicMock(),
            'pixel_values': MagicMock(),
        }
        return searcher

    def test_returns_list(self):
        searcher = self._make_searcher_with_mock([0.3])
        result = searcher.score_images('test', [('a.jpg', _make_jpeg())])
        self.assertIsInstance(result, list)

    def test_each_result_is_path_float_tuple(self):
        searcher = self._make_searcher_with_mock([0.25, 0.10])
        images   = [('a.jpg', _make_jpeg()), ('b.jpg', _make_jpeg())]
        results  = searcher.score_images('query', images)
        for item in results:
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2)
            self.assertIsInstance(item[0], str)
            self.assertIsInstance(item[1], float)

    def test_sorted_descending_by_score(self):
        searcher = self._make_searcher_with_mock([0.10, 0.35, 0.20])
        images   = [('low.jpg', _make_jpeg()), ('high.jpg', _make_jpeg()),
                    ('mid.jpg', _make_jpeg())]
        results  = searcher.score_images('query', images)
        scores   = [s for _, s in results]
        self.assertEqual(scores, sorted(scores, reverse=True),
                         'Results must be sorted highest score first')

    def test_empty_image_list_returns_empty(self):
        from src.ai.cv.clip_search import CLIPImageSearcher
        searcher = CLIPImageSearcher()
        with patch.object(searcher, '_load'):
            searcher._model     = MagicMock()
            searcher._processor = MagicMock()

            text_out = MagicMock()
            text_out.pooler_output = MagicMock()
            searcher._model.text_model.return_value = text_out
            searcher._model.text_projection.return_value = _FakeTensor(1.0)
            searcher._processor.return_value = {'input_ids': MagicMock()}

            result = searcher.score_images('something', [])
        self.assertEqual(result, [])

    def test_progress_callback_called_once_per_image(self):
        searcher = self._make_searcher_with_mock([0.2, 0.3, 0.1])
        images   = [('a.jpg', _make_jpeg()), ('b.jpg', _make_jpeg()),
                    ('c.jpg', _make_jpeg())]
        calls    = []
        searcher.score_images('query', images, progress_cb=lambda d, t: calls.append((d, t)))
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0], (1, 3))
        self.assertEqual(calls[1], (2, 3))
        self.assertEqual(calls[2], (3, 3))

    def test_corrupt_image_data_gives_zero_score_no_crash(self):
        searcher = self._make_searcher_with_mock([0.3])
        images   = [('bad.jpg', b'\xff\xd8corrupt data here')]
        results  = searcher.score_images('query', images)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][1], 0.0)

    def test_all_paths_present_in_results(self):
        searcher = self._make_searcher_with_mock([0.1, 0.4, 0.2])
        paths    = ['x.jpg', 'y.jpg', 'z.jpg']
        images   = [(p, _make_jpeg()) for p in paths]
        results  = searcher.score_images('query', images)
        result_paths = {p for p, _ in results}
        self.assertEqual(result_paths, set(paths))

    def test_single_image_returns_single_result(self):
        searcher = self._make_searcher_with_mock([0.22])
        results  = searcher.score_images('query', [('only.jpg', _make_jpeg())])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'only.jpg')

    def test_no_progress_callback_is_fine(self):
        searcher = self._make_searcher_with_mock([0.2])
        searcher.score_images('query', [('a.jpg', _make_jpeg())])


# ── 2. CLIPImageSearcher — integration (real model, cached) ─────────────────

@unittest.skipUnless(ML_AVAILABLE, 'torch and transformers must be installed')
class TestCLIPImageSearcherIntegration(unittest.TestCase):
    """Uses the actual CLIP model against PIL-generated images."""

    @classmethod
    def setUpClass(cls):
        from src.ai.cv.clip_search import CLIPImageSearcher
        cls.searcher = CLIPImageSearcher()
        cls.searcher._load()

    def test_score_is_float(self):
        result = self.searcher.score_images('a photo', [('img.jpg', _make_jpeg())])
        self.assertIsInstance(result[0][1], float)

    def test_score_in_valid_cosine_range(self):
        result = self.searcher.score_images('person', [('img.jpg', _make_jpeg())])
        score  = result[0][1]
        self.assertGreaterEqual(score, -1.0)
        self.assertLessEqual(score, 1.0)

    def test_multiple_images_sorted_descending(self):
        images  = [(f'{i}.jpg', _make_jpeg(rgb=(i * 30 % 255, 100, 100)))
                   for i in range(5)]
        results = self.searcher.score_images('red colour', images)
        scores  = [s for _, s in results]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_progress_callback_fires_for_each_image(self):
        n       = 4
        images  = [(f'{i}.jpg', _make_jpeg()) for i in range(n)]
        calls   = []
        self.searcher.score_images('document', images,
                                   progress_cb=lambda d, t: calls.append((d, t)))
        self.assertEqual(len(calls), n)
        self.assertTrue(all(t == n for _, t in calls))

    def test_corrupt_image_graceful(self):
        images  = [('bad.jpg', b'not an image'), ('ok.jpg', _make_jpeg())]
        results = self.searcher.score_images('something', images)
        self.assertEqual(len(results), 2)
        bad_score = next(s for p, s in results if p == 'bad.jpg')
        self.assertEqual(bad_score, 0.0)

    def test_semantic_scores_are_consistent(self):
        """Running the same query twice should return the same scores."""
        images   = [('a.jpg', _make_jpeg(rgb=(200, 100, 50))),
                    ('b.jpg', _make_jpeg(rgb=(50, 50, 200)))]
        results1 = self.searcher.score_images('red image', images)
        results2 = self.searcher.score_images('red image', images)
        scores1  = dict(results1)
        scores2  = dict(results2)
        for path in ('a.jpg', 'b.jpg'):
            self.assertAlmostEqual(scores1[path], scores2[path], places=5,
                                   msg='CLIP scores must be deterministic')

    def test_lazy_load_model_persists_across_calls(self):
        _ = self.searcher.score_images('test', [('a.jpg', _make_jpeg())])
        model_ref = self.searcher._model
        _ = self.searcher.score_images('test2', [('b.jpg', _make_jpeg())])
        self.assertIs(self.searcher._model, model_ref,
                      'Model should not be reloaded between calls')


# ── 3. _GallerySearchWorker — Qt signals ────────────────────────────────────

class TestGallerySearchWorker(unittest.TestCase):

    def test_has_progress_signal(self):
        from src.ui.main_window import _GallerySearchWorker
        self.assertTrue(hasattr(_GallerySearchWorker, 'progress'))

    def test_has_done_signal(self):
        from src.ui.main_window import _GallerySearchWorker
        self.assertTrue(hasattr(_GallerySearchWorker, 'done'))

    def test_done_emitted_with_sorted_results(self):
        from src.ui.main_window import _GallerySearchWorker

        images       = [('a.jpg', _make_jpeg()), ('b.jpg', _make_jpeg()),
                        ('c.jpg', _make_jpeg())]
        fake_results = [('b.jpg', 0.35), ('c.jpg', 0.22), ('a.jpg', 0.10)]

        received = []
        with patch('src.ai.cv.clip_search.CLIPImageSearcher.score_images',
                   return_value=fake_results):
            worker = _GallerySearchWorker('document', images)
            worker.done.connect(received.append)
            worker.run()

        self.assertEqual(len(received), 1, 'done signal emitted exactly once')
        scores = [s for _, s in received[0]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_progress_emitted_during_scoring(self):
        from src.ui.main_window import _GallerySearchWorker

        images = [('x.jpg', _make_jpeg()), ('y.jpg', _make_jpeg())]
        progress_calls = []

        def fake_score(query, imgs, progress_cb=None):
            for i, (p, _) in enumerate(imgs):
                if progress_cb:
                    progress_cb(i + 1, len(imgs))
            return [(p, 0.2) for p, _ in imgs]

        with patch('src.ai.cv.clip_search.CLIPImageSearcher.score_images',
                   side_effect=fake_score):
            worker = _GallerySearchWorker('test', images)
            worker.progress.connect(lambda d, t: progress_calls.append((d, t)))
            worker.run()

        self.assertGreater(len(progress_calls), 0)
        self.assertEqual(progress_calls[-1], (2, 2))

    def test_worker_passes_query_to_searcher(self):
        from src.ui.main_window import _GallerySearchWorker

        captured_query = []

        def fake_score(query, imgs, progress_cb=None):
            captured_query.append(query)
            return [(p, 0.1) for p, _ in imgs]

        with patch('src.ai.cv.clip_search.CLIPImageSearcher.score_images',
                   side_effect=fake_score):
            worker = _GallerySearchWorker('weapon or gun', [('a.jpg', _make_jpeg())])
            worker.run()

        self.assertEqual(captured_query[0], 'weapon or gun')


# ── 4 & 5. _GalleryDialog UI (needs QApplication) ────────────────────────────

def _get_app():
    from PyQt6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class TestGalleryDialogUIStructure(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = _get_app()

    def _make_dialog(self):
        from src.ui.main_window import _GalleryDialog
        mock_parser = MagicMock()
        mock_parser.list_directory.return_value = iter([])
        with patch('src.ui.main_window._GalleryWorker') as mock_worker_cls:
            mock_worker_cls.return_value = MagicMock()
            dlg = _GalleryDialog(mock_parser)
        return dlg

    def test_search_box_exists(self):
        dlg = self._make_dialog()
        self.assertTrue(hasattr(dlg, '_search_box'))

    def test_search_button_exists(self):
        dlg = self._make_dialog()
        self.assertTrue(hasattr(dlg, '_search_btn'))
        self.assertEqual(dlg._search_btn.text(), 'Search')

    def test_clear_button_exists(self):
        dlg = self._make_dialog()
        self.assertTrue(hasattr(dlg, '_clear_btn'))
        self.assertEqual(dlg._clear_btn.text(), 'Show All')

    def test_clear_button_disabled_initially(self):
        dlg = self._make_dialog()
        self.assertFalse(dlg._clear_btn.isEnabled(),
                         '"Show All" should be disabled until a search is run')

    def test_search_button_enabled_initially(self):
        dlg = self._make_dialog()
        self.assertTrue(dlg._search_btn.isEnabled())

    def test_status_label_exists(self):
        dlg = self._make_dialog()
        self.assertTrue(hasattr(dlg, '_status'))

    def test_selected_label_exists(self):
        dlg = self._make_dialog()
        self.assertTrue(hasattr(dlg, '_selected_lbl'))

    def test_all_images_list_starts_empty(self):
        dlg = self._make_dialog()
        self.assertEqual(dlg._all_images, [])

    def test_count_starts_at_zero(self):
        dlg = self._make_dialog()
        self.assertEqual(dlg._count, 0)


# ── 5. _make_cell score badge rendering ──────────────────────────────────────

class TestGalleryCellRendering(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = _get_app()

    def _get_make_cell(self):
        from src.ui.main_window import _GalleryDialog
        mock_parser = MagicMock()
        mock_parser.list_directory.return_value = iter([])
        with patch('src.ui.main_window._GalleryWorker') as mock_worker_cls:
            mock_worker_cls.return_value = MagicMock()
            dlg = _GalleryDialog(mock_parser)
        return dlg

    def _dummy_pixmap(self):
        from PyQt6.QtGui import QPixmap
        pix = QPixmap(10, 10)
        pix.fill()
        return pix

    def test_cell_without_score_has_no_match_label(self):
        dlg   = self._get_make_cell()
        cell  = dlg._make_cell('/some/image.jpg', self._dummy_pixmap(), score=None)
        from PyQt6.QtWidgets import QLabel
        texts = [l.text() for l in cell.findChildren(QLabel)]
        self.assertFalse(any('Match' in t for t in texts),
                         'No score badge expected when score=None')

    def test_cell_with_score_shows_match_label(self):
        dlg  = self._get_make_cell()
        cell = dlg._make_cell('/some/image.jpg', self._dummy_pixmap(), score=0.30)
        from PyQt6.QtWidgets import QLabel
        texts = [l.text() for l in cell.findChildren(QLabel)]
        self.assertTrue(any('Match' in t for t in texts),
                        'Score badge (Match %) should appear when score is given')

    def test_high_score_shows_percentage(self):
        dlg  = self._get_make_cell()
        cell = dlg._make_cell('/img.jpg', self._dummy_pixmap(), score=0.30)
        from PyQt6.QtWidgets import QLabel
        match_labels = [l for l in cell.findChildren(QLabel) if 'Match' in l.text()]
        self.assertTrue(any('30%' in l.text() for l in match_labels))

    def test_score_badge_colour_green_for_high(self):
        dlg  = self._get_make_cell()
        cell = dlg._make_cell('/img.jpg', self._dummy_pixmap(), score=0.28)
        from PyQt6.QtWidgets import QLabel
        match_label = next((l for l in cell.findChildren(QLabel) if 'Match' in l.text()), None)
        self.assertIsNotNone(match_label)
        self.assertIn('#4ecca3', match_label.styleSheet())

    def test_score_badge_colour_orange_for_medium(self):
        dlg  = self._get_make_cell()
        cell = dlg._make_cell('/img.jpg', self._dummy_pixmap(), score=0.20)
        from PyQt6.QtWidgets import QLabel
        match_label = next((l for l in cell.findChildren(QLabel) if 'Match' in l.text()), None)
        self.assertIsNotNone(match_label)
        self.assertIn('#f57f17', match_label.styleSheet())

    def test_score_badge_colour_grey_for_low(self):
        dlg  = self._get_make_cell()
        cell = dlg._make_cell('/img.jpg', self._dummy_pixmap(), score=0.10)
        from PyQt6.QtWidgets import QLabel
        match_label = next((l for l in cell.findChildren(QLabel) if 'Match' in l.text()), None)
        self.assertIsNotNone(match_label)
        self.assertIn('#555', match_label.styleSheet())

    def test_cell_has_correct_fixed_size(self):
        from src.ui.main_window import _GALLERY_CELL_W, _GALLERY_CELL_H
        dlg  = self._get_make_cell()
        cell = dlg._make_cell('/img.jpg', self._dummy_pixmap())
        self.assertEqual(cell.width(),  _GALLERY_CELL_W)
        self.assertEqual(cell.height(), _GALLERY_CELL_H)

    def test_cell_tooltip_is_full_path(self):
        dlg  = self._get_make_cell()
        path = '/Users/gmo_g/AppData/Local/Google/Chrome/image.jpg'
        cell = dlg._make_cell(path, self._dummy_pixmap())
        self.assertEqual(cell.toolTip(), path)


# ── 6. _rebuild_grid order ────────────────────────────────────────────────────

class TestGalleryRebuildGrid(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = _get_app()

    def test_rebuild_places_highest_score_first(self):
        from src.ui.main_window import _GalleryDialog, _GALLERY_COLS  # noqa: F401
        mock_parser = MagicMock()
        mock_parser.list_directory.return_value = iter([])
        with patch('src.ui.main_window._GalleryWorker') as mock_cls:
            mock_cls.return_value = MagicMock()
            dlg = _GalleryDialog(mock_parser)

        dlg._all_images = [
            ('low.jpg',  _make_jpeg(rgb=(50, 50, 50))),
            ('high.jpg', _make_jpeg(rgb=(200, 200, 200))),
            ('mid.jpg',  _make_jpeg(rgb=(120, 120, 120))),
        ]
        dlg._rebuild_grid([('high.jpg', 0.40), ('mid.jpg', 0.25), ('low.jpg', 0.08)])

        item = dlg._grid.itemAtPosition(0, 0)
        self.assertIsNotNone(item)
        self.assertEqual(item.widget().toolTip(), 'high.jpg')

    def test_rebuild_low_score_cell_is_dimmed(self):
        from src.ui.main_window import _GalleryDialog
        mock_parser = MagicMock()
        mock_parser.list_directory.return_value = iter([])
        with patch('src.ui.main_window._GalleryWorker') as mock_cls:
            mock_cls.return_value = MagicMock()
            dlg = _GalleryDialog(mock_parser)

        dlg._all_images = [('noise.jpg', _make_jpeg())]
        dlg._rebuild_grid([('noise.jpg', 0.05)])

        item = dlg._grid.itemAtPosition(0, 0)
        cell = item.widget()
        self.assertIn('#111118', cell.styleSheet())


# ── 7. _clear_search restores original order ─────────────────────────────────

class TestGalleryClearSearch(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = _get_app()

    def test_clear_search_removes_score_badges(self):
        from src.ui.main_window import _GalleryDialog
        mock_parser = MagicMock()
        mock_parser.list_directory.return_value = iter([])
        with patch('src.ui.main_window._GalleryWorker') as mock_cls:
            mock_cls.return_value = MagicMock()
            dlg = _GalleryDialog(mock_parser)

        dlg._all_images = [('a.jpg', _make_jpeg()), ('b.jpg', _make_jpeg())]
        dlg._rebuild_grid([('a.jpg', 0.35), ('b.jpg', 0.12)])
        dlg._clear_search()

        from PyQt6.QtWidgets import QLabel
        for i in range(dlg._grid.count()):
            item = dlg._grid.itemAt(i)
            if item and item.widget():
                texts = [l.text() for l in item.widget().findChildren(QLabel)]
                self.assertFalse(any('Match' in t for t in texts),
                                 'After clear, no cell should have a Match badge')

    def test_clear_search_restores_original_order(self):
        from src.ui.main_window import _GalleryDialog
        mock_parser = MagicMock()
        mock_parser.list_directory.return_value = iter([])
        with patch('src.ui.main_window._GalleryWorker') as mock_cls:
            mock_cls.return_value = MagicMock()
            dlg = _GalleryDialog(mock_parser)

        dlg._all_images = [('first.jpg', _make_jpeg()), ('second.jpg', _make_jpeg())]
        dlg._rebuild_grid([('second.jpg', 0.9), ('first.jpg', 0.1)])
        dlg._clear_search()

        item0 = dlg._grid.itemAtPosition(0, 0)
        self.assertIsNotNone(item0)
        self.assertEqual(item0.widget().toolTip(), 'first.jpg',
                         'After clear, original first image should be at position 0,0')

    def test_clear_disables_show_all_button(self):
        from src.ui.main_window import _GalleryDialog
        mock_parser = MagicMock()
        mock_parser.list_directory.return_value = iter([])
        with patch('src.ui.main_window._GalleryWorker') as mock_cls:
            mock_cls.return_value = MagicMock()
            dlg = _GalleryDialog(mock_parser)

        dlg._all_images = [('a.jpg', _make_jpeg())]
        dlg._rebuild_grid([('a.jpg', 0.2)])
        dlg._clear_btn.setEnabled(True)
        dlg._clear_search()
        self.assertFalse(dlg._clear_btn.isEnabled())


if __name__ == '__main__':
    unittest.main(verbosity=2)
