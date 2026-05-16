"""
Tabbed right-pane:
  Hex | Score | Text | Strings | Image | Metadata | Entities | Entropy | Steg | AI Analysis

Tabs are populated lazily — heavy work (steg, strings) is deferred until tab is clicked
unless the file is small enough to do everything upfront.
"""

import webbrowser

from PyQt6.QtWidgets import (
    QTabWidget, QTextEdit, QLabel, QTableWidget, QTableWidgetItem,
    QScrollArea, QWidget, QHeaderView, QVBoxLayout,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QPixmap, QFont, QColor, QBrush

from src.ui.hex_viewer import HexViewer
from src.core.file_type import detect_file_type, is_text, detect_encoding
from src.core.metadata import extract_metadata
from src.ai.entity_extractor import EntityExtractor
import src.ai.entropy_analyzer as entropy_mod
import src.ai.relevance_scorer as relevance_mod
import src.core.strings_util as strings_mod


_DARK_CSS = """
    QTabWidget::pane { border: 1px solid #0f3460; background: #1a1a2e; }
    QTabBar::tab { background: #16213e; color: #aaa; padding: 6px 14px; min-width: 60px; }
    QTabBar::tab:selected { background: #0f3460; color: #4ecca3; }
    QTextEdit, QTableWidget { background: #1a1a2e; color: #e0e0e0; border: none; }
    QHeaderView::section { background: #0f3460; color: #4ecca3; padding: 4px; }
    QTableWidget::item { border-bottom: 1px solid #2a2a4a; }
    QScrollArea { background: #1a1a2e; border: none; }
    QLabel { background: #1a1a2e; color: #e0e0e0; }
"""

_EXTRACTOR = EntityExtractor()
_STEG_THRESHOLD = 20 * 1024 * 1024   # auto-run steg on images < 20 MB
_STR_THRESHOLD  = 50 * 1024 * 1024   # auto-extract strings < 50 MB


# ------------------------------------------------------------------ #
#  Background worker                                                    #
# ------------------------------------------------------------------ #

class PreviewWorker(QThread):
    ready  = pyqtSignal(bytes, dict, list)   # content, meta, entities
    failed = pyqtSignal(str)

    def __init__(self, parser, file_path, entry):
        super().__init__()
        self._parser = parser
        self._path   = file_path
        self._entry  = entry

    def run(self):
        try:
            content = self._parser.read_file_content(self._path)
            if content is None:
                self.failed.emit(f'Could not read: {self._path}')
                return
            meta     = extract_metadata(self._path, content, self._entry)
            entities = _EXTRACTOR.extract_from_bytes(content)
            self.ready.emit(content, meta, entities)
        except Exception as e:
            self.failed.emit(str(e))


# ------------------------------------------------------------------ #
#  Preview pane                                                         #
# ------------------------------------------------------------------ #

class PreviewPane(QTabWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(_DARK_CSS)

        # ---- Tab 0: Hex ----
        self._hex = HexViewer()
        self.addTab(self._hex, 'Hex')

        # ---- Tab 1: Score ----
        self._score_view = QTextEdit()
        self._score_view.setReadOnly(True)
        self.addTab(self._score_view, 'Score')

        # ---- Tab 2: Text ----
        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(QFont('Monospace', 9))
        self.addTab(self._text, 'Text')

        # ---- Tab 3: Strings ----
        self._strings_view = QTextEdit()
        self._strings_view.setReadOnly(True)
        self.addTab(self._strings_view, 'Strings')

        # ---- Tab 4: Image ----
        img_scroll = QScrollArea()
        img_scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._img_label = QLabel()
        self._img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        img_scroll.setWidget(self._img_label)
        img_scroll.setWidgetResizable(True)
        self.addTab(img_scroll, 'Image')

        # ---- Tab 5: Metadata ----
        self._meta_table = QTableWidget(0, 2)
        self._meta_table.setHorizontalHeaderLabels(['Property', 'Value'])
        self._meta_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents)
        self._meta_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        self._meta_table.verticalHeader().setVisible(False)
        self._meta_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._meta_table.cellClicked.connect(self._on_meta_cell_clicked)
        self.addTab(self._meta_table, 'Metadata')

        # ---- Tab 6: Entities / IOC ----
        self._entities_view = QTextEdit()
        self._entities_view.setReadOnly(True)
        self.addTab(self._entities_view, 'Entities')

        # ---- Tab 7: Entropy ----
        self._entropy_view = QTextEdit()
        self._entropy_view.setReadOnly(True)
        self.addTab(self._entropy_view, 'Entropy')

        # ---- Tab 8: Steg ----
        self._steg_view = QTextEdit()
        self._steg_view.setReadOnly(True)
        self.addTab(self._steg_view, 'Steg')

        # ---- Tab 9: AI Analysis ----
        self._ai_view = QTextEdit()
        self._ai_view.setReadOnly(True)
        self._ai_view.setPlaceholderText(
            'Right-click a file and choose "Run AI Analysis".'
        )
        self.addTab(self._ai_view, 'AI Analysis')

        self._worker: PreviewWorker | None = None
        self._current_path: str = ''
        self._current_entry: dict = {}
        self._content_cache: bytes = b''
        self._strings_loaded = False
        self._steg_loaded    = False
        self._score_set      = False

        # Lazy-load strings/steg on tab click
        self.currentChanged.connect(self._on_tab_changed)

    # ---------------------------------------------------------------- #
    #  Public API                                                        #
    # ---------------------------------------------------------------- #

    def load_file(self, parser, file_path: str, entry: dict) -> None:
        if file_path == self._current_path:
            return
        self._current_path = file_path
        self._current_entry = entry
        self._strings_loaded = False
        self._steg_loaded    = False
        self._score_set      = False
        self._clear_all()
        self._text.setPlainText(f'Loading {file_path} …')

        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            self._worker.wait(200)

        self._worker = PreviewWorker(parser, file_path, entry)
        self._worker.ready.connect(self._on_ready)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def show_ai_result(self, html: str) -> None:
        self._ai_view.setHtml(html)
        self.setCurrentIndex(9)

    def show_score_card(self, html: str) -> None:
        """Populate the Score tab with a pre-rendered score card and switch to it."""
        self._score_view.setHtml(html)
        self._score_set = True
        self.setCurrentIndex(1)

    def clear(self) -> None:
        self._current_path = ''
        self._content_cache = b''
        self._clear_all()

    # ---------------------------------------------------------------- #
    #  Slots                                                             #
    # ---------------------------------------------------------------- #

    def _on_ready(self, content: bytes, meta: dict, entities: list) -> None:
        self._content_cache = content
        category = meta.get('Category', '')

        # Hex
        self._hex.set_data(content)

        # Text
        if category == 'image':
            self._text.setPlainText('<binary image data>')
        elif is_text(content[:4096]):
            enc = detect_encoding(content[:65536]) or 'utf-8'
            try:
                self._text.setPlainText(content.decode(enc, errors='replace'))
            except Exception:
                self._text.setPlainText(content.decode('latin-1', errors='replace'))
        else:
            printable = ''.join(
                chr(b) if 0x20 <= b < 0x7F or b in (9, 10, 13) else '.'
                for b in content[:65536]
            )
            self._text.setPlainText(printable)

        # Strings (auto-load if file is small enough)
        if len(content) <= _STR_THRESHOLD:
            self._load_strings(content)
        else:
            self._strings_view.setPlainText(
                f'File is large ({len(content)//1024} KB). '
                'Click the Strings tab to extract.'
            )

        # Image
        if category == 'image':
            pix = QPixmap()
            pix.loadFromData(content)
            if not pix.isNull():
                pix = pix.scaled(800, 600,
                                  Qt.AspectRatioMode.KeepAspectRatio,
                                  Qt.TransformationMode.SmoothTransformation)
                self._img_label.setPixmap(pix)
            else:
                self._img_label.setText('Could not decode image')

        # Metadata
        self._meta_table.setRowCount(len(meta))
        for row, (key, val) in enumerate(meta.items()):
            self._meta_table.setItem(row, 0, QTableWidgetItem(str(key)))
            val_str = str(val)
            val_item = QTableWidgetItem(val_str)
            if val_str.startswith('https://'):
                val_item.setForeground(QBrush(QColor('#4ecca3')))
                val_item.setToolTip('Click to open in browser')
            self._meta_table.setItem(row, 1, val_item)

        # Entities
        self._entities_view.setHtml(_EXTRACTOR.to_html(entities))

        # Entropy (always fast)
        ent_result = entropy_mod.analyze(content)
        self._entropy_view.setHtml(entropy_mod.render_html(ent_result))

        # Score — compute on-the-fly if no precomputed score was provided
        if not self._score_set:
            sample = content[:65536]
            ft = detect_file_type(sample, self._current_entry.get('name', ''))
            sr = relevance_mod.score_file(
                file_path     = self._current_path,
                file_category = ft['category'],
                entropy       = ent_result.overall,
                entities      = entities,
                content_sample= sample,
                is_deleted    = self._current_entry.get('is_deleted', False),
                mtime         = self._current_entry.get('mtime'),
            )
            self._score_view.setHtml(relevance_mod.render_html(sr))
            self._score_set = True
            self.setCurrentIndex(1)

        # Steg (only for images and if small enough)
        if category == 'image' and len(content) <= _STEG_THRESHOLD:
            self._load_steg(content)
        elif category == 'image':
            self._steg_view.setHtml(
                '<p style="color:#aaa">Image too large for auto steg analysis. '
                'Click the Steg tab to run.</p>'
            )
        else:
            self._steg_view.setHtml(
                '<p style="color:#555">Steganography analysis is for image files only.</p>'
            )

    def _on_meta_cell_clicked(self, row: int, col: int) -> None:
        if col != 1:
            return
        item = self._meta_table.item(row, col)
        if item and item.text().startswith('https://'):
            webbrowser.open(item.text())

    def _on_failed(self, msg: str) -> None:
        self._text.setPlainText(f'Error: {msg}')

    def _on_tab_changed(self, index: int) -> None:
        content = self._content_cache
        if not content:
            return
        if index == 3 and not self._strings_loaded:
            self._load_strings(content)
        elif index == 8 and not self._steg_loaded:
            self._load_steg(content)

    # ---------------------------------------------------------------- #
    #  Heavy loaders                                                     #
    # ---------------------------------------------------------------- #

    def _load_strings(self, content: bytes) -> None:
        self._strings_loaded = True
        hits = strings_mod.extract_strings(content)
        self._strings_view.setHtml(strings_mod.to_html(hits))

    def _load_steg(self, content: bytes) -> None:
        self._steg_loaded = True
        try:
            from src.ai import steganalysis
            result = steganalysis.analyze_image(content)
            if result:
                self._steg_view.setHtml(steganalysis.render_html(result))
            else:
                self._steg_view.setHtml(
                    '<p style="color:#888">Could not decode image for steg analysis.</p>'
                )
        except Exception as e:
            self._steg_view.setHtml(f'<p style="color:#ef5350">Steg error: {e}</p>')

    def _clear_all(self) -> None:
        self._hex.set_data(b'')
        self._score_view.clear()
        self._text.clear()
        self._strings_view.clear()
        self._img_label.clear()
        self._meta_table.setRowCount(0)
        self._entities_view.clear()
        self._entropy_view.clear()
        self._steg_view.clear()
