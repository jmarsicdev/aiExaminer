"""Toolbar search widget: name filter + full-text search + progress bar."""

from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLineEdit, QPushButton,
    QProgressBar, QLabel, QComboBox,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont


_CSS = """
    QWidget#SearchBar { background: #16213e; }
    QLineEdit {
        background: #1a1a2e; color: #e0e0e0; border: 1px solid #0f3460;
        border-radius: 4px; padding: 4px 8px; font-size: 13px;
    }
    QLineEdit:focus { border-color: #4ecca3; }
    QPushButton {
        background: #0f3460; color: #4ecca3; border: none;
        border-radius: 4px; padding: 5px 12px; font-size: 12px;
    }
    QPushButton:hover { background: #1a4a8a; }
    QPushButton:disabled { color: #555; }
    QProgressBar {
        background: #1a1a2e; border: 1px solid #0f3460; border-radius: 4px;
        text-align: center; color: #4ecca3; font-size: 11px;
    }
    QProgressBar::chunk { background: #0f3460; border-radius: 3px; }
    QComboBox {
        background: #1a1a2e; color: #e0e0e0; border: 1px solid #0f3460;
        border-radius: 4px; padding: 4px 8px;
    }
    QComboBox QAbstractItemView { background: #16213e; color: #e0e0e0; }
"""


class SearchWorker(QThread):
    """Full-text search across all files in a parser."""
    match_found = pyqtSignal(str, int)   # file_path, byte_offset
    finished    = pyqtSignal(int)        # total matches

    def __init__(self, parser, needle: bytes):
        super().__init__()
        self._parser = parser
        self._needle = needle
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        count = 0
        try:
            self._search_dir('/')
        except Exception:
            pass
        self.finished.emit(count)

    def _search_dir(self, path: str) -> None:
        for entry in self._parser.list_directory(path):
            if self._stop:
                return
            if entry['type'] == 'Folder':
                self._search_dir(entry['path'])
            else:
                self._search_file(entry['path'])

    def _search_file(self, path: str) -> None:
        try:
            content = self._parser.read_file_content(path)
            if not content:
                return
            offset = 0
            while True:
                idx = content.find(self._needle, offset)
                if idx == -1:
                    break
                self.match_found.emit(path, idx)
                offset = idx + 1
        except Exception:
            pass


class SearchBar(QWidget):
    """
    Emits:
      name_filter_changed(str)   — live filter for file-tree name column
      search_requested(bytes)    — full-text search needle
      search_stopped()           — user cancelled
    """
    name_filter_changed = pyqtSignal(str)
    search_requested    = pyqtSignal(bytes)
    search_stopped      = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName('SearchBar')
        self.setStyleSheet(_CSS)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 4, 8, 4)
        lay.setSpacing(6)

        # Name filter
        lay.addWidget(QLabel('Filter:'))
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText('File name filter…')
        self._filter_edit.setFixedWidth(200)
        self._filter_edit.textChanged.connect(self._on_filter_changed)
        lay.addWidget(self._filter_edit)

        # Encoding selector for full-text search
        self._enc_combo = QComboBox()
        self._enc_combo.addItems(['UTF-8', 'UTF-16 LE', 'Latin-1', 'Hex'])
        self._enc_combo.setFixedWidth(90)
        lay.addWidget(self._enc_combo)

        # Full-text search input
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText('Full-text search…')
        self._search_edit.returnPressed.connect(self._on_search)
        lay.addWidget(self._search_edit)

        self._search_btn = QPushButton('Search')
        self._search_btn.clicked.connect(self._on_search)
        lay.addWidget(self._search_btn)

        self._stop_btn = QPushButton('Stop')
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._on_stop)
        lay.addWidget(self._stop_btn)

        # Progress bar
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setFixedWidth(120)
        self._progress.setVisible(False)
        lay.addWidget(self._progress)

        self._status_lbl = QLabel('')
        lay.addWidget(self._status_lbl)

        lay.addStretch()

        # Timer for debouncing name filter
        self._filter_timer = QTimer()
        self._filter_timer.setSingleShot(True)
        self._filter_timer.timeout.connect(
            lambda: self.name_filter_changed.emit(self._filter_edit.text())
        )

    # ------------------------------------------------------------------ #
    #  Public API                                                           #
    # ------------------------------------------------------------------ #

    def set_searching(self, active: bool, status: str = '') -> None:
        self._search_btn.setEnabled(not active)
        self._stop_btn.setEnabled(active)
        self._progress.setVisible(active)
        self._status_lbl.setText(status)

    def set_status(self, text: str) -> None:
        self._status_lbl.setText(text)

    def clear(self) -> None:
        self._filter_edit.clear()
        self._search_edit.clear()
        self._status_lbl.clear()

    # ------------------------------------------------------------------ #
    #  Slots                                                                #
    # ------------------------------------------------------------------ #

    def _on_filter_changed(self, _text: str) -> None:
        self._filter_timer.start(200)

    def _on_search(self) -> None:
        raw = self._search_edit.text().strip()
        if not raw:
            return
        enc = self._enc_combo.currentText()
        if enc == 'Hex':
            try:
                needle = bytes.fromhex(raw.replace(' ', ''))
            except ValueError:
                self._status_lbl.setText('Invalid hex string')
                return
        elif enc == 'UTF-16 LE':
            needle = raw.encode('utf-16-le')
        elif enc == 'Latin-1':
            needle = raw.encode('latin-1', errors='replace')
        else:
            needle = raw.encode('utf-8', errors='replace')
        self.search_requested.emit(needle)

    def _on_stop(self) -> None:
        self.search_stopped.emit()
