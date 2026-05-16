"""Application dialogs: New Case, Bookmark, Export, Report Options."""

from PyQt6.QtWidgets import (
    QDialog, QFormLayout, QLineEdit, QTextEdit, QPushButton,
    QDialogButtonBox, QVBoxLayout, QHBoxLayout, QLabel,
    QColorDialog, QCheckBox, QFileDialog, QComboBox, QGroupBox,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor


_DIALOG_CSS = """
    QDialog { background: #1a1a2e; color: #e0e0e0; }
    QLabel  { color: #e0e0e0; }
    QLineEdit, QTextEdit, QComboBox {
        background: #16213e; color: #e0e0e0;
        border: 1px solid #0f3460; border-radius: 4px; padding: 4px 8px;
    }
    QLineEdit:focus, QTextEdit:focus { border-color: #4ecca3; }
    QPushButton {
        background: #0f3460; color: #4ecca3;
        border: none; border-radius: 4px; padding: 6px 16px;
    }
    QPushButton:hover { background: #1a4a8a; }
    QDialogButtonBox QPushButton { min-width: 80px; }
    QGroupBox { color: #4ecca3; border: 1px solid #0f3460;
                border-radius: 6px; margin-top: 10px; padding-top: 6px; }
    QGroupBox::title { subcontrol-origin: margin; left: 10px; }
    QCheckBox { color: #e0e0e0; }
    QCheckBox::indicator { width: 14px; height: 14px;
                           border: 1px solid #0f3460; background: #16213e; }
    QCheckBox::indicator:checked { background: #4ecca3; }
"""


# ------------------------------------------------------------------ #
#  New Case Dialog                                                      #
# ------------------------------------------------------------------ #

class NewCaseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('New Case')
        self.setStyleSheet(_DIALOG_CSS)
        self.setMinimumWidth(420)

        form = QFormLayout()
        self._case_num  = QLineEdit()
        self._examiner  = QLineEdit()
        self._desc      = QTextEdit()
        self._desc.setFixedHeight(80)
        self._db_path   = QLineEdit()
        self._db_path.setReadOnly(True)
        self._db_path.setPlaceholderText('Click Browse to choose location…')

        browse_btn = QPushButton('Browse…')
        browse_btn.clicked.connect(self._browse_db)
        db_row = QHBoxLayout()
        db_row.addWidget(self._db_path)
        db_row.addWidget(browse_btn)

        form.addRow('Case Number:', self._case_num)
        form.addRow('Examiner:',    self._examiner)
        form.addRow('Description:', self._desc)
        form.addRow('Database:',    db_row)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(btns)

    def _browse_db(self):
        path, _ = QFileDialog.getSaveFileName(
            self, 'Case Database Location', '', 'SQLite DB (*.db)'
        )
        if path:
            self._db_path.setText(path)

    def _validate(self):
        if not self._case_num.text().strip():
            self._case_num.setFocus()
            return
        if not self._db_path.text().strip():
            return
        self.accept()

    @property
    def case_number(self) -> str:
        return self._case_num.text().strip()

    @property
    def examiner(self) -> str:
        return self._examiner.text().strip()

    @property
    def description(self) -> str:
        return self._desc.toPlainText().strip()

    @property
    def db_path(self) -> str:
        return self._db_path.text().strip()


# ------------------------------------------------------------------ #
#  Bookmark Dialog                                                      #
# ------------------------------------------------------------------ #

class BookmarkDialog(QDialog):
    def __init__(self, file_path: str, parent=None,
                 tag_name: str = '', tag_color: str = '#FFDD00', notes: str = ''):
        super().__init__(parent)
        self.setWindowTitle('Bookmark / Tag')
        self.setStyleSheet(_DIALOG_CSS)
        self.setMinimumWidth(380)

        form = QFormLayout()

        path_lbl = QLabel(file_path)
        path_lbl.setWordWrap(True)
        path_lbl.setStyleSheet('color:#aaa;font-size:11px;')
        form.addRow('File:', path_lbl)

        self._tag_name  = QLineEdit(tag_name)
        self._tag_name.setPlaceholderText('e.g. Suspicious, Evidence, Key File…')
        form.addRow('Tag Name:', self._tag_name)

        self._color = tag_color or '#FFDD00'
        self._color_btn = QPushButton()
        self._color_btn.setFixedSize(80, 28)
        self._color_btn.clicked.connect(self._pick_color)
        self._refresh_color_btn()
        form.addRow('Color:', self._color_btn)

        self._notes = QTextEdit(notes)
        self._notes.setFixedHeight(80)
        self._notes.setPlaceholderText('Optional investigator notes…')
        form.addRow('Notes:', self._notes)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(btns)

    def _pick_color(self):
        col = QColorDialog.getColor(QColor(self._color), self, 'Pick Tag Color')
        if col.isValid():
            self._color = col.name()
            self._refresh_color_btn()

    def _refresh_color_btn(self):
        self._color_btn.setStyleSheet(
            f'background:{self._color};border:1px solid #555;border-radius:4px;'
        )

    @property
    def tag_name(self) -> str:
        return self._tag_name.text().strip()

    @property
    def tag_color(self) -> str:
        return self._color

    @property
    def notes(self) -> str:
        return self._notes.toPlainText().strip()


# ------------------------------------------------------------------ #
#  Report Options Dialog                                               #
# ------------------------------------------------------------------ #

class ReportOptionsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Export HTML Report')
        self.setStyleSheet(_DIALOG_CSS)
        self.setMinimumWidth(380)

        lay = QVBoxLayout(self)

        grp = QGroupBox('Include Sections')
        grp_lay = QVBoxLayout(grp)
        self._chk_artifacts  = QCheckBox('Analyzed Files')
        self._chk_bookmarks  = QCheckBox('Bookmarks & Tags')
        self._chk_iocs       = QCheckBox('IOC Summary')
        for chk in (self._chk_artifacts, self._chk_bookmarks, self._chk_iocs):
            chk.setChecked(True)
            grp_lay.addWidget(chk)
        lay.addWidget(grp)

        out_row = QHBoxLayout()
        self._out_path = QLineEdit()
        self._out_path.setPlaceholderText('Output file path…')
        browse_btn = QPushButton('Browse…')
        browse_btn.clicked.connect(self._browse_out)
        out_row.addWidget(self._out_path)
        out_row.addWidget(browse_btn)
        lay.addLayout(out_row)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def _browse_out(self):
        path, _ = QFileDialog.getSaveFileName(
            self, 'Save Report', 'report.html', 'HTML Files (*.html)'
        )
        if path:
            self._out_path.setText(path)

    def _validate(self):
        if self._out_path.text().strip():
            self.accept()

    @property
    def output_path(self) -> str:
        return self._out_path.text().strip()

    @property
    def include_artifacts(self) -> bool:
        return self._chk_artifacts.isChecked()

    @property
    def include_bookmarks(self) -> bool:
        return self._chk_bookmarks.isChecked()

    @property
    def include_iocs(self) -> bool:
        return self._chk_iocs.isChecked()


# ------------------------------------------------------------------ #
#  Open Case Dialog                                                     #
# ------------------------------------------------------------------ #

class OpenCaseDialog(QDialog):
    def __init__(self, cases: list, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Open Case')
        self.setStyleSheet(_DIALOG_CSS)
        self.setMinimumWidth(400)
        self._selected_id = None

        lay = QVBoxLayout(self)
        lay.addWidget(QLabel('Select case to open:'))

        self._combo = QComboBox()
        for c in cases:
            label = f'[{c.case_number}] {c.examiner or ""}'
            self._combo.addItem(label, c.id)
        lay.addWidget(self._combo)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._ok)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def _ok(self):
        self._selected_id = self._combo.currentData()
        self.accept()

    @property
    def selected_case_id(self) -> int | None:
        return self._selected_id
