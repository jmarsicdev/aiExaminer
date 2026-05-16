"""Left-panel QTreeWidget: Cases hierarchy + Bookmarks section."""

from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QMenu, QMessageBox
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon, QColor, QBrush


_CSS = """
    QTreeWidget {
        background: #16213e;
        color: #e0e0e0;
        border: none;
        font-size: 13px;
    }
    QTreeWidget::item:selected { background: #0f3460; color: #4ecca3; }
    QTreeWidget::item:hover    { background: #1e1e3a; }
    QHeaderView::section { background: #0f3460; color: #4ecca3; padding: 4px; }
"""

_CASE_ROLE     = Qt.ItemDataRole.UserRole + 1
_EVIDENCE_ROLE = Qt.ItemDataRole.UserRole + 2
_BOOKMARK_ROLE = Qt.ItemDataRole.UserRole + 3


class CasePanel(QTreeWidget):
    """
    Emits:
      evidence_selected(evidence_id, image_path)
      bookmark_selected(bookmark_id, evidence_id, file_path)
      open_image_requested(image_path)
    """
    evidence_selected   = pyqtSignal(int, str)   # evidence_id, image_path
    bookmark_selected   = pyqtSignal(int, int, str)  # bookmark_id, evidence_id, file_path
    open_image_requested = pyqtSignal(str)        # image_path (load into file tree)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(_CSS)
        self.setHeaderLabel('Case Explorer')
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)
        self.itemDoubleClicked.connect(self._on_double_click)

        self._db = None

    def set_db(self, db_manager) -> None:
        self._db = db_manager
        self.refresh()

    def refresh(self) -> None:
        self.clear()
        if not self._db:
            return
        cases = self._db.get_all_cases()
        for case in cases:
            case_item = QTreeWidgetItem([f'[{case.case_number}] {case.examiner or ""}'])
            case_item.setData(0, _CASE_ROLE, case.id)
            case_item.setForeground(0, QBrush(QColor('#4ecca3')))
            self.addTopLevelItem(case_item)

            evidence_list = self._db.get_evidence_for_case(case.id)
            for ev in evidence_list:
                import os
                ev_item = QTreeWidgetItem(case_item, [f'  {os.path.basename(ev.image_path)}'])
                ev_item.setData(0, _EVIDENCE_ROLE, ev.id)
                ev_item.setData(0, Qt.ItemDataRole.UserRole, ev.image_path)
                ev_item.setToolTip(0, ev.image_path)

                bookmarks = self._db.get_bookmarks(ev.id)
                for bm in bookmarks:
                    color = bm.tag_color or '#FFDD00'
                    bm_item = QTreeWidgetItem(ev_item, [f'    ★ {bm.tag_name or bm.file_path}'])
                    bm_item.setData(0, _BOOKMARK_ROLE, bm.id)
                    bm_item.setData(0, _EVIDENCE_ROLE, ev.id)
                    bm_item.setData(0, Qt.ItemDataRole.UserRole, bm.file_path)
                    bm_item.setForeground(0, QBrush(QColor(color)))
                    bm_item.setToolTip(0, f'{bm.file_path}\n{bm.notes or ""}')

            case_item.setExpanded(True)

    # ------------------------------------------------------------------ #
    #  Slots                                                                #
    # ------------------------------------------------------------------ #

    def _on_double_click(self, item: QTreeWidgetItem, column: int) -> None:
        ev_id = item.data(0, _EVIDENCE_ROLE)
        bm_id = item.data(0, _BOOKMARK_ROLE)
        path  = item.data(0, Qt.ItemDataRole.UserRole)

        if bm_id is not None and ev_id is not None and path:
            self.bookmark_selected.emit(bm_id, ev_id, path)
        elif ev_id is not None and path:
            self.open_image_requested.emit(path)

    def _context_menu(self, pos) -> None:
        item = self.itemAt(pos)
        if not item:
            return

        ev_id = item.data(0, _EVIDENCE_ROLE)
        bm_id = item.data(0, _BOOKMARK_ROLE)
        path  = item.data(0, Qt.ItemDataRole.UserRole)

        menu = QMenu(self)
        menu.setStyleSheet('QMenu { background:#16213e; color:#e0e0e0; }'
                           'QMenu::item:selected { background:#0f3460; }')

        if bm_id is not None:
            go_act = menu.addAction('Go to Bookmark')
            go_act.triggered.connect(lambda: self.bookmark_selected.emit(bm_id, ev_id, path))
            del_act = menu.addAction('Delete Bookmark')
            del_act.triggered.connect(lambda: self._delete_bookmark(bm_id))

        elif ev_id is not None:
            open_act = menu.addAction('Open in File Tree')
            open_act.triggered.connect(lambda: self.open_image_requested.emit(path))

        menu.exec(self.mapToGlobal(pos))

    def _delete_bookmark(self, bm_id: int) -> None:
        if not self._db:
            return
        reply = QMessageBox.question(
            self, 'Delete Bookmark',
            'Remove this bookmark from the database?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._db.delete_bookmark(bm_id)
            self.refresh()
