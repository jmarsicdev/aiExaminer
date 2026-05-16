"""
Case dashboard — summary of case activity and top-scoring files.
"""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QPushButton, QFrame,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QBrush

_BG     = "#1a1a2e"
_CARD   = "#16213e"
_BORDER = "#0f3460"
_ACCENT = "#4ecca3"
_FG     = "#e0e0e0"


def _stat_card(title: str, value: str, color: str = _ACCENT) -> QFrame:
    """A small rounded card showing a stat number."""
    card = QFrame()
    card.setStyleSheet(
        f"QFrame {{ background:{_CARD}; border:1px solid {_BORDER};"
        f"border-radius:8px; padding:12px; }}"
    )
    lay = QVBoxLayout(card)
    lay.setSpacing(4)
    num = QLabel(value)
    num.setStyleSheet(f"color:{color}; font-size:28px; font-weight:bold; border:none;")
    num.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lbl = QLabel(title)
    lbl.setStyleSheet(f"color:#aaa; font-size:11px; border:none;")
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lay.addWidget(num)
    lay.addWidget(lbl)
    return card


class CaseDashboard(QDialog):
    """
    Displays aggregated case stats and top-scoring files.
    file_selected is emitted when user double-clicks a row (with file path).
    """
    file_selected = pyqtSignal(str)

    def __init__(self, db_manager, case_id: int, score_map: dict, parent=None):
        """
        db_manager : DatabaseManager instance
        case_id    : current case ID
        score_map  : dict[path → ScoreResult] from the main window
        """
        super().__init__(parent)
        self.setWindowTitle("Case Dashboard")
        self.resize(900, 580)
        self.setStyleSheet(f"QDialog {{ background:{_BG}; }} QLabel {{ color:{_FG}; }}")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(12)

        # ── Title ──────────────────────────────────────────────────────
        title = QLabel("Case Dashboard")
        title.setStyleSheet(f"color:{_ACCENT}; font-size:18px; font-weight:bold;")
        lay.addWidget(title)

        # ── Gather stats ───────────────────────────────────────────────
        artifacts = db_manager.get_artifacts_for_case(case_id)
        bookmarks = []
        for ev in db_manager.get_evidence_for_case(case_id):
            bookmarks.extend(db_manager.get_bookmarks(ev.id))

        total_scored   = len(score_map)
        critical_count = sum(1 for sr in score_map.values() if sr and sr.tier == "Critical")
        high_count     = sum(1 for sr in score_map.values() if sr and sr.tier == "High")
        tagged_count   = len(bookmarks)
        analyzed_count = len(artifacts)

        # ── Stat cards row ─────────────────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.addWidget(_stat_card("Files Scored",    str(total_scored),   _ACCENT))
        cards_row.addWidget(_stat_card("Critical",        str(critical_count), "#b71c1c"))
        cards_row.addWidget(_stat_card("High",            str(high_count),     "#e65100"))
        cards_row.addWidget(_stat_card("Tagged",          str(tagged_count),   "#f57f17"))
        cards_row.addWidget(_stat_card("AI Analyzed",     str(analyzed_count), "#1565c0"))
        lay.addLayout(cards_row)

        # ── Top 10 critical files ──────────────────────────────────────
        lbl = QLabel("Top 10 Highest-Scoring Files  (double-click to open)")
        lbl.setStyleSheet("color:#aaa; font-size:12px;")
        lay.addWidget(lbl)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["File Path", "Score", "Tier"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setStyleSheet(
            f"QTableWidget {{ background:{_CARD}; color:{_FG}; border:1px solid {_BORDER};"
            f"gridline-color:{_BORDER}; }}"
            f"QHeaderView::section {{ background:{_BORDER}; color:{_ACCENT}; padding:4px; border:none; }}"
        )
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.doubleClicked.connect(self._on_row_double_click)
        lay.addWidget(self._table)

        self._populate_top(score_map)

        # ── Close button ───────────────────────────────────────────────
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(
            f"QPushButton {{ background:{_BORDER}; color:{_ACCENT}; border:none;"
            f"border-radius:4px; padding:6px 20px; }}"
        )
        close_btn.clicked.connect(self.accept)
        lay.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)

    def _populate_top(self, score_map: dict):
        _TIER_COLOR = {
            "Critical": "#b71c1c", "High": "#e65100",
            "Medium": "#f57f17",   "Low": "#1565c0", "Noise": "#424242",
        }
        top = sorted(
            [(p, sr) for p, sr in score_map.items() if sr],
            key=lambda x: -x[1].score
        )[:10]
        for path, sr in top:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(path))
            score_item = QTableWidgetItem(str(sr.score))
            score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 1, score_item)
            tier_item = QTableWidgetItem(sr.tier)
            tier_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            color = _TIER_COLOR.get(sr.tier, "#e0e0e0")
            tier_item.setForeground(QBrush(QColor(color)))
            self._table.setItem(row, 2, tier_item)

    def _on_row_double_click(self, index):
        path_item = self._table.item(index.row(), 0)
        if path_item:
            self.file_selected.emit(path_item.text())
