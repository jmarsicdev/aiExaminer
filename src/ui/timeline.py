"""
Timeline view — plots file timestamps (mtime) on a horizontal scatter chart.

Each dot is a file; clicking a dot emits file_selected(path) signal so the
caller can highlight that file in the tree.
"""
from __future__ import annotations
from datetime import datetime

from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QHBoxLayout, QPushButton
from PyQt6.QtCore import pyqtSignal


# Colour palette matching app dark theme
_BG      = "#1a1a2e"
_FG      = "#e0e0e0"
_ACCENT  = "#4ecca3"
_DOT_REG = "#4ecca3"
_DOT_DEL = "#e65100"   # deleted files in orange
_GRID    = "#0f3460"


class TimelineDialog(QDialog):
    """
    Shows a scrollable scatter timeline of file modification times.

    file_selected is emitted with the file path when user clicks a dot.
    """
    file_selected = pyqtSignal(str)

    def __init__(self, entries: list[dict], parent=None):
        """
        entries: list of dicts, each with at minimum:
            'path'  : str
            'mtime' : str | None  (e.g. "2023-04-15 10:23:11")
            'name'  : str
            'type'  : str         ('File' or 'Folder')
            'is_deleted': bool    (optional, default False)
        """
        super().__init__(parent)
        self.setWindowTitle("File Timeline")
        self.resize(1100, 520)
        self.setStyleSheet(f"QDialog {{ background:{_BG}; }} QLabel {{ color:{_FG}; }}")

        self._entries = [e for e in entries
                         if e.get("type") != "Folder" and e.get("mtime")]
        self._paths   = [e["path"] for e in self._entries]

        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        # ── Header ───────────────────────────────────────────────────
        hdr = QHBoxLayout()
        title = QLabel(f"File Timeline  —  {len(self._entries)} files with timestamps")
        title.setStyleSheet(f"color:{_ACCENT}; font-size:14px; font-weight:bold;")
        hdr.addWidget(title)
        hdr.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(
            f"QPushButton {{ background:#0f3460; color:{_ACCENT}; border:none;"
            f"border-radius:4px; padding:4px 12px; }}"
        )
        close_btn.clicked.connect(self.accept)
        hdr.addWidget(close_btn)
        lay.addLayout(hdr)

        if not self._entries:
            lay.addWidget(QLabel("No files with timestamps found."))
            return

        # ── Plot ─────────────────────────────────────────────────────
        self._build_plot(lay)

    def _parse_dt(self, s: str) -> datetime | None:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return None

    def _build_plot(self, parent_layout):
        import matplotlib
        matplotlib.use("QtAgg")
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg

        fig, ax = plt.subplots(figsize=(12, 4))
        fig.patch.set_facecolor(_BG)
        ax.set_facecolor(_BG)

        dates, ys, colors, paths = [], [], [], []
        for i, e in enumerate(self._entries):
            dt = self._parse_dt(e["mtime"])
            if dt is None:
                continue
            dates.append(dt)
            ys.append(0)
            colors.append(_DOT_DEL if e.get("is_deleted") else _DOT_REG)
            paths.append(e["path"])

        sc = ax.scatter(dates, ys, c=colors, s=30, alpha=0.7, picker=5)

        ax.set_yticks([])
        ax.set_xlabel("Modification Time", color=_FG)
        ax.tick_params(colors=_FG, labelcolor=_FG)
        ax.spines[:].set_color(_GRID)
        ax.xaxis.label.set_color(_FG)
        fig.autofmt_xdate()
        fig.tight_layout()

        self._sc_paths = paths

        canvas = FigureCanvasQTAgg(fig)
        canvas.mpl_connect("pick_event", self._on_pick)
        parent_layout.addWidget(canvas)

        self._hover_label = QLabel("")
        self._hover_label.setStyleSheet(f"color:{_ACCENT}; font-size:11px;")
        parent_layout.addWidget(self._hover_label)

    def _on_pick(self, event):
        idx = event.ind[0] if hasattr(event, "ind") and len(event.ind) else None
        if idx is not None and idx < len(self._sc_paths):
            path = self._sc_paths[idx]
            self._hover_label.setText(path)
            self.file_selected.emit(path)
