"""Performant hex viewer — only paints visible rows using QPainter."""

from PyQt6.QtWidgets import QAbstractScrollArea
from PyQt6.QtCore import Qt, QRect, QSize
from PyQt6.QtGui import QPainter, QColor, QFont, QFontMetrics


_BYTES_PER_ROW = 16
_HEX_BG        = QColor('#1a1a2e')
_HEADER_BG     = QColor('#0f3460')
_ROW_ALT_BG    = QColor('#1e1e3a')
_TEXT_NORMAL   = QColor('#e0e0e0')
_TEXT_OFFSET   = QColor('#4ecca3')
_TEXT_ASCII    = QColor('#aaaaaa')
_TEXT_ZERO     = QColor('#444466')
_SEL_BG        = QColor('#264f78')
_SEARCH_BG     = QColor('#7d4000')


class HexViewer(QAbstractScrollArea):
    """
    Displays arbitrary binary data as hex + ASCII.
    Call set_data(bytes) to load content.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: bytes = b''
        self._sel_start: int = -1
        self._sel_end:   int = -1
        self._hits: list[int] = []  # search hit byte offsets

        font = QFont('Monospace', 10)
        font.setStyleHint(QFont.StyleHint.TypeWriter)
        self.setFont(font)

        self._fm = QFontMetrics(font)
        self._char_w = self._fm.horizontalAdvance('F')
        self._row_h  = self._fm.height() + 4

        # Column pixel offsets (computed once in _recalc_layout)
        self._off_x     = 0
        self._hex_x     = 0
        self._ascii_x   = 0
        self._total_w   = 0
        self._header_h  = self._row_h + 4

        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.viewport().setAutoFillBackground(False)
        self._recalc_layout()

    # ------------------------------------------------------------------ #
    #  Public API                                                           #
    # ------------------------------------------------------------------ #

    def set_data(self, data: bytes) -> None:
        self._data = data if data else b''
        self._sel_start = self._sel_end = -1
        self._hits = []
        self._update_scrollbars()
        self.viewport().update()

    def highlight_hits(self, offsets: list[int]) -> None:
        self._hits = offsets
        self.viewport().update()

    def goto_offset(self, byte_offset: int) -> None:
        row = byte_offset // _BYTES_PER_ROW
        self.verticalScrollBar().setValue(row)
        self.viewport().update()

    # ------------------------------------------------------------------ #
    #  Layout                                                               #
    # ------------------------------------------------------------------ #

    def _recalc_layout(self) -> None:
        cw = self._char_w
        # offset col: 8 hex chars + 2 spaces
        self._off_x  = 4
        off_w = cw * 10
        # hex col: 16 × (2 hex + 1 space) + 1 extra space for mid-gap
        self._hex_x  = self._off_x + off_w
        hex_w = cw * (_BYTES_PER_ROW * 3 + 1)
        # ascii col: 16 chars
        self._ascii_x = self._hex_x + hex_w + cw
        ascii_w = cw * _BYTES_PER_ROW
        self._total_w = self._ascii_x + ascii_w + 8

    def _update_scrollbars(self) -> None:
        total_rows = max(0, (len(self._data) + _BYTES_PER_ROW - 1) // _BYTES_PER_ROW)
        vh = self.viewport().height() - self._header_h
        visible_rows = max(1, vh // self._row_h)
        vbar = self.verticalScrollBar()
        vbar.setRange(0, max(0, total_rows - visible_rows))
        vbar.setPageStep(visible_rows)
        vbar.setSingleStep(1)

        hbar = self.horizontalScrollBar()
        hbar.setRange(0, max(0, self._total_w - self.viewport().width()))
        hbar.setSingleStep(self._char_w)

    def resizeEvent(self, event):
        self._update_scrollbars()
        super().resizeEvent(event)

    # ------------------------------------------------------------------ #
    #  Painting                                                             #
    # ------------------------------------------------------------------ #

    def paintEvent(self, event):
        p = QPainter(self.viewport())
        p.setFont(self.font())
        vp = self.viewport().rect()
        p.fillRect(vp, _HEX_BG)

        if not self._data:
            p.setPen(QColor('#555566'))
            p.drawText(vp, Qt.AlignmentFlag.AlignCenter, 'No data loaded')
            return

        scroll_top  = self.verticalScrollBar().value()
        scroll_left = self.horizontalScrollBar().value()
        dx = -scroll_left

        # Header row
        header_rect = QRect(0, 0, vp.width(), self._header_h)
        p.fillRect(header_rect, _HEADER_BG)
        p.setPen(_TEXT_OFFSET)
        p.drawText(self._off_x + dx, self._fm.ascent() + 2, 'Offset')
        for col in range(_BYTES_PER_ROW):
            hex_xc = self._hex_x + col * self._char_w * 3 + dx
            if col == 8:
                hex_xc += self._char_w
            p.drawText(hex_xc, self._fm.ascent() + 2, f'{col:02X}')
        p.setPen(_TEXT_ASCII)
        p.drawText(self._ascii_x + dx, self._fm.ascent() + 2, '0123456789ABCDEF')

        # Visible rows
        vh = vp.height() - self._header_h
        visible_rows = (vh // self._row_h) + 2
        hit_set = set(self._hits)

        for row_idx in range(visible_rows):
            abs_row = scroll_top + row_idx
            byte_offset = abs_row * _BYTES_PER_ROW
            if byte_offset >= len(self._data):
                break

            y_top = self._header_h + row_idx * self._row_h
            y_text = y_top + self._fm.ascent() + 2
            row_rect = QRect(0, y_top, vp.width(), self._row_h)

            # Alternating row background
            if abs_row % 2 == 1:
                p.fillRect(row_rect, _ROW_ALT_BG)

            chunk = self._data[byte_offset: byte_offset + _BYTES_PER_ROW]

            # Offset column
            p.setPen(_TEXT_OFFSET)
            p.drawText(self._off_x + dx, y_text, f'{byte_offset:08X}')

            # Hex + ASCII columns
            for col, byte_val in enumerate(chunk):
                abs_byte = byte_offset + col
                hex_xc = self._hex_x + col * self._char_w * 3 + dx
                if col >= 8:
                    hex_xc += self._char_w  # mid-gap

                # Background for selection / hit
                cell_rect = QRect(int(hex_xc), y_top, self._char_w * 2, self._row_h)
                if (self._sel_start <= abs_byte <= self._sel_end):
                    p.fillRect(cell_rect, _SEL_BG)
                elif abs_byte in hit_set:
                    p.fillRect(cell_rect, _SEARCH_BG)

                # Hex text
                if byte_val == 0:
                    p.setPen(_TEXT_ZERO)
                else:
                    p.setPen(_TEXT_NORMAL)
                p.drawText(hex_xc, y_text, f'{byte_val:02X}')

                # ASCII column
                asc_xc = self._ascii_x + col * self._char_w + dx
                if 0x20 <= byte_val < 0x7F:
                    p.setPen(_TEXT_ASCII)
                    p.drawText(asc_xc, y_text, chr(byte_val))
                else:
                    p.setPen(_TEXT_ZERO)
                    p.drawText(asc_xc, y_text, '.')

        p.end()

    def scrollContentsBy(self, dx, dy):
        self.viewport().update()
