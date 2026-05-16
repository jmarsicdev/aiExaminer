"""Main application window — 3-pane layout wiring all components."""

import os
import json
import shutil
import struct
import subprocess
import tempfile
import webbrowser

from PyQt6.QtWidgets import (
    QMainWindow, QTreeWidget, QTreeWidgetItem, QFileDialog,
    QVBoxLayout, QHBoxLayout, QWidget, QMenu, QSplitter,
    QStatusBar, QMessageBox, QApplication, QLabel, QToolBar,
    QProgressBar, QHeaderView, QDialog, QTextEdit, QTableWidget,
    QTableWidgetItem, QAbstractItemView, QSpinBox, QDialogButtonBox,
    QCheckBox, QFormLayout, QScrollArea, QPushButton, QLineEdit, QGridLayout,
)
from PyQt6.QtCore import Qt, QPoint, QThread, pyqtSignal, QSize, QTimer, QSettings
from PyQt6.QtGui import QAction, QFont, QColor, QBrush, QPixmap, QDragEnterEvent, QDropEvent

from src.core.image_parser import ImageParser, EWFNotSupportedError
from src.core.local_parser import LocalParser
from src.core.ntfs_raw_parser import RawNTFSParser
from src.db.manager import DatabaseManager
from src.utils.crypto import calculate_hashes
from src.utils.report import generate as generate_report
from src.ai.entity_extractor import EntityExtractor
import src.ai.relevance_scorer as relevance_mod
import src.ai.entropy_analyzer as entropy_mod

from src.ui.preview_pane import PreviewPane
from src.ui.case_panel import CasePanel
from src.ui.search_bar import SearchBar, SearchWorker
from src.ui.timeline import TimelineDialog
from src.ui.dialogs import (
    NewCaseDialog, BookmarkDialog, ReportOptionsDialog, OpenCaseDialog,
)


# ------------------------------------------------------------------ #
#  Styling constants                                                    #
# ------------------------------------------------------------------ #

_TREE_CSS = """
    QTreeWidget {
        background: #1a1a2e; color: #e0e0e0;
        border: none; font-size: 12px;
        alternate-background-color: #1e1e3a;
    }
    QTreeWidget::item:selected { background: #0f3460; color: #4ecca3; }
    QTreeWidget::item:hover    { background: #1e1e3a; }
    QHeaderView::section {
        background: #0f3460; color: #4ecca3;
        padding: 5px; border: none; font-size: 12px;
    }
"""
_TOOLBAR_CSS = """
    QToolBar { background: #16213e; border-bottom: 1px solid #0f3460; spacing: 4px; }
    QToolButton {
        background: #0f3460; color: #4ecca3; border: none;
        border-radius: 4px; padding: 5px 10px; font-size: 12px;
    }
    QToolButton:hover { background: #1a4a8a; }
"""
_WINDOW_CSS = """
    QMainWindow { background: #1a1a2e; }
    QMenuBar { background: #16213e; color: #e0e0e0; }
    QMenuBar::item:selected { background: #0f3460; color: #4ecca3; }
    QMenu { background: #16213e; color: #e0e0e0; border: 1px solid #0f3460; }
    QMenu::item:selected { background: #0f3460; color: #4ecca3; }
    QSplitter::handle { background: #0f3460; }
    QDialog { background: #1a1a2e; color: #e0e0e0; }
    QLabel  { color: #e0e0e0; }
    QSpinBox { background: #16213e; color: #e0e0e0; border: 1px solid #0f3460;
               border-radius:4px; padding:3px; }
    QCheckBox { color: #e0e0e0; }
"""
_MENU_CSS = ('QMenu { background:#16213e; color:#e0e0e0; border:1px solid #0f3460; }'
             'QMenu::item:selected { background:#0f3460; color:#4ecca3; }')


# ------------------------------------------------------------------ #
#  Tree column indices                                                  #
# ------------------------------------------------------------------ #

_COL_NAME    = 0
_COL_TYPE    = 1
_COL_SIZE    = 2
_COL_SCORE   = 3   # forensic relevance score
_COL_MD5     = 4
_COL_PATH    = 5
_COL_DELETED = 6
_COL_MTIME   = 7

_ENTRY_ROLE = Qt.ItemDataRole.UserRole
_PLACEHOLDER_ROLE = Qt.ItemDataRole.UserRole + 1

# Extension → expected magic-byte category for mismatch detection
_EXT_TO_CATEGORY: dict[str, str] = {
    '.jpg': 'image',  '.jpeg': 'image', '.png': 'image',  '.gif': 'image',
    '.bmp': 'image',  '.tiff': 'image', '.tif': 'image',  '.webp': 'image',
    '.exe': 'executable', '.dll': 'executable', '.sys': 'executable',
    '.com': 'executable', '.scr': 'executable', '.msi': 'executable',
    '.pdf': 'document', '.doc': 'document', '.docx': 'document',
    '.xls': 'document', '.xlsx': 'document', '.ppt': 'document', '.pptx': 'document',
    '.xml': 'document', '.html': 'document', '.htm': 'document',
    '.zip': 'archive', '.rar': 'archive', '.7z': 'archive',
    '.tar': 'archive', '.gz': 'archive',  '.bz2': 'archive',
    '.mp3': 'audio',   '.wav': 'audio',   '.flac': 'audio',
    '.mp4': 'video',   '.avi': 'video',   '.mkv': 'video',
    '.py': 'script',   '.js': 'script',   '.bat': 'script', '.ps1': 'script',
    '.log': 'log',
    '.txt': 'text',    '.md': 'text',     '.csv': 'text',
}


# ------------------------------------------------------------------ #
#  Background workers                                                   #
# ------------------------------------------------------------------ #

class AnalysisWorker(QThread):
    result_ready   = pyqtSignal(str, str, str, str, str)
    error_occurred = pyqtSignal(str)
    status_update  = pyqtSignal(str)

    def __init__(self, parser, file_path, nlp=None, cv=None, anomaly=None):
        super().__init__()
        self.parser = parser
        self.file_path = file_path
        self._nlp = nlp
        self._cv  = cv
        self._ano = anomaly
        self.created_nlp = self.created_cv = self.created_ano = None

    def run(self):
        try:
            fname = os.path.basename(self.file_path)
            self.status_update.emit(f'Reading {fname}…')
            content = self.parser.read_file_content(self.file_path)
            if content is None:
                self.error_occurred.emit(f'Could not read: {self.file_path}')
                return

            self.status_update.emit(f'Hashing {fname} ({len(content):,} bytes)…')
            hashes = calculate_hashes(content)
            h_text = f'MD5:    {hashes["md5"]}\nSHA256: {hashes["sha256"]}\n\n'

            ext = os.path.splitext(self.file_path)[1].lower()
            ai_text = ''
            analysis_type = 'None'

            if ext in ('.log', '.csv'):
                self.status_update.emit(f'Running anomaly detection on {fname}…')
                if not self._ano:
                    from src.ai.anomaly.detector import LogAnomalyDetector
                    self._ano = LogAnomalyDetector()
                    self.created_ano = self._ano
                text = content.decode('utf-8', errors='ignore')
                ai_text = self._ano.analyze_logs(text)
                analysis_type = 'Anomaly'

            elif ext == '.pdf':
                self.status_update.emit(f'Extracting PDF text from {fname}…')
                from src.core.pdf_extractor import PDFExtractor
                pdf_text = PDFExtractor().extract(content)
                if not pdf_text.strip():
                    ai_text = 'No extractable text found in PDF.'
                    analysis_type = 'PDF'
                else:
                    self.status_update.emit(f'Running NLP analysis on {fname}…')
                    if not self._nlp:
                        from src.ai.nlp.analyzer import NLPAnalyzer
                        self._nlp = NLPAnalyzer()
                        self.created_nlp = self._nlp
                    ai_text = self._nlp.analyze_text(pdf_text)
                    # NER pass on PDF text
                    try:
                        from src.ai.nlp.ner import SpaCyNER
                        ner_ents = SpaCyNER().extract(pdf_text, max_chars=10_000)
                        if ner_ents:
                            grouped = SpaCyNER().summarise(ner_ents)
                            ner_lines = '\n'.join(
                                f'  {lbl}: {", ".join(vals[:8])}'
                                for lbl, vals in grouped.items()
                            )
                            ai_text += f'\n\n--- NAMED ENTITIES ---\n{ner_lines}'
                    except Exception:
                        pass
                    analysis_type = 'PDF+NLP'

            elif ext in ('.txt', '.md', '.html', '.xml', '.json'):
                self.status_update.emit(f'Running NLP analysis on {fname}…')
                if not self._nlp:
                    from src.ai.nlp.analyzer import NLPAnalyzer
                    self._nlp = NLPAnalyzer()
                    self.created_nlp = self._nlp
                text = content.decode('utf-8', errors='ignore')
                ai_text = self._nlp.analyze_text(text)
                # NER pass on text
                try:
                    from src.ai.nlp.ner import SpaCyNER
                    ner_ents = SpaCyNER().extract(text, max_chars=10_000)
                    if ner_ents:
                        grouped = SpaCyNER().summarise(ner_ents)
                        ner_lines = '\n'.join(
                            f'  {lbl}: {", ".join(vals[:8])}'
                            for lbl, vals in grouped.items()
                        )
                        ai_text += f'\n\n--- NAMED ENTITIES ---\n{ner_lines}'
                except Exception:
                    pass
                analysis_type = 'NLP'

            elif ext in ('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.tif'):
                self.status_update.emit(f'Running computer vision on {fname}…')
                if not self._cv:
                    from src.ai.cv.detector import CVDetector
                    self._cv = CVDetector()
                    self.created_cv = self._cv
                ai_text = self._cv.analyze_image(content)

                self.status_update.emit(f'Running OCR on {fname}…')
                from src.ai.cv.ocr import OCRExtractor
                ocr_result = OCRExtractor().extract_with_confidence(content)
                if ocr_result['text']:
                    ai_text += (
                        f'\n\n--- OCR TEXT (confidence {ocr_result["confidence"]:.0f}%) ---\n'
                        f'{ocr_result["text"][:2000]}'
                    )
                    # Feed OCR text into entity extractor so IOCs in images surface
                    extractor = EntityExtractor()
                    entities  = extractor.extract_from_bytes(ocr_result['text'].encode())
                    if entities:
                        ai_text += (
                            f'\n\n--- IOCs from OCR ({len(entities)}) ---\n'
                            + '\n'.join(f'  {e.kind}: {e.value}' for e in entities[:20])
                        )
                analysis_type = 'CV+OCR'

            else:
                self.status_update.emit(f'Extracting IOCs and entropy from {fname}…')
                extractor = EntityExtractor()
                entities  = extractor.extract_from_bytes(content)
                ent_result = entropy_mod.analyze(content)
                ai_text = (
                    f'Entropy: {ent_result.overall:.3f} bits/byte — {ent_result.label}\n'
                    f'Entities: {len(entities)}\n' +
                    '\n'.join(f'  {e.kind}: {e.value}' for e in entities[:30])
                )
                analysis_type = 'IOC+Entropy'

            self.result_ready.emit(
                h_text + ai_text, ai_text, analysis_type,
                hashes['md5'], hashes['sha256'],
            )
        except Exception as e:
            self.error_occurred.emit(f'Analysis error: {e}')


class ReportWorker(QThread):
    done  = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, db, case_id, path, inc_art, inc_bm, inc_ioc):
        super().__init__()
        self._db = db; self._case_id = case_id; self._path = path
        self._inc_art = inc_art; self._inc_bm = inc_bm; self._inc_ioc = inc_ioc

    def run(self):
        try:
            generate_report(self._db, self._case_id, self._path,
                            include_artifacts=self._inc_art,
                            include_bookmarks=self._inc_bm,
                            include_iocs=self._inc_ioc)
            self.done.emit(self._path)
        except Exception as e:
            self.error.emit(str(e))


class CarverWorker(QThread):
    carved   = pyqtSignal(object)   # CarvedFile
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(int)

    def __init__(self, parser, path, min_size: int = 512):
        super().__init__()
        self._parser = parser
        self._path   = path
        self._min    = min_size
        self._stop   = False

    def stop(self): self._stop = True

    def run(self):
        from src.core.carver import FileCarver
        count = 0
        try:
            content = self._parser.read_file_content(self._path)
            if not content:
                self.finished.emit(0)
                return
            carver = FileCarver()
            for cf in carver.carve_stream(content, progress_cb=self._prog):
                if self._stop:
                    break
                if cf.size >= self._min:
                    self.carved.emit(cf)
                    count += 1
        except Exception as e:
            print(f'CarverWorker error: {e}')
        self.finished.emit(count)

    def _prog(self, pos, total):
        self.progress.emit(pos, total)


class RelevanceWorker(QThread):
    """
    Score all files for forensic relevance.

    Two-phase: walk the tree collecting file samples sequentially (avoids
    parser thread-safety issues), then score all jobs in parallel using a
    thread pool (CPU-bound entropy / entity / scoring work).
    """
    scored        = pyqtSignal(str, object)   # path, ScoreResult
    mismatch      = pyqtSignal(str, str, str) # path, detected_label, extension
    status_update = pyqtSignal(str)
    finished      = pyqtSignal()

    def __init__(self, parser, root='/'):
        super().__init__()
        self._parser = parser
        self._root   = root
        self._stop   = False

    def stop(self): self._stop = True

    def run(self):
        # ── Phase 1: walk and collect jobs ─────────────────────────────
        self.status_update.emit('Scanning filesystem…')
        jobs: list[dict] = []
        self._collect(self._root, jobs)
        if self._stop or not jobs:
            self.finished.emit()
            return

        total = len(jobs)
        self.status_update.emit(f'Scoring {total} files in parallel…')

        # ── Phase 2: parallel scoring ───────────────────────────────────
        from src.utils.parallel_scorer import score_files_parallel

        def _progress(done: int, _total: int):
            if not self._stop:
                self.status_update.emit(f'Scoring… {done}/{_total} files')

        results = score_files_parallel(jobs, max_workers=4, progress_cb=_progress)

        for path, sr in results:
            if sr and not self._stop:
                self.scored.emit(path, sr)

        self.finished.emit()

    def _collect(self, path: str, out: list, inode=None):
        try:
            for entry in self._parser.list_directory(path, inode=inode):
                if self._stop:
                    return
                if entry['type'] == 'Folder':
                    self.status_update.emit(f'Scanning… {entry["path"]}')
                    self._collect(entry['path'], out, inode=entry.get('inode'))
                else:
                    self._read_and_build(entry, out)
        except Exception:
            pass

    def _read_and_build(self, entry: dict, out: list):
        try:
            self.status_update.emit(f'Reading {entry["name"]}…')
            content = self._parser.read_file_content(entry['path'])
            if not content:
                return
            sample  = content[:65536]
            ent_res = entropy_mod.analyze(sample)
            from src.core.file_type import detect_file_type
            ft       = detect_file_type(sample, entry['name'])
            entities = EntityExtractor().extract_from_bytes(sample)
            out.append({
                'file_path':      entry['path'],
                'file_category':  ft['category'],
                'entropy':        ent_res.overall,
                'entities':       entities,
                'content_sample': sample,
                'is_deleted':     entry.get('is_deleted', False),
                'mtime':          entry.get('mtime'),
            })
            # Flag disguised files: magic-byte category doesn't match extension
            ext = os.path.splitext(entry['name'])[1].lower()
            ext_cat = _EXT_TO_CATEGORY.get(ext)
            if (ext_cat and ft['category'] != 'unknown'
                    and ft['category'] != ext_cat):
                self.mismatch.emit(entry['path'], ft['label'], ext)
        except Exception:
            pass


# ------------------------------------------------------------------ #
#  Main Window                                                          #
# ------------------------------------------------------------------ #

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('aiExaminer — Forensic Analyzer')
        self.resize(1600, 950)
        self.setStyleSheet(_WINDOW_CSS)

        self.parser = None
        self.db_manager = None
        self.current_case_id = None
        self.current_evidence_id = None
        self._ewf_mount_dir = None
        self._worker  = None
        self._search_worker = None
        self._report_worker = None
        self._carver_worker = None
        self._rel_worker    = None
        self._current_file_path = None
        self._nlp = self._cv = self._ano = None
        self._search_results: list = []
        self._score_map: dict[str, object] = {}  # path → ScoreResult
        self._batch_worker = None
        self._settings = QSettings('aiExaminer', 'aiExaminer')

        self._build_ui()
        self._build_menu()
        self._build_toolbar()
        self._connect_signals()
        self.setAcceptDrops(True)

    # ---------------------------------------------------------------- #
    #  Layout                                                            #
    # ---------------------------------------------------------------- #

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_lay = QVBoxLayout(central)
        root_lay.setContentsMargins(0, 0, 0, 0)
        root_lay.setSpacing(0)

        self._search_bar = SearchBar()
        root_lay.addWidget(self._search_bar)

        self._h_split = QSplitter(Qt.Orientation.Horizontal)

        self._case_panel = CasePanel()
        self._case_panel.setMinimumWidth(200)
        self._h_split.addWidget(self._case_panel)

        centre = QWidget()
        c_lay  = QVBoxLayout(centre)
        c_lay.setContentsMargins(0, 0, 0, 0)
        c_lay.setSpacing(0)

        self._tree = QTreeWidget()
        self._tree.setStyleSheet(_TREE_CSS)
        self._tree.setAlternatingRowColors(True)
        self._tree.setColumnCount(8)
        self._tree.setHeaderLabels(
            ['Name', 'Type', 'Size', 'Score', 'MD5', 'Full Path', 'Deleted', 'Modified']
        )
        hdr = self._tree.header()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.setSortingEnabled(True)
        c_lay.addWidget(self._tree)

        self._h_split.addWidget(centre)

        self._preview = PreviewPane()
        self._preview.setMinimumWidth(340)
        self._h_split.addWidget(self._preview)

        self._h_split.setSizes([220, 700, 500])
        root_lay.addWidget(self._h_split)

        self._status = QStatusBar()
        self._status.setStyleSheet(
            'QStatusBar{background:#16213e;color:#aaa;font-size:11px}'
            'QStatusBar::item{border:none}'
        )
        self.setStatusBar(self._status)
        self._status_label   = QLabel('Ready')
        self._status_progress = QProgressBar()
        self._status_progress.setRange(0, 0)
        self._status_progress.setFixedWidth(150)
        self._status_progress.setVisible(False)
        self._status.addWidget(self._status_label)
        self._status.addPermanentWidget(self._status_progress)

    def _build_menu(self):
        mb = self.menuBar()

        case_m = mb.addMenu('Case')
        self._act_new_case   = QAction('New Case…',  self, shortcut='Ctrl+N')
        self._act_open_case  = QAction('Open Case…', self)
        self._act_close_case = QAction('Close Case', self)
        for a in (self._act_new_case, self._act_open_case,
                  case_m.addSeparator(), self._act_close_case):
            if isinstance(a, QAction): case_m.addAction(a)

        file_m = mb.addMenu('File')
        self._act_open_image  = QAction('Open Image…',          self, shortcut='Ctrl+O')
        self._act_open_folder = QAction('Open Logical Folder…', self)
        self._act_export      = QAction('Export Report…',       self, shortcut='Ctrl+R')
        for a in (self._act_open_image, self._act_open_folder,
                  file_m.addSeparator(), self._act_export):
            if isinstance(a, QAction): file_m.addAction(a)
        file_m.addSeparator()
        self._recent_menu = file_m.addMenu('Recent Files')
        self._refresh_recent_menu()

        view_m = mb.addMenu('View')
        self._act_toggle_case  = QAction('Toggle Case Panel', self, checkable=True, checked=True)
        self._act_gallery      = QAction('Image Gallery…', self)
        self._act_timeline     = QAction('File Timeline…', self)
        self._act_dashboard    = QAction('Case Dashboard…', self, shortcut='Ctrl+D')
        for a in (self._act_toggle_case, view_m.addSeparator(),
                  self._act_gallery, self._act_timeline, self._act_dashboard):
            if isinstance(a, QAction): view_m.addAction(a)

        tools_m = mb.addMenu('Tools')
        self._act_run_ai      = QAction('Run AI Analysis',      self, shortcut='Ctrl+A')
        self._act_hash_file   = QAction('Hash Selected File',   self)
        self._act_carve       = QAction('Carve File for Embedded Content…', self)
        self._act_carve_image = QAction('Carve Entire Image / Folder…',     self)
        self._act_score_all   = QAction('Score All Files (Relevance AI)…',  self)
        self._act_batch_ai    = QAction('Analyze All Critical Files…',       self, shortcut='Ctrl+B')
        self._act_browser_art = QAction('Extract Browser Artifacts…',       self)
        self._act_registry    = QAction('Parse Registry Hive…',             self)
        self._act_yara        = QAction('YARA Scan…',           self, shortcut='Ctrl+Y')
        sep = tools_m.addSeparator
        for a in (self._act_run_ai, self._act_hash_file, sep(),
                  self._act_carve, self._act_carve_image, sep(),
                  self._act_score_all, self._act_batch_ai, sep(),
                  self._act_browser_art, self._act_registry, sep(),
                  self._act_yara):
            if isinstance(a, QAction): tools_m.addAction(a)

    def _build_toolbar(self):
        tb = QToolBar('Main')
        tb.setStyleSheet(_TOOLBAR_CSS)
        tb.setMovable(False)
        tb.setIconSize(QSize(16, 16))
        self.addToolBar(tb)
        for a in (self._act_new_case, self._act_open_image, self._act_open_folder,
                  None, self._act_run_ai, self._act_carve_image,
                  self._act_score_all, self._act_yara, self._act_dashboard,
                  None, self._act_export):
            if a is None:
                tb.addSeparator()
            else:
                tb.addAction(a)

    def _connect_signals(self):
        self._act_new_case.triggered.connect(self._new_case)
        self._act_open_case.triggered.connect(self._open_case)
        self._act_close_case.triggered.connect(self._close_case)
        self._act_open_image.triggered.connect(self._open_image_dialog)
        self._act_open_folder.triggered.connect(self._open_folder_dialog)
        self._act_export.triggered.connect(self._export_report)
        self._act_toggle_case.toggled.connect(self._case_panel.setVisible)
        self._act_run_ai.triggered.connect(self._run_ai_analysis)
        self._act_hash_file.triggered.connect(self._hash_selected)
        self._act_carve.triggered.connect(self._carve_selected_file)
        self._act_carve_image.triggered.connect(self._carve_image)
        self._act_score_all.triggered.connect(self._score_all_files)
        self._act_batch_ai.triggered.connect(self._batch_ai_analysis)
        self._act_browser_art.triggered.connect(self._extract_browser_artifacts)
        self._act_registry.triggered.connect(self._parse_registry)
        self._act_gallery.triggered.connect(self._show_gallery)
        self._act_timeline.triggered.connect(self._show_timeline)
        self._act_yara.triggered.connect(self._yara_scan)
        self._act_dashboard.triggered.connect(self._show_dashboard)

        self._tree.itemSelectionChanged.connect(self._on_tree_selection)
        self._tree.customContextMenuRequested.connect(self._tree_context_menu)
        self._tree.itemExpanded.connect(self._on_item_expanded)

        self._search_bar.name_filter_changed.connect(self._apply_name_filter)
        self._search_bar.search_requested.connect(self._start_full_search)
        self._search_bar.search_stopped.connect(self._stop_full_search)

        self._case_panel.open_image_requested.connect(self._load_image)
        self._case_panel.bookmark_selected.connect(self._jump_to_bookmark)

    # ---------------------------------------------------------------- #
    #  Case management                                                   #
    # ---------------------------------------------------------------- #

    def _new_case(self):
        dlg = NewCaseDialog(self)
        if dlg.exec() != dlg.DialogCode.Accepted: return
        self.db_manager = DatabaseManager(dlg.db_path)
        self.current_case_id = self.db_manager.create_case(
            dlg.case_number, dlg.examiner, dlg.description)
        self._case_panel.set_db(self.db_manager)
        self._set_status(f'Case {dlg.case_number} created')

    def _open_case(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Open Case Database', '', 'SQLite DB (*.db)')
        if not path: return
        self.db_manager = DatabaseManager(path)
        cases = self.db_manager.get_all_cases()
        if not cases:
            QMessageBox.information(self, 'Open Case', 'No cases found.'); return
        dlg = OpenCaseDialog(cases, self)
        if dlg.exec() != dlg.DialogCode.Accepted: return
        self.current_case_id = dlg.selected_case_id
        self._case_panel.set_db(self.db_manager)
        case = self.db_manager.get_case_by_id(self.current_case_id)
        self._set_status(f'Opened case: {case.case_number}')

    def _close_case(self):
        self.db_manager = self.current_case_id = self.current_evidence_id = None
        self._case_panel.set_db(None)
        self._set_status('Case closed')

    # ---------------------------------------------------------------- #
    #  Image / folder loading                                            #
    # ---------------------------------------------------------------- #

    def _open_image_dialog(self):
        path, _ = QFileDialog.getOpenFileName(
            self, 'Open Forensic Image', '',
            'All Supported (*.E01 *.e01 *.dd *.raw *.img *.iso *.001);;All Files (*)')
        if path: self._load_image(path)

    def _open_folder_dialog(self):
        path = QFileDialog.getExistingDirectory(self, 'Select Logical Folder')
        if path: self._load_folder(path)

    def _load_folder(self, path: str):
        self._tree.clear(); self._preview.clear(); self._score_map.clear()
        try:
            self.parser = LocalParser(path)
            self._populate_tree_lazy('/', self._tree.invisibleRootItem())
            if self.db_manager and self.current_case_id:
                self.current_evidence_id = self.db_manager.add_evidence(self.current_case_id, path)
            self._add_recent_file(path)
            self._set_status(f'Loaded folder: {path}')
        except Exception as e:
            QMessageBox.critical(self, 'Load Error', str(e))

    def _load_image(self, path: str):
        self._tree.clear(); self._preview.clear(); self._score_map.clear()
        self._set_status(f'Loading {os.path.basename(path)} …')
        QApplication.processEvents()
        try:
            self.parser = ImageParser(path)
            self._populate_tree_lazy('/', self._tree.invisibleRootItem())
            if self.db_manager and self.current_case_id:
                self.current_evidence_id = self.db_manager.add_evidence(self.current_case_id, path)
            self._add_recent_file(path)
            self._set_status(f'Loaded: {path}')
        except EWFNotSupportedError:
            self._load_e01_via_ewfmount(path)
        except Exception as e:
            QMessageBox.critical(self, 'Load Error', str(e))

    def _load_e01_via_ewfmount(self, e01_path: str):
        self._unmount_ewf()
        mount_dir = tempfile.mkdtemp(prefix='aiExaminer_ewf_')
        result = subprocess.run(['ewfmount', e01_path, mount_dir],
                                capture_output=True, text=True)
        if result.returncode != 0:
            shutil.rmtree(mount_dir, ignore_errors=True)
            QMessageBox.critical(self, 'E01 Mount Failed',
                                 f'ewfmount failed:\n{result.stderr.strip()}'); return
        raw_image = os.path.join(mount_dir, 'ewf1')
        if not os.path.exists(raw_image):
            shutil.rmtree(mount_dir, ignore_errors=True)
            QMessageBox.critical(self, 'E01 Mount Failed', 'ewf1 not found'); return
        self._ewf_mount_dir = mount_dir
        self._set_status('E01 mounted — opening filesystem…')
        QApplication.processEvents()
        try:
            self.parser = ImageParser(raw_image)
            self._populate_tree_lazy('/', self._tree.invisibleRootItem())
            if self.db_manager and self.current_case_id:
                self.current_evidence_id = self.db_manager.add_evidence(self.current_case_id, e01_path)
            self._set_status(f'Loaded E01: {os.path.basename(e01_path)}')
        except Exception:
            self._try_raw_ntfs_fallback(e01_path, raw_image, mount_dir)

    def _try_raw_ntfs_fallback(self, e01_path: str, raw_image: str, mount_dir: str):
        self._set_status('Trying raw NTFS parser…'); QApplication.processEvents()
        try:
            with open(raw_image, 'rb') as f: mbr = f.read(512)
            part_off = 0
            if mbr[510:512] == b'\x55\xaa':
                for i in range(4):
                    ent = mbr[446 + i * 16: 462 + i * 16]
                    lba = struct.unpack_from('<I', ent, 8)[0]
                    if ent[4] and lba:
                        part_off = lba * 512; break
            self.parser = RawNTFSParser(raw_image, partition_offset=part_off)
            self._populate_tree_lazy('/', self._tree.invisibleRootItem())
            if self.db_manager and self.current_case_id:
                self.current_evidence_id = self.db_manager.add_evidence(self.current_case_id, e01_path)
            self._set_status(f'Loaded E01 (raw NTFS): {os.path.basename(e01_path)} — VBR missing, using built-in parser')
        except Exception as e:
            QMessageBox.critical(self, 'Parse Failed', f'All parsers failed:\n{e}')
            self._unmount_ewf()

    def _unmount_ewf(self):
        if self._ewf_mount_dir and os.path.isdir(self._ewf_mount_dir):
            subprocess.run(['fusermount', '-u', self._ewf_mount_dir], capture_output=True)
            shutil.rmtree(self._ewf_mount_dir, ignore_errors=True)
        self._ewf_mount_dir = None

    def closeEvent(self, event):
        self._unmount_ewf(); super().closeEvent(event)

    # ---------------------------------------------------------------- #
    #  File tree                                                         #
    # ---------------------------------------------------------------- #

    def _populate_tree_lazy(self, path: str, parent: QTreeWidgetItem, inode=None):
        if not self.parser: return
        entries = self.parser.list_directory_safe(path, inode=inode)
        for i, entry in enumerate(entries):
            item = self._make_tree_item(entry)
            parent.addChild(item)
            if entry['type'] == 'Folder':
                ph = QTreeWidgetItem(['Loading…'])
                ph.setData(0, _PLACEHOLDER_ROLE, True)
                item.addChild(ph)
            if i % 200 == 0: QApplication.processEvents()

    def _on_item_expanded(self, item: QTreeWidgetItem):
        if item.childCount() != 1: return
        child = item.child(0)
        if not child.data(0, _PLACEHOLDER_ROLE): return
        entry = item.data(0, _ENTRY_ROLE)
        if not entry: return
        item.removeChild(child)
        # Prefer inode-based listing — more reliable for deep NTFS paths
        self._populate_tree_lazy(entry['path'], item, inode=entry.get('inode'))
        # Apply any pending score from score_map
        self._apply_scores_to_item(item)

    def _make_tree_item(self, entry: dict) -> QTreeWidgetItem:
        size_str = f'{entry["size"]:,}' if entry.get('size') else '—'
        deleted  = 'Yes' if entry.get('is_deleted') else ''
        mtime    = str(entry.get('mtime') or '')
        sr = self._score_map.get(entry['path'])
        score_str = str(sr.score) if sr else ''
        item = QTreeWidgetItem([
            entry['name'], entry['type'], size_str,
            score_str, '', entry['path'], deleted, mtime,
        ])
        item.setData(0, _ENTRY_ROLE, entry)
        if deleted:
            for c in range(8): item.setForeground(c, QColor('#ef5350'))
        elif entry['type'] == 'Folder':
            item.setForeground(0, QColor('#4ecca3'))
        if sr:
            self._apply_score_style(item, sr)
        return item

    def _apply_score_style(self, item: QTreeWidgetItem, sr):
        color = QColor(sr.badge_color)
        item.setForeground(_COL_SCORE, color)
        item.setText(_COL_SCORE, str(sr.score))

    def _apply_scores_to_item(self, parent: QTreeWidgetItem):
        for i in range(parent.childCount()):
            child = parent.child(i)
            path = child.text(_COL_PATH)
            if path in self._score_map:
                self._apply_score_style(child, self._score_map[path])

    def _apply_name_filter(self, text: str):
        text = text.lower()
        self._filter_recursive(self._tree.invisibleRootItem(), text)

    def _filter_recursive(self, parent: QTreeWidgetItem, text: str) -> bool:
        any_vis = False
        for i in range(parent.childCount()):
            child = parent.child(i)
            cv = self._filter_recursive(child, text)
            nm = text in child.text(0).lower() if text else True
            vis = nm or cv
            child.setHidden(not vis)
            any_vis = any_vis or vis
        return any_vis

    # ---------------------------------------------------------------- #
    #  Selection & preview                                               #
    # ---------------------------------------------------------------- #

    def _on_tree_selection(self):
        items = self._tree.selectedItems()
        if not items or not self.parser: return
        item  = items[0]
        entry = item.data(0, _ENTRY_ROLE)
        if not entry or entry['type'] == 'Folder': return
        self._current_file_path = entry['path']
        self._preview.load_file(self.parser, entry['path'], entry)
        sr = self._score_map.get(entry['path'])
        if sr:
            self._preview.show_score_card(relevance_mod.render_html(sr))

    # ---------------------------------------------------------------- #
    #  Context menu                                                      #
    # ---------------------------------------------------------------- #

    def _tree_context_menu(self, pos: QPoint):
        item  = self._tree.itemAt(pos)
        if not item: return
        entry = item.data(0, _ENTRY_ROLE)
        if not entry: return

        menu = QMenu(self)
        menu.setStyleSheet(_MENU_CSS)

        if entry['type'] != 'Folder':
            menu.addAction('Run AI Analysis',       self._run_ai_analysis)
            menu.addAction('Calculate Hashes',      self._hash_selected)
            menu.addAction('Carve File for Embedded Content', self._carve_selected_file)
            menu.addSeparator()
            menu.addAction('Extract Browser Artifacts', self._extract_browser_artifacts)
            menu.addAction('Parse as Registry Hive',    self._parse_registry)
            menu.addSeparator()

            # ── Evidence tagging ───────────────────────────────────────
            tag_menu = QMenu('Tag File', self)
            tag_menu.setStyleSheet(_MENU_CSS)
            _TAGS = [
                ('Key Evidence', '#b71c1c'),
                ('Reviewed',     '#1b5e20'),
                ('Excluded',     '#424242'),
            ]
            for tag_name, tag_color in _TAGS:
                tag_menu.addAction(
                    tag_name,
                    lambda tn=tag_name, tc=tag_color: self._tag_file(entry, item, tn, tc)
                )
            tag_menu.addSeparator()
            tag_menu.addAction('Remove Tag', lambda: self._remove_tag(entry, item))
            menu.addMenu(tag_menu)

            menu.addAction('Add Bookmark…',         lambda: self._add_bookmark(entry))
            menu.addAction('Export File…',          lambda: self._export_file(entry))

        menu.exec(self._tree.viewport().mapToGlobal(pos))

    # ---------------------------------------------------------------- #
    #  Hashing                                                           #
    # ---------------------------------------------------------------- #

    def _hash_selected(self):
        if not self._current_file_path or not self.parser: return
        self._set_status('Hashing…'); QApplication.processEvents()
        try:
            content = self.parser.read_file_content(self._current_file_path)
            if not content: self._set_status('Could not read file'); return
            hashes = calculate_hashes(content)
            items = self._tree.selectedItems()
            if items: items[0].setText(_COL_MD5, hashes['md5'])
            self._set_status(f'MD5: {hashes["md5"]}  SHA256: {hashes["sha256"][:16]}…')
        except Exception as e:
            self._set_status(f'Hash error: {e}')

    # ---------------------------------------------------------------- #
    #  AI Analysis                                                       #
    # ---------------------------------------------------------------- #

    def _run_ai_analysis(self):
        if not self._current_file_path or not self.parser: return
        if self._worker and self._worker.isRunning():
            self._set_status('Analysis already running…'); return
        self._preview.show_ai_result('<p style="color:#aaa">Analyzing…</p>')
        self._set_status('Running AI analysis…')
        self._status_progress.setVisible(True)
        self._tree.setEnabled(False)
        self._worker = AnalysisWorker(self.parser, self._current_file_path,
                                       self._nlp, self._cv, self._ano)
        self._worker.result_ready.connect(self._on_analysis_done)
        self._worker.error_occurred.connect(self._on_analysis_error)
        self._worker.status_update.connect(self._set_status)
        self._worker.start()

    def _on_analysis_done(self, display, ai_text, atype, md5, sha256):
        self._tree.setEnabled(True); self._status_progress.setVisible(False)
        if self._worker:
            if self._worker.created_nlp: self._nlp = self._worker.created_nlp
            if self._worker.created_cv:  self._cv  = self._worker.created_cv
            if self._worker.created_ano: self._ano = self._worker.created_ano
        self._preview.show_ai_result(
            f'<pre style="color:#e0e0e0;font-size:12px;white-space:pre-wrap">{display}</pre>')
        self._set_status(f'Analysis done — type: {atype}')
        if self.db_manager and self.current_evidence_id:
            self.db_manager.add_artifact(self.current_evidence_id,
                                         self._current_file_path,
                                         md5, sha256, atype, ai_text)
            self._case_panel.refresh()

    def _on_analysis_error(self, msg):
        self._tree.setEnabled(True); self._status_progress.setVisible(False)
        self._preview.show_ai_result(f'<p style="color:#ef5350">Error: {msg}</p>')
        self._set_status(f'Analysis error: {msg}')

    # ---------------------------------------------------------------- #
    #  File Carving                                                      #
    # ---------------------------------------------------------------- #

    def _carve_selected_file(self):
        if not self._current_file_path or not self.parser: return
        self._do_carve(self._current_file_path)

    def _carve_image(self):
        """Carve the entire loaded image/folder root."""
        if not self.parser: return
        # Pick a representative file — for a full image carve, we scan a raw block
        self._do_carve('/')

    def _do_carve(self, path: str):
        if self._carver_worker and self._carver_worker.isRunning():
            self._set_status('Carving already in progress…'); return

        dlg = _CarverOptionsDialog(self)
        if dlg.exec() != dlg.DialogCode.Accepted: return
        min_size = dlg.min_size

        save_dir = QFileDialog.getExistingDirectory(
            self, 'Save Carved Files To', '', QFileDialog.Option.ShowDirsOnly)
        if not save_dir: return

        self._set_status('Carving…')
        self._status_progress.setVisible(True)

        results_dlg = _CarveResultsDialog(save_dir, self)
        results_dlg.show()

        self._carver_worker = CarverWorker(self.parser, path, min_size)
        self._carver_worker.carved.connect(
            lambda cf: self._on_carved(cf, save_dir, results_dlg))
        self._carver_worker.progress.connect(
            lambda p, t: self._set_status(f'Carving… {p//1024}KB / {t//1024}KB'))
        self._carver_worker.finished.connect(
            lambda n: self._on_carve_done(n, results_dlg))
        self._carver_worker.start()

    def _on_carved(self, cf, save_dir: str, dlg: '_CarveResultsDialog'):
        fname = f'carved_{cf.offset:08X}.{cf.extension}'
        dest  = os.path.join(save_dir, fname)
        try:
            with open(dest, 'wb') as f: f.write(cf.data)
        except Exception:
            pass
        dlg.add_result(cf.offset, cf.size, cf.label, fname)

    def _on_carve_done(self, count: int, dlg: '_CarveResultsDialog'):
        self._status_progress.setVisible(False)
        self._set_status(f'Carving complete — {count} files recovered')
        dlg.set_done(count)

    # ---------------------------------------------------------------- #
    #  Relevance Scoring                                                 #
    # ---------------------------------------------------------------- #

    def _score_all_files(self):
        if not self.parser:
            QMessageBox.warning(self, 'No Image', 'Load an image or folder first.'); return
        if self._rel_worker and self._rel_worker.isRunning():
            self._set_status('Scoring already running…'); return

        self._set_status('Scoring files for forensic relevance…')
        self._status_progress.setVisible(True)

        self._rel_worker = RelevanceWorker(self.parser)
        self._rel_worker.scored.connect(self._on_file_scored)
        self._rel_worker.mismatch.connect(self._on_type_mismatch)
        self._rel_worker.status_update.connect(self._set_status)
        self._rel_worker.finished.connect(self._on_scoring_done)
        self._rel_worker.start()

    def _on_file_scored(self, path: str, sr):
        self._score_map[path] = sr
        # Update matching tree items
        items = self._tree.findItems(
            os.path.basename(path),
            Qt.MatchFlag.MatchRecursive | Qt.MatchFlag.MatchExactly,
            _COL_NAME,
        )
        for item in items:
            if item.text(_COL_PATH) == path:
                self._apply_score_style(item, sr)

    def _on_scoring_done(self):
        self._status_progress.setVisible(False)
        scored = len(self._score_map)
        critical = sum(1 for s in self._score_map.values() if s.tier == 'Critical')
        high     = sum(1 for s in self._score_map.values() if s.tier == 'High')
        self._set_status(
            f'Scoring done — {scored} files scored | '
            f'{critical} Critical | {high} High'
        )
        if critical or high:
            self._tree.sortItems(_COL_SCORE, Qt.SortOrder.DescendingOrder)

    def _on_type_mismatch(self, path: str, detected_label: str, ext: str):
        items = self._tree.findItems(
            os.path.basename(path),
            Qt.MatchFlag.MatchRecursive | Qt.MatchFlag.MatchExactly,
            _COL_NAME,
        )
        for item in items:
            if item.text(_COL_PATH) == path:
                item.setText(_COL_TYPE, f'⚠ {detected_label}')
                item.setForeground(_COL_TYPE, QColor('#ffa726'))
                item.setToolTip(
                    _COL_TYPE,
                    f'Extension mismatch: "{ext}" extension but magic bytes '
                    f'indicate {detected_label}',
                )
                break

    # ---------------------------------------------------------------- #
    #  Batch AI Analysis                                                #
    # ---------------------------------------------------------------- #

    def _batch_ai_analysis(self):
        if not self.parser:
            QMessageBox.warning(self, 'No Image', 'Load an image or folder first.'); return
        if not self._score_map:
            QMessageBox.warning(self, 'Batch AI',
                'Run "Score All Files" first to identify Critical and High files.'); return

        targets = sorted(
            [p for p, sr in self._score_map.items() if sr and sr.tier in ('Critical', 'High')],
            key=lambda p: -self._score_map[p].score,
        )
        if not targets:
            QMessageBox.information(self, 'Batch AI',
                'No Critical or High files found in the current score map.'); return

        reply = QMessageBox.question(
            self, 'Batch AI Analysis',
            f'Run AI analysis on {len(targets)} Critical/High files?\n\n'
            'Results will be saved to the case database.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._batch_worker = _BatchAIWorker(
            self.parser, targets, self._nlp, self._cv, self._ano)
        self._batch_worker.file_done.connect(self._on_batch_file_done)
        self._batch_worker.finished.connect(self._on_batch_done)
        self._batch_worker.status_update.connect(self._set_status)
        self._status_progress.setVisible(True)
        self._batch_worker.start()

    def _on_batch_file_done(self, path: str, ai_text: str, atype: str, md5: str, sha256: str):
        if self.db_manager and self.current_evidence_id:
            self.db_manager.add_artifact(
                self.current_evidence_id, path, md5, sha256, atype, ai_text)
            self._case_panel.refresh()

    def _on_batch_done(self, count: int):
        self._status_progress.setVisible(False)
        self._set_status(f'Batch AI complete — {count} files analyzed')

    # ---------------------------------------------------------------- #
    #  Browser Artifacts                                                 #
    # ---------------------------------------------------------------- #

    def _extract_browser_artifacts(self):
        if not self._current_file_path or not self.parser: return
        try:
            from src.core import browser_artifacts as ba
            content = self.parser.read_file_content(self._current_file_path)
            if not content:
                QMessageBox.warning(self, 'Browser Artifacts', 'Could not read file.'); return

            db_type = ba.detect_browser_db(self._current_file_path, content)
            if not db_type:
                QMessageBox.information(
                    self, 'Browser Artifacts',
                    'This file was not recognised as a browser database.\n\n'
                    'Supported: Chrome History, Cookies, Login Data; '
                    'Firefox places.sqlite, cookies.sqlite'
                ); return

            arts = ba.extract_from_data(db_type, content)
            html = ba.render_html(arts)
            self._preview.show_ai_result(html)
            self._set_status(f'Browser artifacts: {arts.total_items} items extracted')
        except Exception as e:
            QMessageBox.critical(self, 'Browser Artifacts Error', str(e))

    # ---------------------------------------------------------------- #
    #  Registry Parser                                                   #
    # ---------------------------------------------------------------- #

    def _parse_registry(self):
        if not self._current_file_path or not self.parser: return
        try:
            from src.core.registry_parser import RegistryParser, render_html as reg_html
            content = self.parser.read_file_content(self._current_file_path)
            if not content:
                QMessageBox.warning(self, 'Registry', 'Could not read file.'); return
            if content[:4] != b'regf':
                QMessageBox.information(
                    self, 'Registry',
                    'This file does not appear to be a Windows Registry hive.\n'
                    '(Expected "regf" signature.)'
                ); return
            parser = RegistryParser(content)
            html   = reg_html(parser.root)
            self._preview.show_ai_result(html)
            self._set_status('Registry hive parsed')
        except Exception as e:
            QMessageBox.critical(self, 'Registry Error', str(e))

    # ---------------------------------------------------------------- #
    #  Bookmarks                                                         #
    # ---------------------------------------------------------------- #

    def _add_bookmark(self, entry: dict):
        if not self.db_manager or not self.current_evidence_id:
            QMessageBox.warning(self, 'No Case', 'Open a case database first.'); return
        dlg = BookmarkDialog(entry['path'], self)
        if dlg.exec() != dlg.DialogCode.Accepted: return
        self.db_manager.add_bookmark(self.current_evidence_id, entry['path'],
                                      dlg.tag_name, dlg.tag_color, dlg.notes)
        self._case_panel.refresh()
        self._set_status(f'Bookmark added: {entry["name"]}')

    def _jump_to_bookmark(self, bm_id: int, ev_id: int, file_path: str):
        if not self.parser: return
        items = self._tree.findItems(
            os.path.basename(file_path),
            Qt.MatchFlag.MatchRecursive | Qt.MatchFlag.MatchExactly, _COL_NAME)
        for item in items:
            if item.text(_COL_PATH) == file_path:
                self._tree.setCurrentItem(item); self._tree.scrollToItem(item); break
        self._current_file_path = file_path
        entry = {'name': os.path.basename(file_path), 'type': 'File',
                 'size': 0, 'path': file_path}
        self._preview.load_file(self.parser, file_path, entry)

    # ---------------------------------------------------------------- #
    #  Export file                                                       #
    # ---------------------------------------------------------------- #

    def _export_file(self, entry: dict):
        if not self.parser: return
        dest, _ = QFileDialog.getSaveFileName(
            self, 'Export File', os.path.basename(entry['path']), 'All Files (*)')
        if not dest: return
        try:
            content = self.parser.read_file_content(entry['path'])
            if content is None:
                QMessageBox.warning(self, 'Export', 'Could not read file.'); return
            with open(dest, 'wb') as f: f.write(content)
            self._set_status(f'Exported to {dest}')
        except Exception as e:
            QMessageBox.critical(self, 'Export Error', str(e))

    # ---------------------------------------------------------------- #
    #  Report                                                            #
    # ---------------------------------------------------------------- #

    def _export_report(self):
        if not self.db_manager or not self.current_case_id:
            QMessageBox.warning(self, 'No Case', 'Open a case database first.'); return
        dlg = ReportOptionsDialog(self)
        if dlg.exec() != dlg.DialogCode.Accepted: return
        self._set_status('Generating report…'); self._status_progress.setVisible(True)
        self._report_worker = ReportWorker(
            self.db_manager, self.current_case_id, dlg.output_path,
            dlg.include_artifacts, dlg.include_bookmarks, dlg.include_iocs)
        self._report_worker.done.connect(self._on_report_done)
        self._report_worker.error.connect(self._on_report_error)
        self._report_worker.start()

    def _on_report_done(self, path):
        self._status_progress.setVisible(False); self._set_status(f'Report: {path}')
        if QMessageBox.question(
                self, 'Report Generated',
                f'Report saved.\nOpen in browser?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            webbrowser.open(f'file://{os.path.abspath(path)}')

    def _on_report_error(self, msg):
        self._status_progress.setVisible(False)
        QMessageBox.critical(self, 'Report Error', msg)

    # ---------------------------------------------------------------- #
    #  Full-text search                                                  #
    # ---------------------------------------------------------------- #

    def _start_full_search(self, needle: bytes):
        if not self.parser:
            self._search_bar.set_status('No image loaded'); return
        self._stop_full_search()
        self._search_results.clear()
        self._search_bar.set_searching(True, 'Searching…')
        self._search_worker = SearchWorker(self.parser, needle)
        self._search_worker.match_found.connect(self._on_search_match)
        self._search_worker.finished.connect(self._on_search_done)
        self._search_worker.start()

    def _stop_full_search(self):
        if self._search_worker and self._search_worker.isRunning():
            self._search_worker.stop(); self._search_worker.wait(500)
        self._search_bar.set_searching(False)

    def _on_search_match(self, path: str, offset: int):
        self._search_results.append((path, offset))
        self._search_bar.set_status(f'{len(self._search_results)} hits…')
        items = self._tree.findItems(
            os.path.basename(path),
            Qt.MatchFlag.MatchRecursive | Qt.MatchFlag.MatchExactly, _COL_NAME)
        for item in items:
            if item.text(_COL_PATH) == path:
                item.setBackground(0, QColor('#7d4000'))

    def _on_search_done(self, total: int):
        self._search_bar.set_searching(
            False, f'Search complete — {len(self._search_results)} hits')

    # ---------------------------------------------------------------- #
    #  Gallery view                                                      #
    # ---------------------------------------------------------------- #

    def _show_gallery(self):
        if not self.parser:
            QMessageBox.warning(self, 'Gallery', 'Load an image or folder first.'); return
        dlg = _GalleryDialog(self.parser, self)
        dlg.exec()

    # ---------------------------------------------------------------- #
    #  Timeline                                                          #
    # ---------------------------------------------------------------- #

    def _show_timeline(self):
        if not self.parser: return
        # Collect all tree entries that have an mtime
        entries = []
        def _collect(item):
            entry = item.data(0, _ENTRY_ROLE)
            if entry and entry.get('type') != 'Folder':
                entries.append(entry)
            for i in range(item.childCount()):
                _collect(item.child(i))
        for i in range(self._tree.topLevelItemCount()):
            _collect(self._tree.topLevelItem(i))

        dlg = TimelineDialog(entries, self)
        dlg.file_selected.connect(self._jump_to_path)
        dlg.exec()

    def _jump_to_path(self, file_path: str):
        """Select a tree item by its full path string."""
        def _search(item):
            entry = item.data(0, _ENTRY_ROLE)
            if entry and entry.get('path') == file_path:
                self._tree.setCurrentItem(item)
                self._tree.scrollToItem(item)
                return True
            for i in range(item.childCount()):
                if _search(item.child(i)):
                    return True
            return False
        for i in range(self._tree.topLevelItemCount()):
            if _search(self._tree.topLevelItem(i)):
                break

    # ---------------------------------------------------------------- #
    #  Evidence tagging                                                  #
    # ---------------------------------------------------------------- #

    _TAG_COLORS = {
        'Key Evidence': '#b71c1c',
        'Reviewed':     '#1b5e20',
        'Excluded':     '#424242',
    }

    def _tag_file(self, entry: dict, item: QTreeWidgetItem, tag_name: str, tag_color: str):
        if not self.db_manager or not self.current_evidence_id:
            QMessageBox.warning(self, 'No Case', 'Open a case database first.'); return
        # Replace any existing tag for this file
        self.db_manager.delete_bookmark_for_file(
            self.current_evidence_id, entry['path'])
        self.db_manager.add_bookmark(
            self.current_evidence_id, entry['path'],
            tag_name=tag_name, tag_color=tag_color)
        # Visual indicator on tree item
        col = QColor(tag_color)
        item.setBackground(0, col)
        item.setForeground(0, QBrush(QColor('#ffffff')))
        item.setToolTip(0, f'[{tag_name}] {entry["path"]}')
        self._set_status(f'Tagged "{entry["name"]}" as {tag_name}')
        self._case_panel.refresh()

    def _remove_tag(self, entry: dict, item: QTreeWidgetItem):
        if not self.db_manager or not self.current_evidence_id: return
        self.db_manager.delete_bookmark_for_file(
            self.current_evidence_id, entry['path'])
        item.setBackground(0, QColor(0, 0, 0, 0))
        item.setForeground(0, QBrush(QColor('#e0e0e0')))
        item.setToolTip(0, entry['path'])
        self._set_status(f'Tag removed from "{entry["name"]}"')
        self._case_panel.refresh()

    # ---------------------------------------------------------------- #
    #  YARA scanner                                                      #
    # ---------------------------------------------------------------- #

    def _yara_scan(self):
        if not self.parser:
            QMessageBox.warning(self, 'YARA', 'Load an image or folder first.'); return
        rules_path, _ = QFileDialog.getOpenFileName(
            self, 'Select YARA Rules File', '', 'YARA Rules (*.yar *.yara);;All Files (*)')
        if not rules_path: return

        from src.ai.yara_scanner import YARAScanner
        scanner = YARAScanner()
        try:
            scanner.load_rules(rules_path)
        except Exception as e:
            QMessageBox.critical(self, 'YARA Error', f'Failed to load rules:\n{e}'); return

        dlg = _YARAScanDialog(self.parser, scanner, self)
        dlg.exec()

    # ---------------------------------------------------------------- #
    #  Case Dashboard                                                    #
    # ---------------------------------------------------------------- #

    def _show_dashboard(self):
        if not self.db_manager or not self.current_case_id:
            QMessageBox.warning(self, 'No Case', 'Open a case database first.'); return
        from src.ui.dashboard import CaseDashboard
        dlg = CaseDashboard(self.db_manager, self.current_case_id,
                            self._score_map, self)
        dlg.file_selected.connect(self._jump_to_path)
        dlg.exec()

    # ---------------------------------------------------------------- #
    #  Drag & Drop                                                       #
    # ---------------------------------------------------------------- #

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if not path:
                continue
            if os.path.isdir(path):
                self._load_folder(path)
                self._add_recent_file(path)
                break
            ext = os.path.splitext(path)[1].lower()
            if ext in ('.e01', '.dd', '.raw', '.img', '.iso', '.001'):
                self._load_image(path)
                self._add_recent_file(path)
                break

    # ---------------------------------------------------------------- #
    #  Recent Files                                                      #
    # ---------------------------------------------------------------- #

    _MAX_RECENT = 8

    def _add_recent_file(self, path: str):
        recent = self._settings.value('recent_files', [], type=list)
        if path in recent:
            recent.remove(path)
        recent.insert(0, path)
        recent = recent[:self._MAX_RECENT]
        self._settings.setValue('recent_files', recent)
        self._refresh_recent_menu()

    def _refresh_recent_menu(self):
        self._recent_menu.clear()
        recent = self._settings.value('recent_files', [], type=list)
        if not recent:
            self._recent_menu.addAction('(none)').setEnabled(False)
            return
        for path in recent:
            act = QAction(os.path.basename(path), self)
            act.setToolTip(path)
            act.triggered.connect(lambda _checked, p=path: self._open_recent(p))
            self._recent_menu.addAction(act)
        self._recent_menu.addSeparator()
        self._recent_menu.addAction('Clear Recent', self._clear_recent)

    def _open_recent(self, path: str):
        if os.path.isdir(path):
            self._load_folder(path)
        elif os.path.isfile(path):
            self._load_image(path)
        else:
            QMessageBox.warning(self, 'Recent Files', f'Path not found:\n{path}')

    def _clear_recent(self):
        self._settings.remove('recent_files')
        self._refresh_recent_menu()

    # ---------------------------------------------------------------- #
    #  Helpers                                                           #
    # ---------------------------------------------------------------- #

    def _set_status(self, msg: str): self._status_label.setText(msg)


# ------------------------------------------------------------------ #
#  Batch AI worker                                                      #
# ------------------------------------------------------------------ #

class _BatchAIWorker(QThread):
    """Run AnalysisWorker logic sequentially over a list of file paths."""
    file_done     = pyqtSignal(str, str, str, str, str)  # path, ai_text, atype, md5, sha256
    status_update = pyqtSignal(str)
    finished      = pyqtSignal(int)   # total analyzed

    def __init__(self, parser, paths: list, nlp=None, cv=None, ano=None, parent=None):
        super().__init__(parent)
        self._parser = parser
        self._paths  = paths
        self._nlp    = nlp
        self._cv     = cv
        self._ano    = ano

    def run(self):
        from src.utils.crypto import calculate_hashes
        from src.ai.entity_extractor import EntityExtractor
        import src.ai.entropy_analyzer as entropy_mod

        done = 0
        total = len(self._paths)
        for path in self._paths:
            if self.isInterruptionRequested():
                break
            fname = os.path.basename(path)
            self.status_update.emit(f'Batch AI {done+1}/{total}: {fname}…')
            try:
                content = self._parser.read_file_content(path)
                if not content:
                    continue
                hashes = calculate_hashes(content)
                ext = os.path.splitext(path)[1].lower()
                ai_text = ''
                atype   = 'IOC+Entropy'

                if ext in ('.log', '.csv'):
                    if not self._ano:
                        from src.ai.anomaly.detector import LogAnomalyDetector
                        self._ano = LogAnomalyDetector()
                    ai_text = self._ano.analyze_logs(content.decode('utf-8', errors='ignore'))
                    atype = 'Anomaly'
                elif ext == '.pdf':
                    from src.core.pdf_extractor import PDFExtractor
                    text = PDFExtractor().extract(content)
                    if text.strip():
                        if not self._nlp:
                            from src.ai.nlp.analyzer import NLPAnalyzer
                            self._nlp = NLPAnalyzer()
                        ai_text = self._nlp.analyze_text(text)
                        atype = 'PDF+NLP'
                elif ext in ('.txt', '.md', '.html', '.xml', '.json'):
                    if not self._nlp:
                        from src.ai.nlp.analyzer import NLPAnalyzer
                        self._nlp = NLPAnalyzer()
                    ai_text = self._nlp.analyze_text(
                        content.decode('utf-8', errors='ignore'))
                    atype = 'NLP'
                elif ext in ('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.tif'):
                    if not self._cv:
                        from src.ai.cv.detector import CVDetector
                        self._cv = CVDetector()
                    ai_text = self._cv.analyze_image(content)
                    atype = 'CV'
                else:
                    ent_res  = entropy_mod.analyze(content[:65536])
                    entities = EntityExtractor().extract_from_bytes(content[:65536])
                    ai_text  = (
                        f'Entropy: {ent_res.overall:.3f} — {ent_res.label}\n'
                        + '\n'.join(f'  {e.kind}: {e.value}' for e in entities[:20])
                    )

                self.file_done.emit(path, ai_text, atype,
                                    hashes['md5'], hashes['sha256'])
                done += 1
            except Exception:
                pass

        self.finished.emit(done)


# ------------------------------------------------------------------ #
#  YARA scan dialog + worker                                            #
# ------------------------------------------------------------------ #

class _YARAScanWorker(QThread):
    match_found = pyqtSignal(str, str, str)   # path, rule_name, strings_preview
    progress    = pyqtSignal(int, int)         # done, total
    finished    = pyqtSignal(int)              # total matches

    def __init__(self, parser, scanner, parent=None):
        super().__init__(parent)
        self._parser  = parser
        self._scanner = scanner
        self._stop    = False

    def stop(self): self._stop = True

    def run(self):
        from src.core.file_type import categorize
        files = []
        self._collect('/', files)
        total   = len(files)
        matches = 0
        for i, (path, inode) in enumerate(files):
            if self._stop: break
            self.progress.emit(i + 1, total)
            try:
                data = self._parser.read_file_content(path)
                if not data: continue
                results = self._scanner.scan_bytes(path, data)
                for m in results:
                    preview = ', '.join(
                        f'{ident}@{off}' for off, ident, _ in m.strings[:3]
                    )
                    self.match_found.emit(path, m.rule_name, preview)
                    matches += 1
            except Exception:
                pass
        self.finished.emit(matches)

    def _collect(self, path, out, inode=None):
        try:
            for e in self._parser.list_directory(path, inode=inode):
                if e['type'] == 'Folder':
                    self._collect(e['path'], out, inode=e.get('inode'))
                else:
                    out.append((e['path'], e.get('inode')))
        except Exception:
            pass


class _YARAScanDialog(QDialog):
    def __init__(self, parser, scanner, parent=None):
        super().__init__(parent)
        self.setWindowTitle('YARA Scan Results')
        self.resize(900, 560)
        self.setStyleSheet('QDialog { background:#1a1a2e; } QLabel { color:#e0e0e0; }')

        lay = QVBoxLayout(self)

        hdr = QHBoxLayout()
        self._status = QLabel('Scanning…')
        self._status.setStyleSheet('color:#4ecca3; font-size:12px;')
        hdr.addWidget(self._status)
        hdr.addStretch()
        stop_btn = QPushButton('Stop')
        stop_btn.setStyleSheet(
            'QPushButton { background:#0f3460; color:#4ecca3; border:none;'
            'border-radius:4px; padding:4px 12px; }')
        hdr.addWidget(stop_btn)
        lay.addLayout(hdr)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        lay.addWidget(self._progress)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['File Path', 'Rule', 'Matched Strings'])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setStyleSheet(_TREE_CSS)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSortingEnabled(True)
        lay.addWidget(self._table)

        self._worker = _YARAScanWorker(parser, scanner, self)
        self._worker.match_found.connect(self._on_match)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_done)
        stop_btn.clicked.connect(self._worker.stop)
        self._worker.start()

    def _on_match(self, path: str, rule: str, strings: str):
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._table.setItem(row, 0, QTableWidgetItem(path))
        self._table.setItem(row, 1, QTableWidgetItem(rule))
        self._table.setItem(row, 2, QTableWidgetItem(strings))
        for col in range(3):
            self._table.item(row, col).setForeground(QBrush(QColor('#ff6b6b')))

    def _on_progress(self, done: int, total: int):
        self._progress.setMaximum(total)
        self._progress.setValue(done)
        self._status.setText(f'Scanning… {done}/{total} files  ({self._table.rowCount()} matches)')

    def _on_done(self, total: int):
        self._progress.setVisible(False)
        self._status.setText(f'Scan complete — {total} match(es) found')

    def closeEvent(self, event):
        self._worker.stop()
        self._worker.wait(1000)
        super().closeEvent(event)


# ------------------------------------------------------------------ #
#  Helper dialogs                                                       #
# ------------------------------------------------------------------ #

class _CarverOptionsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Carver Options')
        self.setFixedSize(320, 140)
        lay = QFormLayout(self)
        self._spin = QSpinBox()
        self._spin.setRange(64, 10 * 1024 * 1024)
        self._spin.setValue(512)
        self._spin.setSuffix(' bytes')
        lay.addRow('Minimum carved file size:', self._spin)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addRow(btns)

    @property
    def min_size(self) -> int: return self._spin.value()


class _CarveResultsDialog(QDialog):
    def __init__(self, save_dir: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Carved Files')
        self.resize(720, 450)
        lay = QVBoxLayout(self)
        self._lbl = QLabel(f'Saving to: {save_dir}')
        self._lbl.setStyleSheet('color:#aaa;font-size:11px')
        lay.addWidget(self._lbl)
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(['Offset', 'Size', 'Type', 'Saved As'])
        self._table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch)
        self._table.setStyleSheet(_TREE_CSS)
        lay.addWidget(self._table)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def add_result(self, offset: int, size: int, label: str, fname: str):
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._table.setItem(row, 0, QTableWidgetItem(f'{offset:#010x}'))
        self._table.setItem(row, 1, QTableWidgetItem(f'{size:,}'))
        self._table.setItem(row, 2, QTableWidgetItem(label))
        self._table.setItem(row, 3, QTableWidgetItem(fname))

    def set_done(self, count: int):
        self._lbl.setText(f'{count} files carved.')


_GALLERY_COLS    = 4
_GALLERY_THUMB_W = 196
_GALLERY_THUMB_H = 154
_GALLERY_CELL_W  = _GALLERY_THUMB_W + 16
_GALLERY_CELL_H  = _GALLERY_THUMB_H + 46   # thumb + filename + score badge

_BTN_CSS = (
    'QPushButton { background:#0f3460; color:#4ecca3; border:none;'
    ' border-radius:4px; padding:5px 14px; font-size:12px; }'
    'QPushButton:hover { background:#1a4a8a; }'
    'QPushButton:disabled { background:#222; color:#555; }'
)
_SEARCH_CSS = (
    'QLineEdit { background:#16213e; color:#e0e0e0; border:1px solid #0f3460;'
    ' border-radius:4px; padding:4px 8px; font-size:12px; }'
    'QLineEdit:focus { border-color:#4ecca3; }'
)
_GALLERY_CELL_CSS = (
    'QWidget#galleryCell {'
    '  background:#16213e; border:1px solid #0f3460; border-radius:6px;'
    '}'
    'QWidget#galleryCell:hover { border-color:#4ecca3; }'
    'QLabel { background:transparent; border:none; }'
)

class _GallerySearchWorker(QThread):
    """Runs CLIP scoring for all gallery images against a text query."""
    progress = pyqtSignal(int, int)          # done, total
    done     = pyqtSignal(list)              # list of (path, score) sorted desc

    def __init__(self, query: str, images: list):
        super().__init__()
        self._query  = query
        self._images = images   # list of (path, bytes)

    def run(self):
        from src.ai.cv.clip_search import CLIPImageSearcher
        searcher = CLIPImageSearcher()
        results = searcher.score_images(
            self._query, self._images,
            progress_cb=lambda d, t: self.progress.emit(d, t),
        )
        self.done.emit(results)


class _GalleryDialog(QDialog):
    def __init__(self, parser, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Image Gallery')
        self.resize(1020, 760)
        self.setStyleSheet('QDialog { background:#1a1a2e; } QLabel { color:#e0e0e0; }')

        self._count        = 0
        self._all_images   : list[tuple[str, bytes]]  = []   # (path, raw_bytes)
        self._cell_map     : dict[str, QWidget]        = {}   # path → cell widget
        self._search_worker: _GallerySearchWorker | None = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(6)

        # ── Search bar ──────────────────────────────────────────────────
        search_row = QHBoxLayout()
        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText(
            'AI image search — e.g. "weapon", "document", "person", "money"…')
        self._search_box.setStyleSheet(_SEARCH_CSS)
        self._search_box.returnPressed.connect(self._run_search)
        search_row.addWidget(self._search_box)

        self._search_btn = QPushButton('Search')
        self._search_btn.setStyleSheet(_BTN_CSS)
        self._search_btn.clicked.connect(self._run_search)
        search_row.addWidget(self._search_btn)

        self._clear_btn = QPushButton('Show All')
        self._clear_btn.setStyleSheet(_BTN_CSS)
        self._clear_btn.clicked.connect(self._clear_search)
        self._clear_btn.setEnabled(False)
        search_row.addWidget(self._clear_btn)

        lay.addLayout(search_row)

        # ── Status ──────────────────────────────────────────────────────
        self._status = QLabel('Scanning for images…')
        self._status.setStyleSheet('color:#aaa; font-size:11px; padding:2px 4px;')
        lay.addWidget(self._status)

        # ── Scroll grid ─────────────────────────────────────────────────
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll.setStyleSheet(
            'QScrollArea { border:none; background:#1a1a2e; }'
            'QScrollBar:vertical { background:#16213e; width:10px; }'
            'QScrollBar::handle:vertical { background:#0f3460; border-radius:5px; }'
        )
        self._container = QWidget()
        self._container.setStyleSheet('background:#1a1a2e;')
        self._grid = QGridLayout(self._container)
        self._grid.setSpacing(8)
        self._grid.setContentsMargins(8, 8, 8, 8)
        self._grid.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self._scroll.setWidget(self._container)
        lay.addWidget(self._scroll)

        # ── Selected path ────────────────────────────────────────────────
        self._selected_lbl = QLabel('')
        self._selected_lbl.setStyleSheet(
            'color:#4ecca3; font-size:10px; padding:2px 4px;')
        self._selected_lbl.setWordWrap(True)
        lay.addWidget(self._selected_lbl)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.setStyleSheet(_BTN_CSS)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

        # ── Gallery scan worker ──────────────────────────────────────────
        self._worker = _GalleryWorker(parser)
        self._worker.image_found.connect(self._add_thumb)
        self._worker.finished.connect(self._on_scan_done)
        self._worker.start()

    # ------------------------------------------------------------------ #
    #  Gallery scan                                                         #
    # ------------------------------------------------------------------ #

    def _add_thumb(self, path: str, data: bytes):
        pix = QPixmap()
        pix.loadFromData(data)
        if pix.isNull():
            return
        pix = pix.scaled(
            _GALLERY_THUMB_W, _GALLERY_THUMB_H,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self._all_images.append((path, data))
        cell = self._make_cell(path, pix)
        row, col = divmod(self._count, _GALLERY_COLS)
        self._grid.addWidget(cell, row, col)
        self._cell_map[path] = cell
        self._count += 1
        self._status.setText(f'{self._count} images found — scanning…')

    def _make_cell(self, path: str, pix: QPixmap, score: float | None = None) -> QWidget:
        cell = QWidget()
        cell.setObjectName('galleryCell')
        cell.setStyleSheet(_GALLERY_CELL_CSS)
        cell.setFixedSize(_GALLERY_CELL_W, _GALLERY_CELL_H)
        cell.setToolTip(path)
        cell.setCursor(Qt.CursorShape.PointingHandCursor)
        cell.mousePressEvent = lambda _e, p=path: self._on_click(p)

        cell_lay = QVBoxLayout(cell)
        cell_lay.setContentsMargins(6, 6, 6, 4)
        cell_lay.setSpacing(2)

        img_lbl = QLabel()
        img_lbl.setPixmap(pix)
        img_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        img_lbl.setFixedSize(_GALLERY_THUMB_W, _GALLERY_THUMB_H)
        cell_lay.addWidget(img_lbl)

        name = os.path.basename(path)
        if len(name) > 24:
            name = name[:11] + '…' + name[-10:]
        name_lbl = QLabel(name)
        name_lbl.setStyleSheet('color:#aaa; font-size:9px;')
        name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cell_lay.addWidget(name_lbl)

        if score is not None:
            pct   = int(score * 100)
            color = '#4ecca3' if score >= 0.25 else '#f57f17' if score >= 0.18 else '#555'
            score_lbl = QLabel(f'Match: {pct}%')
            score_lbl.setStyleSheet(
                f'color:{color}; font-size:9px; font-weight:bold;')
            score_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cell_lay.addWidget(score_lbl)

        return cell

    def _on_scan_done(self):
        self._status.setText(
            f'{self._count} image{"s" if self._count != 1 else ""} found'
            ' — type a query and press Search')

    def _on_click(self, path: str):
        self._selected_lbl.setText(path)

    # ------------------------------------------------------------------ #
    #  AI search                                                            #
    # ------------------------------------------------------------------ #

    def _run_search(self):
        query = self._search_box.text().strip()
        if not query or not self._all_images:
            return
        if self._search_worker and self._search_worker.isRunning():
            return

        self._search_btn.setEnabled(False)
        self._clear_btn.setEnabled(False)
        n = len(self._all_images)
        self._status.setText(
            f'Running CLIP search across {n} images — this may take a moment…')

        self._search_worker = _GallerySearchWorker(query, list(self._all_images))
        self._search_worker.progress.connect(self._on_search_progress)
        self._search_worker.done.connect(self._on_search_done)
        self._search_worker.start()

    def _on_search_progress(self, done: int, total: int):
        self._status.setText(f'Scoring images… {done}/{total}')

    def _on_search_done(self, results: list):
        self._search_btn.setEnabled(True)
        self._clear_btn.setEnabled(True)

        # Rebuild grid: show all results sorted by score, dim low matches
        self._rebuild_grid(results)

        above = sum(1 for _, s in results if s >= 0.18)
        self._status.setText(
            f'{above} strong match{"es" if above != 1 else ""} out of '
            f'{len(results)} images for "{self._search_box.text().strip()}"')

    def _rebuild_grid(self, scored: list):
        """Re-lay the grid in score order, showing score badges."""
        # Remove all cells from grid
        for i in reversed(range(self._grid.count())):
            item = self._grid.itemAt(i)
            if item and item.widget():
                item.widget().setParent(None)

        score_map = dict(scored)
        # Sort: high scores first, then alphabetical for ties
        ordered = sorted(self._all_images, key=lambda x: -score_map.get(x[0], 0))

        for idx, (path, data) in enumerate(ordered):
            score = score_map.get(path, 0.0)
            pix   = QPixmap()
            pix.loadFromData(data)
            if pix.isNull():
                continue
            pix = pix.scaled(
                _GALLERY_THUMB_W, _GALLERY_THUMB_H,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            cell = self._make_cell(path, pix, score=score)
            # Dim low-confidence results
            if score < 0.15:
                cell.setStyleSheet(
                    'QWidget#galleryCell { background:#111118;'
                    ' border:1px solid #222; border-radius:6px; opacity:0.4; }'
                    'QLabel { background:transparent; border:none; color:#444; }')
            row, col = divmod(idx, _GALLERY_COLS)
            self._grid.addWidget(cell, row, col)

    def _clear_search(self):
        """Restore the original scan order with no score badges."""
        self._search_box.clear()
        self._clear_btn.setEnabled(False)

        for i in reversed(range(self._grid.count())):
            item = self._grid.itemAt(i)
            if item and item.widget():
                item.widget().setParent(None)

        for idx, (path, data) in enumerate(self._all_images):
            pix = QPixmap()
            pix.loadFromData(data)
            if pix.isNull():
                continue
            pix = pix.scaled(
                _GALLERY_THUMB_W, _GALLERY_THUMB_H,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            cell = self._make_cell(path, pix)
            row, col = divmod(idx, _GALLERY_COLS)
            self._grid.addWidget(cell, row, col)

        self._status.setText(
            f'{self._count} image{"s" if self._count != 1 else ""} found')

    # ------------------------------------------------------------------ #

    def closeEvent(self, event):
        if self._worker.isRunning():
            self._worker.requestInterruption()
            self._worker.wait(500)
        if self._search_worker and self._search_worker.isRunning():
            self._search_worker.quit()
            self._search_worker.wait(500)
        super().closeEvent(event)


class _GalleryWorker(QThread):
    image_found = pyqtSignal(str, bytes)
    finished    = pyqtSignal()

    _IMAGE_EXTS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp'}

    def __init__(self, parser):
        super().__init__()
        self._parser = parser
        from src.utils.thumbnail_cache import ThumbnailCache
        self._cache = ThumbnailCache(os.path.join(tempfile.gettempdir(), 'aiExaminer_thumbs'))

    def run(self):
        self._walk('/')
        self.finished.emit()

    def _walk(self, path: str, inode=None):
        try:
            for entry in self._parser.list_directory(path, inode=inode):
                if self.isInterruptionRequested():
                    return
                if entry['type'] == 'Folder':
                    self._walk(entry['path'], inode=entry.get('inode'))
                elif any(entry['name'].lower().endswith(e) for e in self._IMAGE_EXTS):
                    try:
                        data = self._parser.read_file_content(entry['path'])
                        if data:
                            raw = data[:2 * 1024 * 1024]
                            thumb = self._cache.get_or_make(raw, _GALLERY_THUMB_W, _GALLERY_THUMB_H)
                            self.image_found.emit(entry['path'], thumb if thumb else raw)
                    except Exception:
                        pass
        except Exception:
            pass


class _TimelineDialog(QDialog):
    def __init__(self, parser, parent=None):
        super().__init__(parent)
        self.setWindowTitle('File Timeline')
        self.resize(1000, 600)
        lay = QVBoxLayout(self)

        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(
            ['File', 'Created', 'Modified', 'Accessed', 'Changed (MFT)', 'Deleted'])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.setStyleSheet(_TREE_CSS)
        self._table.setSortingEnabled(True)
        lay.addWidget(self._table)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

        self._collect(parser)

    def _collect(self, parser, path='/'):
        try:
            for entry in parser.list_directory(path):
                if entry['type'] == 'Folder':
                    self._collect(parser, entry['path'])
                else:
                    row = self._table.rowCount()
                    self._table.insertRow(row)
                    self._table.setItem(row, 0, QTableWidgetItem(entry['path']))
                    for col, key in enumerate(('crtime', 'mtime', 'atime', 'ctime'), 1):
                        self._table.setItem(row, col, QTableWidgetItem(str(entry.get(key) or '—')))
                    self._table.setItem(row, 5, QTableWidgetItem('Yes' if entry.get('is_deleted') else ''))
        except Exception:
            pass
