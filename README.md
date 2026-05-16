# aiExaminer

An intelligent digital forensic examination software that leverages AI to accelerate the analysis of forensic images.

## Project Structure
- `src/`: Core source code.
  - `ui/`: Desktop GUI (PyQt/PySide).
  - `core/`: Forensic parsing engine.
  - `ai/`: AI processing modules (NLP, Computer Vision, Anomaly Detection).
  - `db/`: Case management database.
- `models/`: Local AI model weights.
- `data/`: Test data and case outputs.
- `tests/`: Automated tests.

## Setup
1. Create a virtual environment: `python -m venv .venv`
2. Activate the environment: `source .venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`

---

## Usage Guide

### Launching the App

```bash
./run_aiExaminer.sh
```

---

### 1. Creating a Case

A case stores all your evidence, bookmarks, and analysis results in a SQLite database that persists between sessions.

1. Go to **Case → New Case…** (or press `Ctrl+N`)
2. Fill in the fields:
   - **Case Number** — e.g. `2024-001`
   - **Examiner** — your name
   - **Description** — optional notes about the investigation
   - **Database** — click **Browse…**, navigate to a folder, and save a `.db` file (e.g. `case001.db`)
3. Click **OK** — the case appears in the Case Explorer panel on the left

> Always create or open a case before loading evidence if you want results saved to disk.

---

### 2. Opening an Existing Case

1. Go to **Case → Open Case…**
2. Select the `.db` file from a previous session
3. Choose the case from the dropdown and click **OK**

---

### 3. Loading a Forensic Image

Supported formats: `.E01`, `.dd`, `.raw`, `.img`, `.iso`, `.001`

1. Go to **File → Open Image…** (or press `Ctrl+O`, or click the toolbar button)
2. Browse to your image file and select it
3. The file tree populates — folders expand lazily when clicked

**E01 images:** If `pytsk3` was built without `libewf` support, the app automatically falls back to `ewfmount`. If that also fails, a built-in raw NTFS parser is tried as a last resort. Requires `libewf-tools` installed (`sudo apt install libewf-tools`).

---

### 4. Opening a Logical Folder

Use this to browse a live filesystem or an already-mounted directory instead of an image file.

1. Go to **File → Open Logical Folder…**
2. Select the directory to browse

---

### 5. Browsing the File Tree

- The centre pane shows the filesystem tree with columns: **Name, Type, Size, Score, MD5, Full Path, Deleted, Modified**
- **Deleted files** are highlighted in red
- **Folders** are highlighted in teal — click the arrow to expand them
- Use the **name filter** in the search bar at the top to live-filter by filename
- Click any column header to sort

---

### 6. Previewing a File

1. Click any file in the tree
2. The right pane loads a preview automatically:
   - **Text files** — shown as plain text
   - **Images** — rendered inline
   - **Binary files** — shown in the hex viewer

---

### 7. Running AI Analysis

Analyses the selected file and displays results in the preview pane. The type of analysis depends on the file extension:

| File type | Analysis |
|---|---|
| `.log`, `.csv` | Anomaly detection |
| `.txt`, `.md`, `.html`, `.xml`, `.json` | NLP entity extraction |
| `.jpg`, `.jpeg`, `.png`, `.bmp`, `.gif`, `.tiff` | Computer vision |
| Everything else | IOC extraction + entropy analysis |

**Steps:**
1. Select a file in the tree
2. Go to **Tools → Run AI Analysis** (or press `Ctrl+A`, or right-click → **Run AI Analysis**)
3. Results appear in the preview pane; if a case is open they are saved to the database

---

### 8. Hashing a File

1. Select a file in the tree
2. Go to **Tools → Hash Selected File** (or right-click → **Calculate Hashes**)
3. The MD5 hash appears in the tree's MD5 column; both MD5 and SHA-256 appear in the status bar

---

### 9. Scoring All Files for Forensic Relevance

Walks the entire loaded image/folder and scores every file based on entropy, file type, IOC indicators, and whether it is deleted. High-scoring files are sorted to the top.

1. Load an image or folder
2. Go to **Tools → Score All Files (Relevance AI)…** (or click the toolbar button)
3. The Score column fills in as files are processed — colour-coded by tier (Critical, High, Medium, Low)
4. When complete, Critical and High files are automatically sorted to the top

---

### 10. Full-Text / Binary Search

Searches every file in the loaded image for a text or hex string.

1. Type your search term in the **search bar** at the top of the window
2. Click the search button or press Enter
3. Matching files are highlighted in the tree; the hit count updates in the search bar
4. Click **Stop** to cancel a running search

---

### 11. Carving a File for Embedded Content

Extracts embedded files (JPEG, PNG, PDF, ZIP, etc.) hidden inside another file's raw bytes.

1. Select a file in the tree
2. Right-click → **Carve File for Embedded Content** (or **Tools → Carve File for Embedded Content…**)
3. Set a minimum carved file size (default: 512 bytes) and click **OK**
4. Choose a folder to save carved files into
5. A results table shows each carved file's offset, size, and type

---

### 12. Carving the Entire Image

Same as above but scans the whole loaded image/folder root.

1. Go to **Tools → Carve Entire Image / Folder…** (or click the toolbar button)
2. Follow the same size and save-folder prompts

---

### 13. Extracting Browser Artifacts

Parses Chrome and Firefox browser databases for history, cookies, and saved login data.

Supported files: `History`, `Cookies`, `Login Data` (Chrome), `places.sqlite`, `cookies.sqlite` (Firefox)

1. Navigate to the browser profile folder in the file tree (e.g. `Users/<name>/AppData/Local/Google/Chrome/User Data/Default/`)
2. Select a supported database file
3. Right-click → **Extract Browser Artifacts** (or **Tools → Extract Browser Artifacts…**)
4. Results are rendered in the preview pane

---

### 14. Parsing a Registry Hive

1. Navigate to a Windows Registry hive file (e.g. `Windows/System32/config/SYSTEM`, `NTUSER.DAT`)
2. Select it in the file tree
3. Right-click → **Parse as Registry Hive** (or **Tools → Parse Registry Hive…**)
4. The key/value tree is rendered in the preview pane

---

### 15. Adding a Bookmark

Flag a file of interest for later review.

1. Right-click a file in the tree → **Add Bookmark…**
2. Set a tag name (e.g. `Suspicious`, `Key Evidence`), pick a highlight colour, and add optional notes
3. Click **OK** — the bookmark appears in the Case Explorer panel
4. Double-click a bookmark in the Case Explorer to jump straight to that file

---

### 16. Exporting a File

Save a file out of the forensic image to your local filesystem.

1. Right-click a file in the tree → **Export File…**
2. Choose a destination path and click Save

---

### 17. Image Gallery

Browse all image files in the loaded evidence as thumbnails.

1. Go to **View → Image Gallery…**
2. Thumbnails load progressively; hover over one to see the full path

---

### 18. File Timeline

View all files sorted by their timestamps (created, modified, accessed, MFT changed).

1. Go to **View → File Timeline…**
2. Click any column header to sort chronologically
3. The Deleted column flags files recovered from unallocated space

---

### 19. Exporting an HTML Report

Generates a self-contained HTML report from the case database.

1. Make sure a case is open and you have run some analysis
2. Go to **File → Export Report…** (or press `Ctrl+R`)
3. Choose which sections to include: **Analyzed Files**, **Bookmarks & Tags**, **IOC Summary**
4. Click **Browse…** to set the output `.html` path, then **OK**
5. When complete you will be prompted to open it in your browser

---

### 20. Closing a Case

**Case → Close Case** — unloads the database. The loaded image/folder stays open.
