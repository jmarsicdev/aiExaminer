"""
Browser artifact extractor — reads Chrome and Firefox SQLite databases.

Can operate on:
  - Files directly from the local filesystem
  - Bytes extracted from a forensic image (written to a temp file first)

Returns structured ArtifactCollection objects with history, downloads, cookies,
saved passwords (Chrome Login Data), and form autofill data.
"""

import sqlite3
import tempfile
import os
import datetime
from dataclasses import dataclass, field


# Chrome epoch: microseconds since 1601-01-01
_CHROME_EPOCH_DELTA = 11_644_473_600_000_000


@dataclass
class HistoryEntry:
    url:        str
    title:      str
    visit_time: str
    visit_count: int
    source:     str   # 'chrome' or 'firefox'


@dataclass
class DownloadEntry:
    url:           str
    target_path:   str
    start_time:    str
    total_bytes:   int
    state:         str
    source:        str


@dataclass
class CookieEntry:
    host:         str
    name:         str
    value:        str
    creation:     str
    expires:      str
    is_secure:    bool
    is_httponly:  bool
    source:       str


@dataclass
class SavedPassword:
    origin_url:  str
    username:    str
    # Password is stored encrypted — we show presence only
    has_password: bool
    date_created: str
    source:      str


@dataclass
class BrowserArtifacts:
    history:   list[HistoryEntry]   = field(default_factory=list)
    downloads: list[DownloadEntry]  = field(default_factory=list)
    cookies:   list[CookieEntry]    = field(default_factory=list)
    passwords: list[SavedPassword]  = field(default_factory=list)
    errors:    list[str]            = field(default_factory=list)

    @property
    def total_items(self) -> int:
        return len(self.history) + len(self.downloads) + len(self.cookies) + len(self.passwords)


# ------------------------------------------------------------------ #
#  Detection helpers                                                    #
# ------------------------------------------------------------------ #

_CHROME_DB_NAMES = {'history', 'login data', 'cookies', 'web data',
                    'bookmarks', 'favicons', 'top sites'}

_FIREFOX_DB_NAMES = {'places.sqlite', 'cookies.sqlite', 'formhistory.sqlite',
                     'logins.json', 'key4.db', 'signons.sqlite'}


def detect_browser_db(file_path: str, data: bytes) -> str | None:
    """
    Return 'chrome_history', 'chrome_cookies', 'chrome_passwords',
    'firefox_places', 'firefox_cookies', or None.
    """
    name = os.path.basename(file_path).lower()
    if name == 'history':
        return 'chrome_history'
    if name == 'login data':
        return 'chrome_passwords'
    if name == 'cookies' and data[:16].startswith(b'SQLite'):
        return 'chrome_cookies'
    if name == 'places.sqlite':
        return 'firefox_places'
    if name == 'cookies.sqlite' and data[:16].startswith(b'SQLite'):
        return 'firefox_cookies'
    return None


# ------------------------------------------------------------------ #
#  Main extractor                                                       #
# ------------------------------------------------------------------ #

def extract_from_data(db_type: str, data: bytes) -> BrowserArtifacts:
    """
    Write bytes to a temp file and parse the SQLite database.
    Returns a BrowserArtifacts collection.
    """
    arts = BrowserArtifacts()
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix='.sqlite')
        os.close(fd)
        with open(tmp, 'wb') as f:
            f.write(data)
        _parse(db_type, tmp, arts)
    except Exception as e:
        arts.errors.append(str(e))
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)
    return arts


def extract_from_path(db_type: str, db_path: str) -> BrowserArtifacts:
    """Parse a browser SQLite file directly from disk."""
    arts = BrowserArtifacts()
    try:
        _parse(db_type, db_path, arts)
    except Exception as e:
        arts.errors.append(str(e))
    return arts


def _parse(db_type: str, path: str, arts: BrowserArtifacts) -> None:
    conn = sqlite3.connect(f'file:{path}?mode=ro&immutable=1', uri=True)
    try:
        conn.row_factory = sqlite3.Row
        if db_type == 'chrome_history':
            _chrome_history(conn, arts)
            _chrome_downloads(conn, arts)
        elif db_type == 'chrome_passwords':
            _chrome_passwords(conn, arts)
        elif db_type == 'chrome_cookies':
            _chrome_cookies(conn, arts)
        elif db_type == 'firefox_places':
            _firefox_history(conn, arts)
        elif db_type == 'firefox_cookies':
            _firefox_cookies(conn, arts)
    finally:
        conn.close()


# ------------------------------------------------------------------ #
#  Chrome parsers                                                       #
# ------------------------------------------------------------------ #

def _chrome_time(ts: int) -> str:
    """Convert Chrome timestamp (µs since 1601-01-01) to ISO string."""
    if not ts:
        return '—'
    try:
        unix_us = ts - _CHROME_EPOCH_DELTA
        dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=unix_us)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)


def _chrome_history(conn: sqlite3.Connection, arts: BrowserArtifacts) -> None:
    try:
        cur = conn.execute(
            'SELECT url, title, last_visit_time, visit_count '
            'FROM urls ORDER BY last_visit_time DESC LIMIT 5000'
        )
        for row in cur:
            arts.history.append(HistoryEntry(
                url=row['url'] or '',
                title=row['title'] or '',
                visit_time=_chrome_time(row['last_visit_time'] or 0),
                visit_count=row['visit_count'] or 0,
                source='chrome',
            ))
    except Exception as e:
        arts.errors.append(f'Chrome history: {e}')


def _chrome_downloads(conn: sqlite3.Connection, arts: BrowserArtifacts) -> None:
    try:
        cur = conn.execute(
            'SELECT tab_url, target_path, start_time, total_bytes, state '
            'FROM downloads ORDER BY start_time DESC LIMIT 2000'
        )
        states = {0: 'In progress', 1: 'Complete', 2: 'Cancelled',
                  3: 'Bug', 4: 'Interrupted'}
        for row in cur:
            arts.downloads.append(DownloadEntry(
                url=row['tab_url'] or '',
                target_path=row['target_path'] or '',
                start_time=_chrome_time(row['start_time'] or 0),
                total_bytes=row['total_bytes'] or 0,
                state=states.get(row['state'], str(row['state'])),
                source='chrome',
            ))
    except Exception as e:
        arts.errors.append(f'Chrome downloads: {e}')


def _chrome_cookies(conn: sqlite3.Connection, arts: BrowserArtifacts) -> None:
    try:
        cur = conn.execute(
            'SELECT host_key, name, value, creation_utc, expires_utc, '
            'is_secure, is_httponly FROM cookies ORDER BY creation_utc DESC LIMIT 5000'
        )
        for row in cur:
            arts.cookies.append(CookieEntry(
                host=row['host_key'] or '',
                name=row['name'] or '',
                value=(row['value'] or '')[:120],
                creation=_chrome_time(row['creation_utc'] or 0),
                expires=_chrome_time(row['expires_utc'] or 0),
                is_secure=bool(row['is_secure']),
                is_httponly=bool(row['is_httponly']),
                source='chrome',
            ))
    except Exception as e:
        arts.errors.append(f'Chrome cookies: {e}')


def _chrome_passwords(conn: sqlite3.Connection, arts: BrowserArtifacts) -> None:
    try:
        cur = conn.execute(
            'SELECT origin_url, username_value, password_value, date_created '
            'FROM logins ORDER BY date_created DESC'
        )
        for row in cur:
            arts.passwords.append(SavedPassword(
                origin_url=row['origin_url'] or '',
                username=row['username_value'] or '',
                has_password=bool(row['password_value']),
                date_created=_chrome_time(row['date_created'] or 0),
                source='chrome',
            ))
    except Exception as e:
        arts.errors.append(f'Chrome passwords: {e}')


# ------------------------------------------------------------------ #
#  Firefox parsers                                                      #
# ------------------------------------------------------------------ #

def _ff_time(ts) -> str:
    """Firefox stores timestamps as µs or ms since Unix epoch."""
    if not ts:
        return '—'
    try:
        ts_int = int(ts)
        # Firefox places uses µs
        if ts_int > 1e13:
            ts_int //= 1000
        dt = datetime.datetime.utcfromtimestamp(ts_int / 1000)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)


def _firefox_history(conn: sqlite3.Connection, arts: BrowserArtifacts) -> None:
    try:
        cur = conn.execute(
            'SELECT url, title, last_visit_date, visit_count '
            'FROM moz_places WHERE visit_count > 0 '
            'ORDER BY last_visit_date DESC LIMIT 5000'
        )
        for row in cur:
            arts.history.append(HistoryEntry(
                url=row['url'] or '',
                title=row['title'] or '',
                visit_time=_ff_time(row['last_visit_date']),
                visit_count=row['visit_count'] or 0,
                source='firefox',
            ))
    except Exception as e:
        arts.errors.append(f'Firefox history: {e}')


def _firefox_cookies(conn: sqlite3.Connection, arts: BrowserArtifacts) -> None:
    try:
        cur = conn.execute(
            'SELECT host, name, value, creationTime, expiry, isSecure, isHttpOnly '
            'FROM moz_cookies ORDER BY creationTime DESC LIMIT 5000'
        )
        for row in cur:
            arts.cookies.append(CookieEntry(
                host=row['host'] or '',
                name=row['name'] or '',
                value=(row['value'] or '')[:120],
                creation=_ff_time(row['creationTime']),
                expires=_ff_time((row['expiry'] or 0) * 1000),
                is_secure=bool(row['isSecure']),
                is_httponly=bool(row['isHttpOnly']),
                source='firefox',
            ))
    except Exception as e:
        arts.errors.append(f'Firefox cookies: {e}')


# ------------------------------------------------------------------ #
#  HTML renderer                                                        #
# ------------------------------------------------------------------ #

def render_html(arts: BrowserArtifacts) -> str:
    parts = []

    if arts.errors:
        parts.append('<p style="color:#ef5350">' +
                     '<br>'.join(arts.errors) + '</p>')

    def section(title: str, rows: list[str], headers: list[str]) -> str:
        if not rows:
            return ''
        hdr = ''.join(f'<th style="background:#0f3460;color:#4ecca3;padding:4px 8px">{h}</th>'
                      for h in headers)
        return (
            f'<h3 style="color:#4ecca3;border-bottom:1px solid #0f3460;padding-bottom:4px">'
            f'{title} ({len(rows)})</h3>'
            f'<table style="width:100%;border-collapse:collapse;font-size:11px">'
            f'<tr>{hdr}</tr>' + ''.join(rows) + '</table><br>'
        )

    def td(val, color='#e0e0e0'):
        v = str(val).replace('<', '&lt;').replace('>', '&gt;')
        return f'<td style="padding:3px 8px;border-bottom:1px solid #2a2a4a;color:{color}">{v}</td>'

    # History
    hist_rows = [
        f'<tr>{td(h.visit_time, "#aaa")}{td(h.visit_count, "#4ecca3")}'
        f'{td(h.title)}{td(h.url[:80])}{td(h.source, "#aaa")}</tr>'
        for h in arts.history[:200]
    ]
    parts.append(section('Browse History', hist_rows,
                         ['Time', 'Visits', 'Title', 'URL', 'Browser']))

    # Downloads
    dl_rows = [
        f'<tr>{td(d.start_time, "#aaa")}{td(d.state, "#ffa726")}'
        f'{td(f"{d.total_bytes:,} B", "#4ecca3")}{td(d.url[:60])}'
        f'{td(d.target_path[:60])}</tr>'
        for d in arts.downloads[:200]
    ]
    parts.append(section('Downloads', dl_rows,
                         ['Time', 'State', 'Size', 'URL', 'Target Path']))

    # Cookies
    cookie_rows = [
        f'<tr>{td(c.creation, "#aaa")}{td(c.host, "#4ecca3")}'
        f'{td(c.name)}{td(c.value[:60])}'
        f'{td("🔒" if c.is_secure else "", "#66bb6a")}</tr>'
        for c in arts.cookies[:200]
    ]
    parts.append(section('Cookies', cookie_rows,
                         ['Created', 'Host', 'Name', 'Value (truncated)', 'Secure']))

    # Saved passwords
    pw_rows = [
        f'<tr>{td(p.date_created, "#aaa")}{td(p.origin_url[:60], "#4ecca3")}'
        f'{td(p.username)}{td("Yes (encrypted)" if p.has_password else "No", "#ffa726")}</tr>'
        for p in arts.passwords
    ]
    parts.append(section('Saved Passwords', pw_rows,
                         ['Created', 'URL', 'Username', 'Password Present']))

    if not parts or all(not p for p in parts):
        return '<p style="color:#888">No browser artifacts found.</p>'
    return ''.join(parts)
