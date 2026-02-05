import re
import sqlite3
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# ======================
# Config
# ======================
BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = BASE_DIR / "app.db"
# React Admin UI (Vite build output)
ADMIN_DIST_DIR = BASE_DIR / "web" / "dist"
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
ADMIN_UI_ENABLED = False


UPLOAD_DIR.mkdir(exist_ok=True)

ALLOWED_EXT = {".exe", ".msi", ".zip", ".apk", ".dmg", ".pkg", ".rar", ".7z", ".tar", ".gz", ".whl", ".deb", ".rpm"}
MAX_SIZE_MB = 4096  # 4GB
STEALTH_MODE = True
HIDDEN_VERSION_FILE = "version_info.dat"
MAX_LOG_LINES = 500

# ======================
# Logging (in-memory)
# ======================
LOGS: List[Dict[str, Any]] = []

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def log_event(message: str):
    LOGS.append({"ts": utc_now_iso(), "msg": message})
    if len(LOGS) > MAX_LOG_LINES:
        del LOGS[: len(LOGS) - MAX_LOG_LINES]

# ======================
# DB helpers
# ======================
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def table_columns(conn: sqlite3.Connection, table: str) -> set:
    rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
    return {r[1] for r in rows}

def ensure_columns(conn: sqlite3.Connection, table: str, cols: Dict[str, str]):
    existing = table_columns(conn, table)
    for name, ddl_type in cols.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl_type};")

def init_db_and_migrate():
    conn = db()
    cur = conn.cursor()

    # existing table files (keep for backward compatibility)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app_id TEXT NOT NULL,
        version TEXT NOT NULL,
        original_name TEXT NOT NULL,
        stored_path TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # add new columns (migration)
    ensure_columns(conn, "files", {
        "updated_at": "TEXT",
        "notes": "TEXT",
        "revision": "INTEGER DEFAULT 1",
    })

    # apps table: remember per-app settings + which build is LIVE
    cur.execute("""
    CREATE TABLE IF NOT EXISTS apps (
        app_id TEXT PRIMARY KEY,
        live_file_id INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_files_app ON files(app_id);")
    conn.commit()
    conn.close()

# ======================
# Version compare
# ======================
def is_valid_version(v: str) -> bool:
    return bool(re.fullmatch(r"[0-9A-Za-z.\-_]+", v.strip()))

def version_key(v: str):
    try:
        from packaging.version import Version
        return Version(v)
    except Exception:
        return v

# ======================
# App
# ======================
app = FastAPI(title="AutoLoad CMD - Deployment Control Panel", version="1.1")
init_db_and_migrate()
log_event("Server started.")

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

ADMIN_UI_ENABLED = ADMIN_DIST_DIR.exists() and (ADMIN_DIST_DIR / "index.html").exists()
if ADMIN_UI_ENABLED:
    app.mount("/admin", StaticFiles(directory=str(ADMIN_DIST_DIR), html=True), name="admin")
    log_event("Admin UI enabled at /admin (served from web/dist).")
else:
    log_event("Admin UI not found (web/dist). Using built-in HTML UI at /.")

# ======================
# UI (Dashboard + Edit/Replace/Set Live)
# ======================
INDEX_HTML = (TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")

@app.get("/", response_class=HTMLResponse)
def index(ui: Optional[str] = None):
    if ui == "admin" and ADMIN_UI_ENABLED:
        return RedirectResponse(url="/admin", status_code=307)
    return HTMLResponse(INDEX_HTML)

@app.get("/favicon.ico")
def favicon():
    return PlainTextResponse("", status_code=204)

# ======================
# API
# ======================
@app.get("/api/health")
def api_health():
    return {"ok": True, "time": utc_now_iso()}

@app.get("/api/config")
def api_config():
    return {
        "stealth_mode": STEALTH_MODE,
        "hidden_version_file": HIDDEN_VERSION_FILE,
        "max_upload_mb": MAX_SIZE_MB,
    }

@app.get("/api/logs")
def api_logs(limit: int = 140):
    limit = max(10, min(limit, MAX_LOG_LINES))
    return JSONResponse(LOGS[-limit:])

def upsert_app(app_id: str):
    conn = db()
    now = utc_now_iso()
    row = conn.execute("SELECT app_id FROM apps WHERE app_id=?", (app_id,)).fetchone()
    if row:
        conn.execute("UPDATE apps SET updated_at=? WHERE app_id=?", (now, app_id))
    else:
        conn.execute("INSERT INTO apps(app_id, live_file_id, created_at, updated_at) VALUES(?,?,?,?)",
                     (app_id, None, now, now))
    conn.commit()
    conn.close()

def get_live_file_id(app_id: str) -> Optional[int]:
    conn = db()
    row = conn.execute("SELECT live_file_id FROM apps WHERE app_id=?", (app_id,)).fetchone()
    conn.close()
    return row["live_file_id"] if row and row["live_file_id"] is not None else None

@app.get("/api/{app_id}/live")
def api_get_live(app_id: str):
    upsert_app(app_id)
    return {"app_id": app_id, "live_file_id": get_live_file_id(app_id)}

@app.post("/api/{app_id}/set-live")
async def api_set_live(app_id: str, payload: Dict[str, Any]):
    file_id = payload.get("file_id")
    if file_id is None:
        raise HTTPException(400, "file_id required")

    conn = db()
    row = conn.execute("SELECT id FROM files WHERE id=? AND app_id=?", (file_id, app_id)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "file_id not found for this app_id")

    now = utc_now_iso()
    upsert_app(app_id)
    conn = db()
    conn.execute("UPDATE apps SET live_file_id=?, updated_at=? WHERE app_id=?", (file_id, now, app_id))
    conn.commit()
    conn.close()

    log_event(f"SET_LIVE app_id={app_id} live_file_id={file_id}")
    return {"ok": True, "app_id": app_id, "live_file_id": file_id}

@app.post("/api/upload")
async def api_upload(
    request: Request,
    app_id: str = Form(...),
    version: str = Form(...),
    notes: str = Form(""),
    file: UploadFile = File(...)
):
    app_id = app_id.strip()
    version = version.strip()

    if not app_id:
        raise HTTPException(400, "app_id required")
    if not is_valid_version(version):
        raise HTTPException(400, "invalid version format (use 1.2.3 / 2026.01.26 / etc.)")

    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, f"File type not allowed: {ext}")

    safe_app = re.sub(r"[^0-9A-Za-z._-]+", "_", app_id)
    safe_ver = re.sub(r"[^0-9A-Za-z._-]+", "_", version)
    dest_dir = UPLOAD_DIR / safe_app / safe_ver
    dest_dir.mkdir(parents=True, exist_ok=True)

    stored_name = re.sub(r"[^0-9A-Za-z._-]+", "_", file.filename)
    dest_path = dest_dir / stored_name

    size = 0
    h = hashlib.sha256()

    with dest_path.open("wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_SIZE_MB * 1024 * 1024:
                out.close()
                try:
                    dest_path.unlink(missing_ok=True)
                except Exception:
                    pass
                raise HTTPException(413, f"File too large (> {MAX_SIZE_MB} MB)")
            out.write(chunk)
            h.update(chunk)

    sha = h.hexdigest()
    now = utc_now_iso()

    conn = db()
    cur = conn.cursor()
    cur.execute("""
      INSERT INTO files(app_id, version, original_name, stored_path, size_bytes, sha256, created_at, updated_at, notes, revision)
      VALUES(?,?,?,?,?,?,?,?,?,?)
    """, (app_id, version, file.filename, str(dest_path), size, sha, now, now, notes, 1))
    conn.commit()
    row_id = cur.lastrowid
    conn.close()

    upsert_app(app_id)

    ip = request.client.host if request.client else "unknown"
    log_event(f"UPLOAD app_id={app_id} version={version} file_id={row_id} file={file.filename} size={size/1024/1024:.2f}MB ip={ip}")

    return {
        "id": row_id,
        "app_id": app_id,
        "version": version,
        "original_name": file.filename,
        "size_bytes": size,
        "sha256": sha,
        "revision": 1,
        "notes": notes,
        "created_at": now,
        "updated_at": now,
        "download_url": f"/api/download/{row_id}",
    }

@app.get("/api/{app_id}/versions")
def api_versions(app_id: str):
    upsert_app(app_id)
    conn = db()
    rows = conn.execute("""
      SELECT id, app_id, version, original_name, size_bytes, sha256, created_at, updated_at, notes, revision
      FROM files
      WHERE app_id=?
    """, (app_id,)).fetchall()
    conn.close()

    items = [{
        "id": r["id"],
        "app_id": r["app_id"],
        "version": r["version"],
        "original_name": r["original_name"],
        "size_bytes": r["size_bytes"],
        "sha256": r["sha256"],
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
        "notes": r["notes"],
        "revision": r["revision"] if r["revision"] is not None else 1,
        "download_url": f"/api/download/{r['id']}",
    } for r in rows]

    items.sort(key=lambda x: version_key(x["version"]), reverse=True)
    return JSONResponse(items)

@app.get("/api/{app_id}/latest")
def api_latest(app_id: str):
    upsert_app(app_id)

    live_id = get_live_file_id(app_id)
    conn = db()

    # if live is set → return that build
    if live_id is not None:
        r = conn.execute("""
          SELECT id, app_id, version, original_name, size_bytes, sha256, created_at, updated_at, notes, revision
          FROM files WHERE id=? AND app_id=?
        """, (live_id, app_id)).fetchone()
        conn.close()
        if not r:
            raise HTTPException(404, "Live build missing")
        return JSONResponse({
            "app_id": r["app_id"],
            "version": r["version"],
            "original_name": r["original_name"],
            "size_bytes": r["size_bytes"],
            "sha256": r["sha256"],
            "revision": r["revision"] if r["revision"] is not None else 1,
            "notes": r["notes"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
            "download_url": f"/api/download/{r['id']}",
        })

    # else auto-latest by version
    rows = conn.execute("""
      SELECT id, app_id, version, original_name, size_bytes, sha256, created_at, updated_at, notes, revision
      FROM files
      WHERE app_id=?
    """, (app_id,)).fetchall()
    conn.close()

    if not rows:
        raise HTTPException(404, "No files for this app_id")

    items = [dict(r) for r in rows]
    items.sort(key=lambda x: version_key(x["version"]), reverse=True)
    top = items[0]

    return JSONResponse({
        "app_id": top["app_id"],
        "version": top["version"],
        "original_name": top["original_name"],
        "size_bytes": top["size_bytes"],
        "sha256": top["sha256"],
        "revision": top["revision"] if top["revision"] is not None else 1,
        "notes": top["notes"],
        "created_at": top["created_at"],
        "updated_at": top["updated_at"],
        "download_url": f"/api/download/{top['id']}",
    })

@app.get("/api/download/{file_id}")
def api_download(file_id: int, request: Request):
    conn = db()
    r = conn.execute("""
      SELECT app_id, version, original_name, stored_path, revision
      FROM files WHERE id=?
    """, (file_id,)).fetchone()
    conn.close()

    if not r:
        raise HTTPException(404, "Not found")

    path = Path(r["stored_path"])
    if not path.exists():
        raise HTTPException(404, "File missing on disk")

    ip = request.client.host if request.client else "unknown"
    log_event(f"DOWNLOAD id={file_id} app_id={r['app_id']} version={r['version']} rev={r['revision']} ip={ip}")

    return FileResponse(str(path), filename=r["original_name"], media_type="application/octet-stream")

# ---------- EDIT METADATA ----------
@app.patch("/api/file/{file_id}")
async def api_edit_file(file_id: int, payload: Dict[str, Any]):
    new_version = payload.get("version")
    notes = payload.get("notes")

    if new_version is not None:
        new_version = str(new_version).strip()
        if not new_version:
            new_version = None
        elif not is_valid_version(new_version):
            raise HTTPException(400, "invalid version format")

    conn = db()
    row = conn.execute("SELECT id, app_id, version FROM files WHERE id=?", (file_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "not found")

    now = utc_now_iso()
    if new_version is not None and new_version != row["version"]:
        conn.execute("UPDATE files SET version=?, updated_at=? WHERE id=?", (new_version, now, file_id))
        log_event(f"EDIT_META id={file_id} version {row['version']} -> {new_version}")
    if notes is not None:
        conn.execute("UPDATE files SET notes=?, updated_at=? WHERE id=?", (str(notes), now, file_id))
        log_event(f"EDIT_META id={file_id} notes updated")

    conn.commit()
    conn.close()

    return {"ok": True, "id": file_id}

# ---------- REPLACE FILE CONTENT ----------
@app.put("/api/file/{file_id}/replace")
async def api_replace_file(file_id: int, request: Request, file: UploadFile = File(...)):
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, f"File type not allowed: {ext}")

    conn = db()
    r = conn.execute("""
      SELECT id, app_id, version, original_name, stored_path, revision
      FROM files WHERE id=?
    """, (file_id,)).fetchone()
    if not r:
        conn.close()
        raise HTTPException(404, "not found")

    app_id = r["app_id"]
    version = r["version"]
    old_path = Path(r["stored_path"])
    rev = (r["revision"] if r["revision"] is not None else 1) + 1

    safe_app = re.sub(r"[^0-9A-Za-z._-]+", "_", app_id)
    safe_ver = re.sub(r"[^0-9A-Za-z._-]+", "_", version)
    dest_dir = UPLOAD_DIR / safe_app / safe_ver
    dest_dir.mkdir(parents=True, exist_ok=True)

    stored_name = re.sub(r"[^0-9A-Za-z._-]+", "_", file.filename)
    new_path = dest_dir / stored_name

    # write new file
    size = 0
    h = hashlib.sha256()
    with new_path.open("wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_SIZE_MB * 1024 * 1024:
                out.close()
                try:
                    new_path.unlink(missing_ok=True)
                except Exception:
                    pass
                conn.close()
                raise HTTPException(413, f"File too large (> {MAX_SIZE_MB} MB)")
            out.write(chunk)
            h.update(chunk)

    sha = h.hexdigest()
    now = utc_now_iso()

    # delete old file if different
    try:
        if old_path.exists() and old_path.resolve() != new_path.resolve():
            old_path.unlink(missing_ok=True)
    except Exception:
        pass

    conn.execute("""
      UPDATE files
      SET original_name=?, stored_path=?, size_bytes=?, sha256=?, updated_at=?, revision=?
      WHERE id=?
    """, (file.filename, str(new_path), size, sha, now, rev, file_id))
    conn.commit()
    conn.close()

    ip = request.client.host if request.client else "unknown"
    log_event(f"REPLACE_FILE id={file_id} app_id={app_id} version={version} rev={rev} file={file.filename} ip={ip}")

    return {
        "ok": True,
        "id": file_id,
        "app_id": app_id,
        "version": version,
        "revision": rev,
        "original_name": file.filename,
        "size_bytes": size,
        "sha256": sha,
        "updated_at": now,
        "download_url": f"/api/download/{file_id}",
    }
