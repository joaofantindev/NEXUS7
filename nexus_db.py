"""NEXUS-7 - motor de dados local (SQLite).

Persistencia de scans, resultados, alvos recorrentes e configuracoes para
uso da GUI e do futuro daemon headless (nexusd). Rodada em modo Fase 2.
"""

from __future__ import annotations

import os
import sqlite3
import datetime


def data_dir() -> str:
    env = os.environ.get("NEXUS7_DATA_DIR")
    if env:
        os.makedirs(env, exist_ok=True)
        return env
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    d = os.path.join(base, "nexus7")
    os.makedirs(d, exist_ok=True)
    return d


def config_dir() -> str:
    env = os.environ.get("NEXUS7_CONFIG_DIR")
    if env:
        os.makedirs(env, exist_ok=True)
        return env
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    d = os.path.join(base, "nexus7")
    os.makedirs(d, exist_ok=True)
    return d


DB_PATH = os.path.join(data_dir(), "nexus.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_id TEXT,
    tool_name TEXT,
    mode TEXT,
    target TEXT,
    extra TEXT,
    proxy TEXT,
    status TEXT DEFAULT 'running',
    exit_code INTEGER,
    created_at TEXT,
    finished_at TEXT,
    log TEXT
);
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    kind TEXT,
    title TEXT,
    detail TEXT,
    ts TEXT
);
CREATE TABLE IF NOT EXISTS targets (
    target TEXT PRIMARY KEY,
    hits INTEGER DEFAULT 1,
    last_used TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def _now() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    con = _conn()
    try:
        con.executescript(_SCHEMA)
        con.commit()
    finally:
        con.close()


# ------------------------------ scans ---------------------------------- #
def add_scan(tool_id: str, tool_name: str, mode: str, target: str,
             extra: str, proxy: str) -> int:
    con = _conn()
    try:
        cur = con.execute(
            "INSERT INTO scans (tool_id, tool_name, mode, target, extra, proxy,"
            " status, created_at) VALUES (?,?,?,?,?,?, 'running', ?)",
            (tool_id, tool_name, mode, target, extra, proxy, _now()))
        con.commit()
        return int(cur.lastrowid)
    finally:
        con.close()


def finish_scan(scan_id: int, exit_code: int) -> None:
    con = _conn()
    try:
        con.execute(
            "UPDATE scans SET status = ?, exit_code = ?, finished_at = ?"
            " WHERE id = ?",
            ("done" if exit_code == 0 else "error", exit_code, _now(), scan_id))
        con.commit()
    finally:
        con.close()


def save_log(scan_id: int, text: str) -> None:
    con = _conn()
    try:
        con.execute("UPDATE scans SET log = ? WHERE id = ?", (text, scan_id))
        con.commit()
    finally:
        con.close()


def get_scan(scan_id: int) -> dict | None:
    con = _conn()
    try:
        row = con.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()


def list_scans(limit: int = 60) -> list[dict]:
    con = _conn()
    try:
        rows = con.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


# ---------------------------- results ---------------------------------- #
def add_result(scan_id: int, kind: str, title: str, detail: str = "") -> None:
    con = _conn()
    try:
        con.execute("INSERT INTO results (scan_id, kind, title, detail, ts)"
                    " VALUES (?,?,?,?,?)",
                    (scan_id, kind, title, detail, _now()))
        con.commit()
    finally:
        con.close()


def add_results(scan_id: int, items: list[tuple[str, str, str]]) -> None:
    if not items:
        return
    con = _conn()
    try:
        con.executemany(
            "INSERT INTO results (scan_id, kind, title, detail, ts)"
            " VALUES (?,?,?,?,?)",
            [(scan_id, k, t, d, _now()) for k, t, d in items])
        con.commit()
    finally:
        con.close()


def list_results(scan_id: int) -> list[dict]:
    con = _conn()
    try:
        rows = con.execute(
            "SELECT * FROM results WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


# ---------------------------- targets ---------------------------------- #
def touch_target(target: str) -> None:
    if not target.strip():
        return
    con = _conn()
    try:
        con.execute(
            "INSERT INTO targets (target, hits, last_used) VALUES (?, 1, ?)"
            " ON CONFLICT(target) DO UPDATE SET"
            " hits = hits + 1, last_used = excluded.last_used",
            (target.strip(), _now()))
        con.commit()
    finally:
        con.close()


def recent_targets(limit: int = 25) -> list[str]:
    con = _conn()
    try:
        rows = con.execute(
            "SELECT target FROM targets"
            " ORDER BY last_used DESC, hits DESC LIMIT ?",
            (limit,)).fetchall()
        return [r["target"] for r in rows]
    finally:
        con.close()


# ---------------------------- settings --------------------------------- #
def get_setting(key: str, default: str = "") -> str:
    con = _conn()
    try:
        row = con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default
    finally:
        con.close()


def set_setting(key: str, value: str) -> None:
    con = _conn()
    try:
        con.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value))
        con.commit()
    finally:
        con.close()