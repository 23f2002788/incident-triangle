import json
import os
import sqlite3
from typing import Any

DB_PATH = os.environ.get("INCIDENT_DB_PATH", "incident_state.sqlite3")


def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                state_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                run_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                PRIMARY KEY (run_id, receipt_id),
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            )
        """)


def get_run(run_id: str):
    with connect() as conn:
        row = conn.execute(
            "SELECT run_id, request_hash, state_json FROM runs WHERE run_id=?",
            (run_id,)
        ).fetchone()
    if not row:
        return None
    return {
        "run_id": row["run_id"],
        "request_hash": row["request_hash"],
        "state": json.loads(row["state_json"]),
    }


def save_new_run(run_id: str, request_hash: str, state: dict[str, Any]):
    with connect() as conn:
        conn.execute(
            "INSERT INTO runs(run_id, request_hash, state_json) VALUES(?,?,?)",
            (run_id, request_hash, json.dumps(state, separators=(",", ":")))
        )


def save_receipt_result(run_id: str, receipt_id: str, receipt_hash: str, state: dict):
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        prior = conn.execute(
            "SELECT receipt_hash FROM receipts WHERE run_id=? AND receipt_id=?",
            (run_id, receipt_id)
        ).fetchone()
        if prior and prior["receipt_hash"] != receipt_hash:
            raise ValueError("receipt conflict")
        conn.execute(
            "INSERT OR IGNORE INTO receipts(run_id, receipt_id, receipt_hash) VALUES(?,?,?)",
            (run_id, receipt_id, receipt_hash)
        )
        conn.execute(
            "UPDATE runs SET state_json=? WHERE run_id=?",
            (json.dumps(state, separators=(",", ":")), run_id)
        )
        conn.commit()


def update_run_state(run_id: str, state: dict):
    with connect() as conn:
        conn.execute(
            "UPDATE runs SET state_json=? WHERE run_id=?",
            (json.dumps(state, separators=(",", ":")), run_id)
        )


def get_receipt(run_id: str, receipt_id: str):
    with connect() as conn:
        row = conn.execute(
            "SELECT receipt_hash FROM receipts WHERE run_id=? AND receipt_id=?",
            (run_id, receipt_id)
        ).fetchone()
    return row["receipt_hash"] if row else None
