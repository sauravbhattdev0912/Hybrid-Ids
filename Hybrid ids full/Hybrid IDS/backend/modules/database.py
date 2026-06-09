"""
database.py
-----------
Simple SQLite database helper.

The database stores only three useful things:
1. alerts          -> attack records
2. logs            -> attack + normal records
3. traffic_history -> packet count for chart
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent.parent / "data" / "ids.db"


def now_utc() -> str:
    """Return current time in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def get_connection() -> sqlite3.Connection:
    """Open database connection."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if this is the first run."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT,
            port INTEGER,
            protocol TEXT,
            type TEXT,
            method TEXT,
            confidence REAL,
            raw_packet TEXT
        );

        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT,
            port INTEGER,
            protocol TEXT,
            type TEXT,
            method TEXT,
            verdict TEXT,
            stage TEXT
        );

        CREATE TABLE IF NOT EXISTS traffic_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            count INTEGER NOT NULL
        );
        """
    )

    conn.commit()
    conn.close()


def save_alert(packet: dict, attack_type: str, method: str, confidence: float) -> None:
    """Save one attack alert."""
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO alerts
        (timestamp, ip, port, protocol, type, method, confidence, raw_packet)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            now_utc(),
            packet.get("ip", "unknown"),
            int(packet.get("port", 0)),
            str(packet.get("protocol", "TCP")).upper(),
            attack_type,
            method,
            confidence,
            json.dumps(packet),
        ),
    )
    conn.commit()
    conn.close()


def save_log(packet: dict, attack_type: str, method: str | None, verdict: str, stage: str) -> None:
    """Save one detection log."""
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO logs
        (timestamp, ip, port, protocol, type, method, verdict, stage)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            now_utc(),
            packet.get("ip", "unknown"),
            int(packet.get("port", 0)),
            str(packet.get("protocol", "TCP")).upper(),
            attack_type,
            method,
            verdict,
            stage,
        ),
    )
    conn.commit()
    conn.close()


def save_traffic_count(count: int) -> None:
    """Save packet count for the traffic chart."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO traffic_history (timestamp, count) VALUES (?, ?)",
        (now_utc(), int(count)),
    )
    conn.commit()
    conn.close()


def get_alerts(limit: int = 100, method: str | None = None) -> list[dict]:
    """Return recent alerts."""
    conn = get_connection()
    if method:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE method=? ORDER BY id DESC LIMIT ?",
            (method, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_logs(limit: int = 100, method: str | None = None) -> list[dict]:
    """Return recent logs."""
    conn = get_connection()
    if method:
        rows = conn.execute(
            "SELECT * FROM logs WHERE method=? ORDER BY id DESC LIMIT ?",
            (method, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM logs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_stats() -> dict:
    """Return numbers used by dashboard cards."""
    conn = get_connection()
    total_traffic = conn.execute("SELECT COALESCE(SUM(count), 0) FROM traffic_history").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    signature_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE method='Signature'").fetchone()[0]
    anomaly_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE method='Anomaly'").fetchone()[0]
    conn.close()

    return {
        "totalTraffic": int(total_traffic),
        "totalAlerts": int(total_alerts),
        "signatureDetections": int(signature_count),
        "anomalyDetections": int(anomaly_count),
    }


def get_traffic_series(n: int = 20) -> dict:
    """Return data for traffic line chart."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT timestamp, count FROM traffic_history ORDER BY id DESC LIMIT ?",
        (n,),
    ).fetchall()
    conn.close()

    rows = list(reversed(rows))
    labels = [row["timestamp"][11:16] for row in rows]
    values = [row["count"] for row in rows]
    return {"labels": labels, "values": values}
