"""
SQLite-based checkpoint store for session persistence.

Replaces LangGraph's built-in state checkpointing with a simpler,
queryable, portable solution. Each checkpoint captures the full
agent state: conversation history, findings, pending/completed
targets, and token usage.

Features:
- Save/load full agent state at any point
- Resume from last checkpoint after crash or manual pause
- Query past sessions and their findings
- Export session data for audit trails
"""

import sqlite3
import json
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Optional


@dataclass
class Checkpoint:
    """A snapshot of agent state at a point in time."""
    session_id: str
    phase: str                              # Current phase name
    step_index: int                         # Iteration count
    agent_state: dict                       # Full conversation history + context
    findings_so_far: list[dict]             # Accumulated findings
    pending_targets: list[str] = field(default_factory=list)
    completed_targets: list[str] = field(default_factory=list)
    token_usage: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_phases: list[str] = field(default_factory=list)


class CheckpointStore:
    """
    Persistent session store backed by SQLite.

    Usage:
        store = CheckpointStore()
        cp = store.resume_or_start("session-123", {"targets": [...]})
        # ... do work ...
        store.save(cp)

    The DB file is portable — copy it to another machine and resume.
    """

    def __init__(self, db_path: str = "~/.mantis/mantis.db"):
        self.db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self._init_schema()

    def _init_schema(self):
        """Create tables if they don't exist."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS checkpoints (
                session_id TEXT,
                phase TEXT,
                step_index INTEGER,
                state_json TEXT,
                created_at TEXT,
                PRIMARY KEY (session_id, phase, step_index)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                mode TEXT,
                target TEXT,
                started_at TEXT,
                last_updated TEXT,
                status TEXT DEFAULT 'running',
                finding_count INTEGER DEFAULT 0,
                total_cost_usd REAL DEFAULT 0.0
            );

            CREATE INDEX IF NOT EXISTS idx_cp_session
                ON checkpoints(session_id, created_at DESC);
        """)
        self.conn.commit()

    def save(self, cp: Checkpoint):
        """Save a checkpoint. Overwrites if same session/phase/step."""
        state_json = json.dumps(asdict(cp), default=str)
        self.conn.execute(
            "INSERT OR REPLACE INTO checkpoints VALUES (?, ?, ?, ?, ?)",
            (cp.session_id, cp.phase, cp.step_index, state_json, cp.timestamp),
        )
        # Update session summary
        self.conn.execute("""
            INSERT INTO sessions (session_id, started_at, last_updated,
                                  finding_count, total_cost_usd, status)
            VALUES (?, ?, ?, ?, ?, 'running')
            ON CONFLICT(session_id) DO UPDATE SET
                last_updated = excluded.last_updated,
                finding_count = excluded.finding_count,
                total_cost_usd = excluded.total_cost_usd,
                status = CASE WHEN ? = 'complete' THEN 'complete' ELSE status END
        """, (
            cp.session_id, cp.timestamp, cp.timestamp,
            len(cp.findings_so_far),
            cp.token_usage.get("cost_usd", 0.0),
            cp.phase,
        ))
        self.conn.commit()

    def latest(self, session_id: str) -> Optional[Checkpoint]:
        """Load the most recent checkpoint for a session."""
        row = self.conn.execute(
            "SELECT state_json FROM checkpoints "
            "WHERE session_id = ? ORDER BY step_index DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        if row:
            data = json.loads(row[0])
            return Checkpoint(**data)
        return None

    def resume_or_start(self, session_id: str, initial_state: dict) -> Checkpoint:
        """Load existing checkpoint or create a new one."""
        existing = self.latest(session_id)
        if existing:
            print(f"[*] Resuming session {session_id}")
            print(f"    Phase: {existing.phase}, Step: {existing.step_index}, "
                  f"Findings: {len(existing.findings_so_far)}")
            return existing

        return Checkpoint(
            session_id=session_id,
            phase="init",
            step_index=0,
            agent_state=initial_state,
            findings_so_far=[],
            pending_targets=initial_state.get("targets", []),
            completed_targets=[],
            token_usage={"prompt": 0, "completion": 0, "cost_usd": 0.0},
        )

    def list_sessions(self) -> list[dict]:
        """List all sessions with summary info."""
        rows = self.conn.execute(
            "SELECT * FROM sessions ORDER BY last_updated DESC"
        ).fetchall()
        cols = [
            "session_id", "mode", "target", "started_at",
            "last_updated", "status", "finding_count", "total_cost_usd",
        ]
        return [dict(zip(cols, row)) for row in rows]

    def delete_session(self, session_id: str):
        """Delete all checkpoints for a session."""
        self.conn.execute("DELETE FROM checkpoints WHERE session_id = ?", (session_id,))
        self.conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        self.conn.commit()
