"""Tests for the CheckpointStore."""

import os
import tempfile
from mantis.core.checkpoint import CheckpointStore, Checkpoint


def test_save_and_load():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        store = CheckpointStore(db_path=db_path)

        cp = Checkpoint(
            session_id="test-001",
            phase="scanning",
            step_index=5,
            agent_state={"history": [{"role": "user", "content": "test"}]},
            findings_so_far=[{"title": "XSS", "severity": "high"}],
        )
        store.save(cp)

        loaded = store.latest("test-001")
        assert loaded is not None
        assert loaded.phase == "scanning"
        assert loaded.step_index == 5
        assert len(loaded.findings_so_far) == 1


def test_resume_or_start():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        store = CheckpointStore(db_path=db_path)

        # First call: creates new
        cp = store.resume_or_start("new-session", {"targets": ["example.com"]})
        assert cp.phase == "init"
        assert cp.step_index == 0

        # Save progress
        cp.phase = "scanning"
        cp.step_index = 10
        store.save(cp)

        # Second call: resumes
        cp2 = store.resume_or_start("new-session", {})
        assert cp2.phase == "scanning"
        assert cp2.step_index == 10
