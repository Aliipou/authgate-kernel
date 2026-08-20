"""Pytest bootstrap — fail-closed API requires admin token + audit path."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

os.environ.setdefault("AUTHGATE_ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault(
    "AUTHGATE_AUDIT_PATH",
    str(Path(tempfile.gettempdir()) / "authgate-pytest-audit.jsonl"),
)
os.environ.setdefault("AUTHGATE_BACKEND", "python")
