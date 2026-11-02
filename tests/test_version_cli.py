# SPDX-License-Identifier: MIT
"""CLI --version flag for main.py (#9)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_version() -> str:
    path = ROOT / "app" / "version.py"
    spec = importlib.util.spec_from_file_location("_encrypthome_version_test", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.version


def test_version_flag_prints_version_and_exits_zero() -> None:
    expected = _load_version()
    proc = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--version"],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == expected
    # Must not fall through into GUI startup chatter.
    assert "Initializing" not in proc.stdout
    assert "ENTER EVENT LOOP" not in proc.stdout
