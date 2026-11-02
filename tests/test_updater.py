# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

from __future__ import annotations

import os

import pytest

from utilities.updater import EncryptHomeUpdater


def test_github_release_manifest_preserves_asset_digest(monkeypatch, tmp_path):
    monkeypatch.setattr(EncryptHomeUpdater, "_user_update_dir", staticmethod(lambda: str(tmp_path)))
    monkeypatch.setattr("utilities.updater.platform.system", lambda: "Linux")

    manifest = EncryptHomeUpdater._github_release_to_manifest(
        {
            "tag_name": "v27.0.1",
            "published_at": "2026-11-02T00:00:00Z",
            "assets": [
                {
                    "name": "EncryptHome-Linux",
                    "browser_download_url": "https://example.test/EncryptHome-Linux",
                    "digest": "sha256:" + "a" * 64,
                    "size": 1024 * 1024,
                }
            ],
        }
    )

    assert manifest["version"] == "27.0.1"
    assert manifest["sha256"] == "a" * 64
    assert manifest["size_mb"] == 1.0


@pytest.mark.parametrize(
    ("system", "expected"),
    [
        ("Windows", "EncryptHome-Windows.exe"),
        ("Darwin", "EncryptHome-macOS"),
        ("Linux", "EncryptHome-Linux"),
    ],
)
def test_github_release_asset_avoids_installer(monkeypatch, system, expected):
    monkeypatch.setattr("utilities.updater.platform.system", lambda: system)
    release = {
        "assets": [
            {"name": "EncryptHome-Setup.exe"},
            {"name": "EncryptHome-Linux"},
            {"name": "EncryptHome-macOS"},
            {"name": "EncryptHome-Windows.exe"},
        ]
    }

    assert EncryptHomeUpdater._github_release_asset(release)["name"] == expected


def test_update_directory_is_user_writable(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr("utilities.updater.platform.system", lambda: "Linux")

    update_dir = EncryptHomeUpdater._user_update_dir()
    assert update_dir.startswith(str(tmp_path))
    assert EncryptHomeUpdater._path_is_writable(os.path.join(update_dir, "app"))


def test_user_install_path_is_outside_application_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(EncryptHomeUpdater, "_user_update_dir", staticmethod(lambda: str(tmp_path / "updates")))
    updater = EncryptHomeUpdater("27.0.1", "https://example.test/releases/latest")

    target = updater._user_install_path(str(tmp_path / "updates" / "EncryptHome-Linux"))

    assert target == os.path.join(str(tmp_path), "app", "EncryptHome")
    assert target != str(tmp_path / "updates" / "EncryptHome-Linux")
