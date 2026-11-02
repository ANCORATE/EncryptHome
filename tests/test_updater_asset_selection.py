# SPDX-License-Identifier: MIT
"""Focused tests for update asset selection helpers."""

from __future__ import annotations

from utilities.updater import EncryptHomeUpdater


RELEASE = {
    "tag_name": "v27.1-beta",
    "assets": [
        {
            "name": "EncryptHome-Windows.exe",
            "browser_download_url": "https://example.test/EncryptHome-Windows.exe",
            "digest": "sha256:" + "a" * 64,
            "size": 4096,
        },
        {
            "name": "EncryptHome-Setup.exe",
            "browser_download_url": "https://example.test/EncryptHome-Setup.exe",
            "digest": "sha256:" + "b" * 64,
            "size": 8192,
        },
    ],
}


def test_portable_asset_is_selected_by_default():
    asset = EncryptHomeUpdater._github_release_asset(RELEASE, installer=False)
    assert asset is not None
    assert asset["name"] == "EncryptHome-Windows.exe"


def test_installer_asset_is_selected_when_requested():
    asset = EncryptHomeUpdater._github_release_asset(RELEASE, installer=True)
    assert asset is not None
    assert asset["name"] == "EncryptHome-Setup.exe"


def test_manifest_can_be_built_for_installer_asset():
    asset = EncryptHomeUpdater._github_release_asset(RELEASE, installer=True)
    manifest = EncryptHomeUpdater._github_release_to_manifest(RELEASE, asset=asset)
    assert manifest["version"] == "27.1-beta"
    assert manifest["url"].endswith("EncryptHome-Setup.exe")
    assert manifest["sha256"] == "b" * 64
