
import unittest
from unittest.mock import patch

from utilities.updater import (
    EncryptHomeUpdater,
    parse_version,
    validate_latest_json,
)


class ParseVersionTests(unittest.TestCase):

    def test_newer_version(self):
        self.assertGreater(
            parse_version("27.0"),
            parse_version("26.9")
        )

    def test_release_is_newer_than_prerelease(self):
        self.assertLess(
            parse_version("27.0-beta.1"),
            parse_version("27.0")
        )

    def test_build_metadata_is_ignored(self):
        self.assertEqual(
            parse_version("1.2.3+build"),
            parse_version("1.2.3")
        )

    def test_invalid_version_raises(self):
        with self.assertRaises(ValueError):
            parse_version("invalid-version")

    def test_fourth_component_is_compared(self):
        self.assertLess(
            parse_version("27.0.1.1"),
            parse_version("27.0.1.2")
        )

    def test_beta_numbers_are_compared_numerically(self):
        self.assertLess(
            parse_version("27.0-beta.2"),
            parse_version("27.0-beta.10")
        )

    def test_alpha_is_older_than_beta(self):
        self.assertLess(
            parse_version("27.0-alpha.1"),
            parse_version("27.0-beta.1")
        )

    def test_build_metadata_does_not_change_order(self):
        self.assertEqual(
            parse_version("27.0+build.1"),
            parse_version("27.0+build.2")
        )

    def test_invalid_build_metadata_raises(self):
        with self.assertRaises(ValueError):
            parse_version("1.2.3+build..1")

    def test_numeric_prerelease_identifier_cannot_have_leading_zeroes(self):
        with self.assertRaises(ValueError):
            parse_version("1.2.3-beta.01")

    def test_legacy_prerelease_aliases_are_case_insensitive(self):
        self.assertEqual(
            parse_version("1.0.0-BETA.1"),
            parse_version("1.0.0-beta.1")
        )
        self.assertEqual(
            parse_version("1.0.0-RC1"),
            parse_version("1.0.0-rc1")
        )

    def test_legacy_alpha_alias_matches_alpha(self):
        self.assertEqual(
            parse_version("1.0.0-a.1"),
            parse_version("1.0.0-alpha.1")
        )

    def test_legacy_beta_alias_matches_beta(self):
        self.assertEqual(
            parse_version("1.0.0-b.1"),
            parse_version("1.0.0-beta.1")
        )

    def test_compact_rc_numbers_are_compared_numerically(self):
        self.assertLess(
            parse_version("1.0.0-rc1"),
            parse_version("1.0.0-rc2")
        )

    def test_compact_prerelease_matches_dotted_form(self):
        self.assertEqual(
            parse_version("1.0.0-beta10"),
            parse_version("1.0.0-beta.10")
        )

    def test_stable_alias_matches_release(self):
        self.assertEqual(
            parse_version("1.0.0-stable"),
            parse_version("1.0.0")
        )

    def test_manifest_rejects_malformed_version(self):
        with self.assertRaises(ValueError):
            validate_latest_json({
                "version": "invalid-version",
                "url": "https://example.com/update.exe",
            })

    def _run_update(self, current_version, latest_version):
        updater = object.__new__(EncryptHomeUpdater)
        updater.current_version = current_version
        updater.channel = "stable"
        manifest = {
            "version": latest_version,
            "url": "https://example.com/update.exe",
        }
        with patch.object(
            EncryptHomeUpdater,
            "fetch_manifest",
            return_value=manifest
        ):
            return updater.run()

    def test_stable_release_is_available_for_same_prerelease_core(self):
        result = self._run_update("27.0.1.2-beta.1", "27.0.1.2")
        self.assertEqual(result["status"], "UPDATE_AVAILABLE")

    def test_stable_release_with_lower_extra_component_is_not_available(self):
        result = self._run_update("27.0.1.2-beta.1", "27.0.1.1")
        self.assertEqual(result["status"], "NO_UPDATE")


if __name__ == "__main__":
    unittest.main()
