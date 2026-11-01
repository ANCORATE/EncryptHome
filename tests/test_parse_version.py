
import unittest

from utilities.updater import parse_version


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

    def test_prerelease_identifiers_are_case_sensitive(self):
        self.assertNotEqual(
            parse_version("1.0.0-BETA"),
            parse_version("1.0.0-beta")
        )


if __name__ == "__main__":
    unittest.main()
