
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

    def test_invalid_version_does_not_raise(self):
        result = parse_version("invalid-version")
        self.assertEqual(result, (0, 0, 0, 0, 0))


if __name__ == "__main__":
    unittest.main()
