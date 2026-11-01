# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

import unittest

from utilities.updater import parse_version


class ParseVersionTests(unittest.TestCase):
    def test_newer_stable_version_compares_greater(self):
        self.assertGreater(parse_version("27.0"), parse_version("26.9"))

    def test_prerelease_compares_less_than_stable_release(self):
        self.assertLess(parse_version("27.0-beta.1"), parse_version("27.0"))

    def test_build_metadata_is_ignored(self):
        self.assertEqual(parse_version("1.2.3+build"), parse_version("1.2.3"))

    def test_invalid_input_returns_zero_tuple_without_crashing(self):
        self.assertEqual(parse_version("not-a-version"), (0, 0, 0, 0, 0))


if __name__ == "__main__":
    unittest.main()
