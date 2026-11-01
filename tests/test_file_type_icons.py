# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from utilities.file_type_icons import file_type_icon


class FileTypeIconTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def test_common_types_render_with_distinct_custom_icons(self):
        filenames = (
            "report.docx",
            "table.xlsx",
            "slides.pptx",
            "movie.mp4",
            "photo.png",
            "song.mp3",
            "backup.zip",
            "source.py",
            "data.db",
            "unknown.xyz",
        )
        icons = [file_type_icon(filename) for filename in filenames]
        self.assertTrue(all(not icon.isNull() for icon in icons))

        images = [icon.pixmap(48, 48).toImage() for icon in icons]
        self.assertTrue(all(not image.isNull() for image in images))
        self.assertNotEqual(images[0], images[1])
        self.assertNotEqual(images[0], images[2])
        self.assertNotEqual(images[3], images[4])


if __name__ == "__main__":
    unittest.main()