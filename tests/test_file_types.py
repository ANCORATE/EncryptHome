
# SPDX-License-Identifier: MIT
# Copyright (c) 2026

import unittest

from utilities.file_types import (
    sniff_magic,
    detect_type_key,
    type_label,
    guess_kind,
    KIND_IMAGE,
    KIND_PDF,
    KIND_TEXT,
    KIND_BINARY,
)


class FileTypeDetectionTests(unittest.TestCase):

    def test_detect_png_from_magic_bytes(self):
        data = b"\x89PNG\r\n\x1a\n"
        self.assertEqual(sniff_magic(data), "png")
        self.assertEqual(detect_type_key("photo.txt", data), "png")

    def test_detect_pdf_from_magic_bytes(self):
        data = b"%PDF-1.7"
        self.assertEqual(sniff_magic(data), "pdf")
        self.assertEqual(guess_kind("document.pdf", data), KIND_PDF)

    def test_content_overrides_filename_extension(self):
        data = b"\x89PNG\r\n\x1a\n"
        self.assertEqual(detect_type_key("document.pdf", data), "png")
        self.assertEqual(type_label("document.pdf", data), "PNG-Bild")

    def test_detect_compound_tar_gz_extension(self):
        self.assertEqual(detect_type_key("backup.tar.gz"), "gzip")

    def test_detect_text_content(self):
        data = b"Hello, this is a simple text file."
        self.assertEqual(sniff_magic(data), "text")
        self.assertEqual(guess_kind("notes.txt", data), KIND_TEXT)

    def test_unknown_binary_falls_back_to_binary(self):
        data = b"\x00\x01\x02\x03\x04\x05"
        self.assertIsNone(sniff_magic(data))
        self.assertEqual(guess_kind("unknown.xyz", data), KIND_BINARY)
        self.assertEqual(type_label("unknown.xyz", data), "Unbekannt")

    def test_extension_detection_is_case_insensitive(self):
        self.assertEqual(detect_type_key("PHOTO.PNG"), "png")
        self.assertEqual(detect_type_key("REPORT.PDF"), "pdf")


if __name__ == "__main__":
    unittest.main()
