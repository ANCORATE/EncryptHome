import os
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import app.core
from app.core import HEADER_LEN, META_LEN_SIZE, SALT_LEN, write_header
from app.workers import AddWorker, DeleteWorker, MetadataSaveWorker
from decrypt import decrypt_blob_range, decrypt_meta
from encrypt import encrypt_file_to_blob, encrypt_meta
from utilities.container_ops import (
    _META_JOURNAL_MAGIC,
    atomic_container_update,
    atomic_container_write,
    new_file_entry,
    recover_container_metadata,
    save_container_metadata,
)


class AtomicContainerUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.vault_path = os.path.join(self.temp_dir.name, "test.salt")
        self.master_key = b"K" * 32
        self.initial_meta = {"files": [], "created": 1, "flags": 0}
        self._write_vault(self.initial_meta)

    def _write_vault(self, meta):
        meta_blob = encrypt_meta(meta, self.master_key)
        with open(self.vault_path, "wb") as vault:
            write_header(vault, 0, b"S" * SALT_LEN)
            vault.write(meta_blob)
            vault.write(struct.pack("<Q", len(meta_blob)))

    def _read_meta(self):
        with open(self.vault_path, "rb") as vault:
            vault.seek(-META_LEN_SIZE, os.SEEK_END)
            meta_length = struct.unpack("<Q", vault.read(META_LEN_SIZE))[0]
            vault.seek(-META_LEN_SIZE - meta_length, os.SEEK_END)
            return decrypt_meta(vault.read(meta_length), self.master_key)

    def test_failed_update_leaves_original_bytes_unchanged(self):
        original = Path(self.vault_path).read_bytes()

        with self.assertRaisesRegex(RuntimeError, "simulated failure"):
            with atomic_container_update(self.vault_path, self.master_key) as (
                destination,
                _meta,
            ):
                destination.write(b"incomplete replacement")
                raise RuntimeError("simulated failure")

        self.assertEqual(Path(self.vault_path).read_bytes(), original)

    def test_invalid_metadata_length_is_rejected_without_more_changes(self):
        with open(self.vault_path, "rb+") as vault:
            vault.seek(-META_LEN_SIZE, os.SEEK_END)
            vault.write(struct.pack("<Q", 0))
        damaged = Path(self.vault_path).read_bytes()

        with self.assertRaisesRegex(ValueError, "Metadatenlänge"):
            with atomic_container_update(self.vault_path, self.master_key):
                self.fail("Invalid metadata length must not enter the update")

        self.assertEqual(Path(self.vault_path).read_bytes(), damaged)

    def test_copy_progress_and_mid_copy_cancel_preserve_original(self):
        with open(self.vault_path, "rb") as vault:
            existing_meta = self._read_meta()
        meta_blob = encrypt_meta(existing_meta, self.master_key)
        with open(self.vault_path, "wb") as vault:
            write_header(vault, 0, b"S" * SALT_LEN)
            vault.write(b"x" * (2 * 1024 * 1024))
            vault.write(meta_blob)
            vault.write(struct.pack("<Q", len(meta_blob)))
        original = Path(self.vault_path).read_bytes()
        stop_event = threading.Event()
        progress_values = []

        def cancel_after_copy_starts(value):
            progress_values.append(value)
            if value >= 40:
                stop_event.set()

        with self.assertRaisesRegex(RuntimeError, "abgebrochen"):
            with atomic_container_update(
                self.vault_path,
                self.master_key,
                progress_cb=cancel_after_copy_starts,
                stop_event=stop_event,
            ):
                self.fail("Cancelled update must not yield a writable replacement")

        self.assertTrue(progress_values)
        self.assertEqual(progress_values, sorted(progress_values))
        self.assertEqual(Path(self.vault_path).read_bytes(), original)

    def test_add_cancellation_preserves_vault_and_success_round_trips_blob(self):
        source_path = os.path.join(self.temp_dir.name, "source.txt")
        original_data = b"atomic add regression test" * 100
        Path(source_path).write_bytes(original_data)
        original_vault = Path(self.vault_path).read_bytes()

        stop_event = threading.Event()
        stop_event.set()
        errors = []
        cancelled_worker = AddWorker(
            self.vault_path, [source_path], self.master_key, 0, stop_event
        )
        cancelled_worker.error.connect(errors.append)
        cancelled_worker.run()
        self.assertTrue(errors)
        self.assertEqual(Path(self.vault_path).read_bytes(), original_vault)

        completed = []
        errors = []
        progress_values = []
        stages = []
        worker = AddWorker(
            self.vault_path,
            [source_path],
            self.master_key,
            0,
            threading.Event(),
        )
        worker.finished.connect(completed.append)
        worker.error.connect(errors.append)
        worker.progress.connect(progress_values.append)
        worker.stage.connect(stages.append)
        with patch("app.workers.load_settings", return_value={"del_source_added": False}):
            worker.run()

        self.assertFalse(errors, errors)
        self.assertEqual(completed, [["source.txt"]])
        self.assertEqual(progress_values[-1], 100)
        self.assertEqual(progress_values[0], 20)
        self.assertIn("Kopiere vorhandene Tresordaten sicher...", stages)
        self.assertIn("Prüfe Datei 1 von 1...", stages)
        self.assertIn("Schreibe Tresor sicher...", stages)
        entry = self._read_meta()["files"][0]
        restored_path = os.path.join(self.temp_dir.name, "restored.txt")
        with open(self.vault_path, "rb") as vault:
            vault.seek(entry["offset"])
            decrypt_blob_range(
                vault,
                restored_path,
                entry["length"],
                self.master_key,
                entry["name"],
            )
        self.assertEqual(Path(restored_path).read_bytes(), original_data)

    def test_metadata_save_updates_only_metadata_and_recovers_interrupted_write(self):
        original_meta = self._read_meta()
        original_blob = Path(self.vault_path).read_bytes()
        updated_meta = original_meta | {"folders": ["Projects"]}
        save_container_metadata(
            self.vault_path, updated_meta, self.master_key
        )
        self.assertEqual(self._read_meta()["folders"], ["Projects"])
        updated_bytes = Path(self.vault_path).read_bytes()
        self.assertEqual(updated_bytes[:HEADER_LEN], original_blob[:HEADER_LEN])
        self.assertFalse(os.path.exists(self.vault_path + ".anc-meta-recovery"))

        with open(self.vault_path, "rb") as vault:
            current_bytes = vault.read()
        current_meta = self._read_meta()
        current_meta_blob = encrypt_meta(current_meta, self.master_key)
        old_meta_blob = encrypt_meta(original_meta, self.master_key)
        journal_path = self.vault_path + ".anc-meta-recovery"
        with open(journal_path, "wb") as journal:
            journal.write(_META_JOURNAL_MAGIC)
            journal.write(b"\x00")
            journal.write(struct.pack("<QQ", len(original_blob), len(old_meta_blob)))
            journal.write(old_meta_blob)

        current_meta_pos = len(current_bytes) - META_LEN_SIZE - len(current_meta_blob)
        with open(self.vault_path, "rb+") as vault:
            vault.truncate(current_meta_pos + max(1, len(current_meta_blob) // 2))

        self.assertTrue(recover_container_metadata(self.vault_path))
        self.assertEqual(self._read_meta(), original_meta)
        self.assertEqual(Path(self.vault_path).stat().st_size, len(original_blob))
        self.assertFalse(os.path.exists(journal_path))
        recovered_bytes = Path(self.vault_path).read_bytes()

        with open(journal_path, "wb") as journal:
            journal.write(_META_JOURNAL_MAGIC)
            journal.write(b"\x01")
            journal.write(struct.pack("<QQ", len(original_blob), len(old_meta_blob)))
            journal.write(old_meta_blob)
        self.assertFalse(recover_container_metadata(self.vault_path))
        self.assertEqual(Path(self.vault_path).read_bytes(), recovered_bytes)
        self.assertFalse(os.path.exists(journal_path))

    def test_delete_worker_reopens_vault_after_removing_entry(self):
        source_path = os.path.join(self.temp_dir.name, "delete-source.bin")
        source_data = b"delete worker regression" * 64
        Path(source_path).write_bytes(source_data)
        entries = []
        with open(self.vault_path, "wb") as vault:
            write_header(vault, 0, b"S" * SALT_LEN)
            for index in range(2):
                name = f"file{index}.bin"
                offset = vault.tell()
                encrypt_file_to_blob(source_path, vault, self.master_key, filename=name)
                length = vault.tell() - offset
                entries.append(
                    new_file_entry(name, len(source_data), offset, length)
                )
            metadata = self.initial_meta | {"files": entries}
            meta_blob = encrypt_meta(metadata, self.master_key)
            vault.write(meta_blob)
            vault.write(struct.pack("<Q", len(meta_blob)))

        finished = []
        errors = []
        worker = DeleteWorker(
            self.vault_path,
            metadata,
            0,
            self.master_key,
            "Standard (Schnell)",
            threading.Event(),
        )
        worker.finished.connect(
            lambda name, new_meta, overwrite_error: finished.append(
                (name, new_meta, overwrite_error)
            )
        )
        worker.error.connect(errors.append)
        worker.run()

        self.assertFalse(errors, errors)
        self.assertEqual(finished[0][0], "file0.bin")
        self.assertEqual(finished[0][2], "")
        reopened_meta = self._read_meta()
        self.assertEqual([entry["name"] for entry in reopened_meta["files"]], ["file1.bin"])
        restored_path = os.path.join(self.temp_dir.name, "remaining.bin")
        remaining = reopened_meta["files"][0]
        with open(self.vault_path, "rb") as vault:
            vault.seek(remaining["offset"])
            decrypt_blob_range(
                vault,
                restored_path,
                remaining["length"],
                self.master_key,
                remaining["name"],
            )
        self.assertEqual(Path(restored_path).read_bytes(), source_data)
        self.assertFalse(list(Path(self.temp_dir.name).glob("*.anc-delete-*")))

    def test_failed_confirmed_overwrite_keeps_existing_vault(self):
        original = Path(self.vault_path).read_bytes()
        confirmed_stat = os.stat(self.vault_path)

        with self.assertRaisesRegex(RuntimeError, "simulated failure"):
            with atomic_container_write(
                self.vault_path, expected_stat=confirmed_stat
            ) as destination:
                destination.write(b"incomplete new vault")
                raise RuntimeError("simulated failure")

        self.assertEqual(Path(self.vault_path).read_bytes(), original)

    def test_confirmed_overwrite_replaces_only_the_confirmed_file(self):
        confirmed_stat = os.stat(self.vault_path)
        with atomic_container_write(
            self.vault_path, expected_stat=confirmed_stat
        ) as destination:
            write_header(destination, 0, b"N" * SALT_LEN)
            new_blob = encrypt_meta(
                self.initial_meta | {"created": 2}, self.master_key
            )
            destination.write(new_blob)
            destination.write(struct.pack("<Q", len(new_blob)))

        self.assertEqual(self._read_meta()["created"], 2)

    def test_new_vault_write_rejects_a_file_created_mid_operation(self):
        target_path = os.path.join(self.temp_dir.name, "new.salt")
        with self.assertRaisesRegex(RuntimeError, "außerhalb der App"):
            with atomic_container_write(
                target_path, expected_stat=None
            ) as destination:
                destination.write(b"temporary vault")
                Path(target_path).write_bytes(b"concurrent file")

        self.assertEqual(Path(target_path).read_bytes(), b"concurrent file")


if __name__ == "__main__":
    unittest.main()