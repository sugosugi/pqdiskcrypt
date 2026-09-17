"""Real-file regressions for manually saved headers and safe volume renewal."""
import copy
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pqdiskcrypt as P

SMALL = {"timeCost": 1, "memKiB": 8, "parallelism": 1}


class ManualHeaderCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pqdisk-manual-header-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.pq = P.PQCrypto()
        self.fs = P.VolumeFS(self.pq)

    def volume(self, hide=False):
        volume = self.pq.new_volume(hide_names=hide)
        self.pq.add_password_slot(volume["header"], volume["vmk"], "Manual-header-password!", SMALL)
        return volume, {"vmk": volume["vmk"], "volumeId": volume["volumeId"], "hideNames": hide}

    def root(self, name="data"):
        root = self.base / name
        root.mkdir()
        (root / "document.txt").write_bytes(b"document contents" * 500)
        return root

    def test_selected_header_only_is_saved_and_survives_roundtrip(self):
        for hide in (False, True):
            for location in ("outside", "root", "nested"):
                with self.subTest(hide=hide, location=location):
                    root = self.root("%s-%s" % (hide, location))
                    volume, ctx = self.volume(hide)
                    if location == "outside":
                        destination = self.base / (root.name + "-chosen.data")
                    elif location == "root":
                        destination = root / "chosen.data"
                    else:
                        (root / "nested").mkdir()
                        destination = root / "nested" / "chosen.data"
                    saved = self.fs.save_encryption_header(str(root), volume["header"], str(destination))
                    raw = destination.read_bytes()
                    self.assertEqual(saved, str(destination.resolve()))
                    self.assertFalse((root / P.VOLUME_HEADER_NAME).exists())
                    self.assertEqual(self.fs.scan_tree(str(root), header_path=saved)["files"], 1)
                    result = self.fs.encrypt_tree(str(root), ctx, header_path=saved)
                    self.assertEqual((result["files"], result["errors"]), (1, []))
                    self.assertEqual(destination.read_bytes(), raw)
                    result = self.fs.decrypt_tree(str(root), ctx)
                    self.assertEqual((result["files"], result["errors"], result["headerRemoved"]), (1, [], False))
                    self.assertEqual((root / "document.txt").read_bytes(), b"document contents" * 500)
                    self.assertEqual(destination.read_bytes(), raw)
                    self.assertFalse((root / P.VOLUME_HEADER_NAME).exists())

    def test_only_exact_selected_arbitrary_path_is_excluded(self):
        root = self.root()
        volume, ctx = self.volume()
        selected = root / "chosen.data"
        self.fs.save_encryption_header(str(root), volume["header"], str(selected))
        (root / "ordinary.data").write_bytes(selected.read_bytes())
        self.assertEqual(self.fs.scan_tree(str(root), header_path=str(selected))["files"], 2)
        result = self.fs.encrypt_tree(str(root), ctx, header_path=str(selected))
        self.assertEqual(result["files"], 2)
        self.assertTrue(selected.exists())
        self.assertTrue((root / "ordinary.data.pqfc").exists())

    def test_selected_header_requires_matching_full_id_and_layout(self):
        root = self.root()
        volume, ctx = self.volume()
        foreign, _ = self.volume()
        # Even matching filename prefixes cannot authorize another full ID.
        foreign["header"]["volume_id"] = P.b64encode(ctx["volumeId"][:6] + b"x" * (P.VOLUME_ID_LEN - 6))
        selected = self.base / "selected.data"
        for invalid in (foreign["header"], dict(volume["header"], hide_names=True)):
            with self.subTest(header=invalid["volume_id"], hide=invalid["hide_names"]):
                selected.write_text(P.header_json(invalid), encoding="utf-8")
                with self.assertRaises(P.PQError) as raised:
                    self.fs.encrypt_tree(str(root), ctx, header_path=str(selected))
                self.assertEqual(raised.exception.code, "VOLUME_CHANGED")
                self.assertTrue((root / "document.txt").exists())

    def test_decrypt_keeps_legacy_header_by_default(self):
        root = self.root()
        volume, ctx = self.volume()
        self.fs.write_volume_header(str(root), volume["header"])
        self.fs.encrypt_tree(str(root), ctx)
        raw = (root / P.VOLUME_HEADER_NAME).read_bytes()
        result = self.fs.decrypt_tree(str(root), ctx)
        self.assertFalse(result["headerRemoved"])
        self.assertEqual(result["removedHeaders"], [])
        self.assertEqual((root / P.VOLUME_HEADER_NAME).read_bytes(), raw)

    def test_decrypt_then_reencrypt_replaces_selected_old_header(self):
        for hide in (False, True):
            with self.subTest(hide=hide):
                root = self.root(str(hide))
                old, old_ctx = self.volume(hide)
                destination = self.base / (str(hide) + "-chosen.pqvolume")
                self.fs.save_encryption_header(str(root), old["header"], str(destination))
                self.fs.encrypt_tree(str(root), old_ctx, header_path=str(destination))
                self.assertFalse(self.fs.can_start_new_volume(str(root)))
                self.fs.decrypt_tree(str(root), old_ctx)
                self.assertTrue(self.fs.can_start_new_volume(str(root)))
                new, new_ctx = self.volume(hide)
                self.fs.save_encryption_header(str(root), new["header"], str(destination), previous_header=old["header"])
                self.assertNotEqual(old["header"]["volume_id"], self.fs.read_header_file(str(destination))["volume_id"])
                encrypted = self.fs.encrypt_tree(str(root), new_ctx, header_path=str(destination))
                self.assertEqual((encrypted["files"], encrypted["errors"]), (1, []))
                self.assertEqual(self.fs.decrypt_tree(str(root), new_ctx)["files"], 1)
                self.assertEqual((root / "document.txt").read_bytes(), b"document contents" * 500)
                self.assertFalse((root / P.VOLUME_HEADER_NAME).exists())

    def test_save_never_overwrites_unrelated_existing_files(self):
        root = self.root()
        old, _ = self.volume()
        new, _ = self.volume()
        other, _ = self.volume()
        destination = self.base / "chosen.data"
        cases = [(b"ordinary important file", old["header"]),
                 (P.header_json(other["header"]).encode(), old["header"]),
                 (P.header_json(old["header"]).encode(), None)]
        for contents, previous in cases:
            with self.subTest(previous=previous is not None, contents=contents[:20]):
                destination.write_bytes(contents)
                with self.assertRaises(P.PQError):
                    self.fs.save_encryption_header(str(root), new["header"], str(destination), previous_header=previous)
                self.assertEqual(destination.read_bytes(), contents)

    def test_any_remaining_ciphertext_blocks_header_replacement(self):
        old, ctx = self.volume()
        new, _ = self.volume()
        ciphertext = self.pq.encrypt_volume_bytes(ctx["vmk"], ctx["volumeId"], b"secret")
        for index, (name, contents) in enumerate((("renamed.data", ciphertext),
                (P.VOLUME_HEADER_NAME, ciphertext), ("truncated.data", ciphertext[:20]),
                ("magic-only.data", P.MAGIC))):
            with self.subTest(name=name):
                root = self.root("retained-%d" % index)
                (root / name).write_bytes(contents)
                destination = self.base / (str(index) + "-old.pqvolume")
                destination.write_text(P.header_json(old["header"]), encoding="utf-8")
                original = destination.read_bytes()
                self.assertFalse(self.fs.can_start_new_volume(str(root)))
                with self.assertRaises(P.PQError) as raised:
                    self.fs.save_encryption_header(str(root), new["header"], str(destination), previous_header=old["header"])
                self.assertEqual(raised.exception.code, "VOLUME_NOT_EMPTY")
                self.assertEqual(destination.read_bytes(), original)

    def test_manifest_temporary_and_unscanned_directory_block_new_volume(self):
        for index, name in enumerate((P.DIR_MANIFEST_NAME, P.TMP_PREFIX + "left", "System Volume Information")):
            root = self.root("metadata-%d" % index)
            if name in P.SYSTEM_DIRS:
                (root / name).mkdir()
            else:
                (root / name).write_bytes(b"leftover")
            self.assertFalse(self.fs.can_start_new_volume(str(root)))

    def test_unreadable_and_link_entries_block_new_volume(self):
        root = self.root()
        original = self.fs.list_entries

        def entries(path):
            return original(path) + [("unsafe-link", "link")]

        with mock.patch.object(self.fs, "list_entries", side_effect=entries):
            self.assertFalse(self.fs.can_start_new_volume(str(root)))
        with mock.patch.object(self.fs, "probe_file", side_effect=PermissionError("injected read denial")):
            self.assertFalse(self.fs.can_start_new_volume(str(root)))

    def test_different_save_location_preserves_old_header(self):
        root = self.root()
        old, _ = self.volume()
        new, _ = self.volume()
        previous = root / "old.pqvolume"
        previous.write_text(P.header_json(old["header"]), encoding="utf-8")
        original = previous.read_bytes()
        destination = self.base / "new.pqvolume"
        self.fs.save_encryption_header(str(root), new["header"], str(destination), previous_header=old["header"])
        self.assertEqual(previous.read_bytes(), original)
        self.assertEqual(self.fs.read_header_file(str(destination)), new["header"])

    def test_file_appearing_at_new_destination_is_not_overwritten(self):
        root = self.root()
        volume, _ = self.volume()
        destination = self.base / "racing.data"
        original_write = self.fs.write_file_bytes

        def racing_write(path, contents, replace=True):
            destination.write_bytes(b"new unrelated file")
            return original_write(path, contents, replace=replace)

        with mock.patch.object(self.fs, "write_file_bytes", side_effect=racing_write):
            with self.assertRaises((OSError, P.PQError)):
                self.fs.save_encryption_header(str(root), volume["header"], str(destination))
        self.assertEqual(destination.read_bytes(), b"new unrelated file")

    def test_old_header_changed_during_safety_scan_is_preserved(self):
        root = self.root()
        old, _ = self.volume()
        new, _ = self.volume()
        destination = self.base / "old.pqvolume"
        destination.write_text(P.header_json(old["header"]), encoding="utf-8")
        original = destination.read_bytes()
        stamp = destination.stat()
        changed = original.replace(b"\n  ", b"\n \t", 1)

        def change_during_scan(path):
            destination.write_bytes(changed)
            os.utime(destination, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            return True

        with mock.patch.object(self.fs, "can_start_new_volume", side_effect=change_during_scan):
            with self.assertRaises(P.PQError) as raised:
                self.fs.save_encryption_header(str(root), new["header"], str(destination), previous_header=old["header"])
        self.assertEqual(raised.exception.code, "SOURCE_CHANGED")
        self.assertEqual(destination.read_bytes(), changed)

    def test_invalid_new_header_does_not_create_any_file(self):
        root = self.root()
        volume, _ = self.volume()
        invalid = copy.deepcopy(volume["header"])
        invalid["slots"] = []
        destination = self.base / "invalid.pqvolume"
        with self.assertRaises(P.PQError):
            self.fs.save_encryption_header(str(root), invalid, str(destination))
        self.assertFalse(destination.exists())
        self.assertFalse((root / P.VOLUME_HEADER_NAME).exists())

    def test_reserved_metadata_destinations_are_rejected(self):
        root = self.root()
        volume, _ = self.volume()
        for name in (P.LOCK_NAME, P.DIR_MANIFEST_NAME, P.TMP_PREFIX + "selected"):
            with self.subTest(name=name):
                destination = root / name
                with self.assertRaises(P.PQError) as raised:
                    self.fs.save_encryption_header(str(root), volume["header"], str(destination))
                self.assertEqual(raised.exception.code, "UNSAFE_PATH")
        selected = root / P.VOLUME_HEADER_NAME
        self.fs.save_encryption_header(str(root), volume["header"], str(selected))
        self.assertEqual(self.fs.read_header_file(str(selected)), volume["header"])


if __name__ == "__main__":
    unittest.main()
