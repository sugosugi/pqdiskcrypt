"""Real-file regressions for removing only safely completed local volume headers."""
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pqdiskcrypt as P


class HeaderCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pqdisk-cleanup-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.pq = P.PQCrypto()
        self.fs = P.VolumeFS(self.pq)

    def volume(self, hide=False, name="volume"):
        root = self.base / name
        root.mkdir()
        vol = self.pq.new_volume(hide_names=hide)
        self.pq.add_password_slot(vol["header"], vol["vmk"], "Cleanup-Password-2026!",
                                  {"timeCost": 1, "memKiB": 8, "parallelism": 1})
        self.fs.write_volume_header(str(root), vol["header"])
        ctx = {"vmk": vol["vmk"], "volumeId": vol["volumeId"], "hideNames": hide}
        files = {"data.txt": b"data" * 4000, "nested/note.txt": b"nested"}
        for name, raw in files.items():
            path = root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw)
        self.assertEqual(self.fs.encrypt_tree(str(root), ctx)["errors"], [])
        return root, vol, ctx, files

    @staticmethod
    def backup(root, header, name="backup.pqvolume"):
        path = root / name
        path.write_text(P.header_json(header), encoding="utf-8")
        return path

    def assert_restored(self, root, files):
        for name, raw in files.items():
            self.assertEqual((root / name).read_bytes(), raw)

    def test_all_matching_root_headers_removed_and_others_preserved(self):
        for hide in (False, True):
            with self.subTest(hide=hide):
                root, vol, ctx, files = self.volume(hide, str(hide))
                expected = {root / P.VOLUME_HEADER_NAME}
                for name in ("backup.pqvolume", "BACKUP.PQVOLUME.TXT", "backup.pqvolume.json"):
                    expected.add(self.backup(root, vol["header"], name))
                invalid = root / "invalid.pqvolume"
                invalid.write_bytes(b"ordinary file")
                other = self.pq.new_volume()
                self.pq.add_password_slot(other["header"], other["vmk"], "Other-Password!",
                                          {"timeCost": 1, "memKiB": 8, "parallelism": 1})
                foreign = self.backup(root, other["header"], "other.pqvolume")
                outside = self.backup(self.base, vol["header"], "external-%s.pqvolume" % hide)
                result = self.fs.decrypt_tree(str(root), ctx, remove_header=True, header_paths=[str(outside)])
                self.assertEqual((result["errors"], result["warnings"]), ([], []))
                self.assertTrue(result["headerRemoved"])
                self.assertEqual({Path(path) for path in result["removedHeaders"]}, expected)
                self.assertTrue(all(not path.exists() for path in expected))
                self.assertTrue(invalid.exists() and foreign.exists() and outside.exists())
                self.assert_restored(root, files)

    def test_selected_arbitrary_root_filename_removed_without_canonical(self):
        root, vol, ctx, files = self.volume()
        (root / P.VOLUME_HEADER_NAME).unlink()
        chosen = self.backup(root, vol["header"], "chosen-header.dat")
        unselected = self.backup(root, vol["header"], "unselected-data.dat")
        result = self.fs.decrypt_tree(str(root), ctx, remove_header=True, header_paths=[str(chosen)])
        self.assertEqual(result["removedHeaders"], [str(chosen)])
        self.assertFalse(chosen.exists())
        self.assertTrue(unselected.exists())
        self.assert_restored(root, files)

    def test_restored_header_shaped_plaintext_is_not_deleted(self):
        root, vol, ctx, files = self.volume()
        files["restored.pqvolume"] = P.header_json(vol["header"]).encode("utf-8")
        (root / "restored.pqvolume.pqfc").write_bytes(self.pq.encrypt_volume_bytes(
            ctx["vmk"], ctx["volumeId"], files["restored.pqvolume"]))
        result = self.fs.decrypt_tree(str(root), ctx, remove_header=True, header_paths=[str(root / "restored.pqvolume")])
        # A selected path absent at the start must never become a cleanup target.
        self.assertTrue(result["headerRemoved"])
        self.assertTrue((root / "restored.pqvolume").exists())
        self.assert_restored(root, files)

    def test_keep_and_explicit_no_cleanup_preserve_headers(self):
        for kwargs in ({"keep_originals": True}, {"remove_header": False}):
            with self.subTest(kwargs=kwargs):
                root, vol, ctx, files = self.volume(name=str(len(list(self.base.iterdir()))))
                backup = self.backup(root, vol["header"])
                result = self.fs.decrypt_tree(str(root), ctx, **kwargs)
                self.assertFalse(result["headerRemoved"])
                self.assertEqual(result["removedHeaders"], [])
                self.assertTrue(backup.exists() and (root / P.VOLUME_HEADER_NAME).exists())
                self.assert_restored(root, files)

    def test_changed_header_with_original_timestamp_is_preserved(self):
        root, vol, ctx, files = self.volume()
        backup = self.backup(root, vol["header"])
        original = backup.stat()
        raw = backup.read_bytes()
        changed = False

        def modify(event):
            nonlocal changed
            if event["type"] == "file-done" and not changed:
                changed = True
                backup.write_bytes(raw.replace(b"\n  ", b"\n \t", 1))
                # Even unchanged file timestamps cannot conceal changed content.
                os.utime(backup, ns=(original.st_atime_ns, original.st_mtime_ns))

        result = self.fs.decrypt_tree(str(root), ctx, remove_header=True, on_event=modify)
        self.assertFalse(result["headerRemoved"])
        self.assertTrue(result["warnings"])
        self.assertTrue(backup.exists() and (root / P.VOLUME_HEADER_NAME).exists())
        self.assert_restored(root, files)

    def test_cleanup_failure_is_reported(self):
        root, vol, ctx, files = self.volume()
        canonical = root / P.VOLUME_HEADER_NAME
        remove = P._remove_file

        def deny(path):
            if Path(path) == canonical:
                raise PermissionError("injected header deletion failure")
            return remove(path)

        with mock.patch.object(P, "_remove_file", side_effect=deny):
            result = self.fs.decrypt_tree(str(root), ctx, remove_header=True)
        self.assertFalse(result["headerRemoved"])
        self.assertIn("injected header deletion failure", result["warnings"][0]["message"])
        self.assertTrue(canonical.exists())
        self.assert_restored(root, files)

    def test_conflicting_plaintext_preserves_every_header(self):
        root, vol, ctx, _ = self.volume()
        backup = self.backup(root, vol["header"])
        (root / "data.txt").write_bytes(b"existing destination")
        result = self.fs.decrypt_tree(str(root), ctx)
        self.assertEqual(result["kept"], 1)
        self.assertFalse(result["headerRemoved"])
        self.assertTrue(backup.exists() and (root / P.VOLUME_HEADER_NAME).exists())

    def test_authentication_failure_preserves_every_header(self):
        root, vol, ctx, _ = self.volume()
        backup = self.backup(root, vol["header"])
        source = root / "data.txt.pqfc"
        raw = bytearray(source.read_bytes())
        raw[-1] ^= 1
        source.write_bytes(raw)
        result = self.fs.decrypt_tree(str(root), ctx)
        self.assertTrue(result["errors"])
        self.assertFalse(result["headerRemoved"])
        self.assertTrue(backup.exists() and (root / P.VOLUME_HEADER_NAME).exists())

    def test_cancellation_after_file_commit_preserves_every_header(self):
        root, vol, ctx, _ = self.volume()
        backup = self.backup(root, vol["header"])
        cancel = threading.Event()
        result = self.fs.decrypt_tree(str(root), ctx, cancel=cancel,
            on_event=lambda event: cancel.set() if event["type"] == "file-done" else None)
        self.assertTrue(result["cancelled"])
        self.assertFalse(result["headerRemoved"])
        self.assertTrue(backup.exists() and (root / P.VOLUME_HEADER_NAME).exists())

    def test_renamed_ciphertext_preserves_backup_without_canonical(self):
        root, vol, ctx, _ = self.volume()
        (root / P.VOLUME_HEADER_NAME).unlink()
        backup = self.backup(root, vol["header"])
        (root / "renamed.bin").write_bytes(self.pq.encrypt_volume_bytes(ctx["vmk"], ctx["volumeId"], b"secret"))
        result = self.fs.decrypt_tree(str(root), ctx)
        self.assertFalse(result["headerRemoved"])
        self.assertTrue(backup.exists())

    def test_missing_manifest_keeps_backup(self):
        root, vol, ctx, _ = self.volume(hide=True)
        backup = self.backup(root, vol["header"])
        (root / P.DIR_MANIFEST_NAME).unlink()
        result = self.fs.decrypt_tree(str(root), ctx)
        self.assertTrue(result["warnings"])
        self.assertFalse(result["headerRemoved"])
        self.assertTrue(backup.exists() and (root / P.VOLUME_HEADER_NAME).exists())

    def test_ciphertext_renamed_to_canonical_header_keeps_backup(self):
        root, vol, ctx, _ = self.volume()
        backup = self.backup(root, vol["header"])
        canonical = root / P.VOLUME_HEADER_NAME
        canonical.unlink()
        (root / "data.txt.pqfc").rename(canonical)
        result = self.fs.decrypt_tree(str(root), ctx)
        self.assertFalse(result["headerRemoved"])
        self.assertTrue(backup.exists() and canonical.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
