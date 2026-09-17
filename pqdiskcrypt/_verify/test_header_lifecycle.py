"""End-to-end regression tests for retained headers and optional legacy cleanup."""
import copy
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import pqdiskcrypt as P

SMALL = {"timeCost": 1, "memKiB": 8, "parallelism": 1}
PASSWORD = "Header-Lifecycle-Regression-2026!"


class HeaderLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pqdisk-lifecycle-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.pq = P.PQCrypto()
        self.fs = P.VolumeFS(self.pq)

    def volume(self, hide=False, name="volume"):
        root = self.base / name
        root.mkdir()
        vol = self.pq.new_volume(hide_names=hide)
        self.pq.add_password_slot(vol["header"], vol["vmk"], PASSWORD, SMALL)
        self.fs.write_volume_header(str(root), vol["header"])
        files = {"data.bin": os.urandom(P.CHUNK_SIZE + 9), "nested/note.txt": b"note", "empty": b""}
        for name, data in files.items():
            path = root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(data)
        ctx = {"vmk": vol["vmk"], "volumeId": vol["volumeId"], "hideNames": hide}
        self.assertEqual(self.fs.encrypt_tree(str(root), ctx)["errors"], [])
        backup = root / "backup.pqvolume"
        backup.write_text(P.header_json(vol["header"]), encoding="utf-8")
        return root, vol, ctx, files, backup

    def assert_headers_preserved(self, root, backup):
        self.assertTrue((root / P.VOLUME_HEADER_NAME).exists())
        self.assertTrue(backup.exists())

    def test_full_decrypt_removes_local_matching_headers_only(self):
        for hide in (False, True):
            with self.subTest(hide=hide):
                root, vol, ctx, files, backup = self.volume(hide, "hidden" if hide else "visible")
                external = self.base / (root.name + "-external.pqvolume")
                external.write_bytes(backup.read_bytes())
                alternate = copy.deepcopy(vol["header"])
                alternate["slots"] = []
                self.pq.add_password_slot(alternate, vol["vmk"], "Other-Password-Slot-2026!", SMALL)
                (root / "alternate.PQVOLUME.TXT").write_text(P.header_json(alternate), encoding="utf-8")
                foreign = self.pq.new_volume()
                self.pq.add_password_slot(foreign["header"], foreign["vmk"], PASSWORD, SMALL)
                preserved = {
                    "other.pqvolume": P.header_json(foreign["header"]).encode(),
                    "invalid.pqvolume": b"invalid header",
                    "unrelated.json": backup.read_bytes(),
                }
                for name, data in preserved.items():
                    (root / name).write_bytes(data)
                result = self.fs.decrypt_tree(str(root), ctx, remove_header=True)
                self.assertEqual((result["errors"], result["warnings"]), ([], []))
                self.assertTrue(result["headerRemoved"])
                for name in (P.VOLUME_HEADER_NAME, "backup.pqvolume", "alternate.PQVOLUME.TXT"):
                    self.assertFalse((root / name).exists(), name)
                for name, data in {**files, **preserved}.items():
                    self.assertEqual((root / name).read_bytes(), data)
                self.assertEqual(external.read_text(encoding="utf-8"), P.header_json(vol["header"]))

    def test_backup_only_volume_is_cleaned_when_explicitly_requested(self):
        root, _, ctx, _, backup = self.volume()
        (root / P.VOLUME_HEADER_NAME).unlink()
        result = self.fs.decrypt_tree(str(root), ctx, remove_header=True)
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["headerRemoved"])
        self.assertFalse(backup.exists())

    def test_keep_ciphertext_preserves_all_local_headers(self):
        root, _, ctx, _, backup = self.volume()
        result = self.fs.decrypt_tree(str(root), ctx, keep_originals=True, remove_header=True)
        self.assertEqual(result["errors"], [])
        self.assertFalse(result["headerRemoved"])
        self.assert_headers_preserved(root, backup)
        self.assertTrue((root / "data.bin.pqfc").exists())

    def test_cancel_preserves_all_local_headers(self):
        root, _, ctx, _, backup = self.volume()
        cancel = threading.Event()
        cancel.set()
        result = self.fs.decrypt_tree(str(root), ctx, cancel=cancel, remove_header=True)
        self.assertTrue(result["cancelled"])
        self.assert_headers_preserved(root, backup)

    def test_authentication_failure_preserves_all_local_headers(self):
        root, _, ctx, _, backup = self.volume()
        path = root / "data.bin.pqfc"
        corrupt = bytearray(path.read_bytes())
        corrupt[-1] ^= 1
        path.write_bytes(corrupt)
        result = self.fs.decrypt_tree(str(root), ctx, remove_header=True)
        self.assertTrue(result["errors"])
        self.assert_headers_preserved(root, backup)
        self.assertEqual(path.read_bytes(), corrupt)
        self.assertFalse((root / "data.bin").exists())

    def test_plaintext_conflict_preserves_all_local_headers(self):
        for hide in (False, True):
            with self.subTest(hide=hide):
                root, _, ctx, _, backup = self.volume(hide, "hidden" if hide else "visible")
                (root / "data.bin").write_bytes(b"do not overwrite")
                result = self.fs.decrypt_tree(str(root), ctx, remove_header=True)
                self.assertEqual(result["kept"], 1)
                self.assert_headers_preserved(root, backup)
                self.assertEqual((root / "data.bin").read_bytes(), b"do not overwrite")

    def test_ciphertext_renamed_to_another_extension_prevents_cleanup(self):
        root, _, ctx, _, backup = self.volume()
        renamed = root / "renamed.blob"
        (root / "data.bin.pqfc").rename(renamed)
        ciphertext = renamed.read_bytes()
        result = self.fs.decrypt_tree(str(root), ctx, remove_header=True)
        self.assertFalse(result["headerRemoved"])
        self.assert_headers_preserved(root, backup)
        self.assertEqual(renamed.read_bytes(), ciphertext)

    def test_foreign_canonical_header_is_preserved(self):
        root, _, ctx, _, backup = self.volume()
        other = self.pq.new_volume()
        self.pq.add_password_slot(other["header"], other["vmk"], PASSWORD, SMALL)
        self.fs.write_volume_header(str(root), other["header"])
        result = self.fs.decrypt_tree(str(root), ctx, remove_header=True)
        self.assertEqual(result["errors"], [])
        self.assertEqual(self.fs.read_volume_header(str(root)), other["header"])
        self.assertFalse(backup.exists())

    def test_damaged_canonical_header_is_preserved(self):
        root, _, ctx, _, backup = self.volume()
        canonical = root / P.VOLUME_HEADER_NAME
        canonical.write_bytes(b"damaged original header")
        result = self.fs.decrypt_tree(str(root), ctx, remove_header=True)
        self.assertEqual(result["errors"], [])
        self.assertEqual(canonical.read_bytes(), b"damaged original header")
        self.assertFalse(backup.exists())


class HeaderLifecycleUITests(unittest.TestCase):
    def setUp(self):
        import fake_tk
        fake_tk.install()
        P._load_tk()
        self.tk = fake_tk
        for answers in fake_tk.SCRIPT.values():
            answers.clear()
        patch = mock.patch.multiple(P, ARGON_MEM_KIB=8, ARGON_TIME=1, ARGON_PAR=1)
        patch.start()
        self.addCleanup(patch.stop)
        self.tmp = tempfile.TemporaryDirectory(prefix="pqdisk-lifecycle-ui-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.window = fake_tk.Tk()
        self.app = P.App(self.window)
        self.addCleanup(self.window.destroy)
        self.pump(lambda: self.app.ready or self.app.selftest_failure)
        self.assertIsNone(self.app.selftest_failure)
        self.app.enc_slot_mode.set("pw")
        self.app.enc_pw.set(PASSWORD)
        self.app.enc_pw2.set(PASSWORD)
        self.app.enc_unlock.pw.set(PASSWORD)
        self.app.dec_unlock.pw.set(PASSWORD)

    def pump(self, until=None):
        until = until or (lambda: not self.app.busy)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.window.pump()
            if until():
                return
            time.sleep(0.005)
        self.fail("UI worker timed out: " + self.app.log_text.get())

    def test_same_folder_encrypt_decrypt_reencrypt_twice_in_both_name_modes(self):
        for hide in (False, True):
            with self.subTest(hide=hide):
                root = self.base / ("hidden" if hide else "visible")
                root.mkdir()
                (root / "nested").mkdir()
                originals = {"data.txt": b"payload", "nested/empty": b""}
                for name, data in originals.items():
                    (root / name).write_bytes(data)
                self.app.enc_path.set(str(root))
                self.app.dec_path.set(str(root))
                self.app.enc_hide.set(hide)
                local_backup = root / "saved.pqvolume"
                saved = None
                for cycle in range(2):
                    if cycle == 0:
                        self.tk.SCRIPT["asksaveasfilename"].append(str(local_backup))
                    self.app.on_enc_start()
                    self.pump()
                    self.assertFalse((root / P.VOLUME_HEADER_NAME).exists())
                    self.assertTrue(local_backup.exists())
                    if saved is None:
                        saved = local_backup.read_bytes()
                    self.assertEqual(local_backup.read_bytes(), saved)
                    self.assertFalse((root / "data.txt").exists())
                    self.app.on_scan("dec")
                    self.pump()
                    self.assertIsNotNone(self.app.dec_header)
                    self.app.dec_unlock.pw.set(PASSWORD)
                    self.app.on_dec_start()
                    self.pump()
                    for name, data in originals.items():
                        self.assertEqual((root / name).read_bytes(), data)
                    self.assertFalse((root / P.VOLUME_HEADER_NAME).exists())
                    self.assertEqual(local_backup.read_bytes(), saved)
                    self.assertFalse(any(path.suffix == P.ENC_EXT or path.name == P.DIR_MANIFEST_NAME
                                         for path in root.rglob("*")))

    def test_usable_header_without_ciphertext_is_reused_for_encryption(self):
        root = self.base / "plaintext"
        root.mkdir()
        (root / "data.txt").write_bytes(b"plaintext")
        stale = self.app.pq.new_volume()
        self.app.pq.add_password_slot(stale["header"], stale["vmk"], PASSWORD, SMALL)
        header_path = root / "old.pqvolume"
        header_path.write_text(P.header_json(stale["header"]), encoding="utf-8")
        saved = header_path.read_bytes()
        self.app.enc_path.set(str(root))
        self.app.on_enc_start()
        self.pump()
        self.assertFalse((root / P.VOLUME_HEADER_NAME).exists())
        self.assertFalse((root / "data.txt").exists())
        self.assertEqual(self.app.enc_header["volume_id"], stale["header"]["volume_id"])
        self.assertEqual(header_path.read_bytes(), saved)

    def test_external_header_is_used_without_creating_local_copy_and_survives(self):
        root = self.base / "external-recovery"
        root.mkdir()
        (root / "data.txt").write_bytes(b"payload")
        external = self.base / "external.pqvolume"
        self.tk.SCRIPT["asksaveasfilename"].append(str(external))
        self.app.enc_path.set(str(root))
        self.app.on_enc_start()
        self.pump()
        saved = external.read_bytes()
        self.assertFalse((root / P.VOLUME_HEADER_NAME).exists())
        self.app.dec_path.set(str(root))
        self.app.on_dec_load_header(str(external))
        self.pump()
        self.app.dec_unlock.pw.set(PASSWORD)
        self.app.on_dec_start()
        self.pump()
        self.assertEqual((root / "data.txt").read_bytes(), b"payload")
        self.assertFalse((root / P.VOLUME_HEADER_NAME).exists())
        self.assertEqual(external.read_bytes(), saved)


if __name__ == "__main__":
    unittest.main(verbosity=2)
