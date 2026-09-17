"""Repeat-folder workflows, including UI state after decrypting the same root."""
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
PASSWORD = "Repeat-Folder-Passphrase-2026!"


class RepeatFolderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pqdisk-repeat-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.pq = P.PQCrypto()
        self.fs = P.VolumeFS(self.pq)

    def volume(self, hide):
        root = self.base / ("hidden" if hide else "visible")
        root.mkdir()
        vol = self.pq.new_volume(hide_names=hide)
        self.pq.add_password_slot(vol["header"], vol["vmk"], PASSWORD, SMALL)
        self.fs.write_volume_header(str(root), vol["header"])
        files = {"data.bin": os.urandom(2 * P.CHUNK_SIZE + 7), "nested/note.txt": b"note", "empty": b""}
        for name, data in files.items():
            path = root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(data)
        ctx = {"vmk": vol["vmk"], "volumeId": vol["volumeId"], "hideNames": hide}
        return root, ctx, files

    @staticmethod
    def encrypted_snapshot(root):
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*")
                if p.is_file() and (p.suffix == P.ENC_EXT or p.name in (P.VOLUME_HEADER_NAME, P.DIR_MANIFEST_NAME))}

    def test_repeat_with_kept_plaintext_reuses_authenticated_ciphertext(self):
        for hide in (False, True):
            with self.subTest(hide=hide):
                root, ctx, files = self.volume(hide)
                self.assertEqual(self.fs.encrypt_tree(str(root), ctx, keep_originals=True)["errors"], [])
                before = self.encrypted_snapshot(root)
                for _ in range(2):
                    result = self.fs.encrypt_tree(str(root), ctx, keep_originals=True)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result.get("reused"), len(files))
                    self.assertEqual(self.encrypted_snapshot(root), before)
                    for name, content in files.items():
                        self.assertEqual((root / name).read_bytes(), content)

    def test_keep_then_delete_originals_then_decrypt(self):
        for hide in (False, True):
            with self.subTest(hide=hide):
                root, ctx, files = self.volume(hide)
                self.assertEqual(self.fs.encrypt_tree(str(root), ctx, keep_originals=True)["errors"], [])
                before = self.encrypted_snapshot(root)
                result = self.fs.encrypt_tree(str(root), ctx, keep_originals=False, verify=False)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result.get("reused"), len(files))
                self.assertEqual(self.encrypted_snapshot(root), before)
                self.assertTrue(all(not (root / name).exists() for name in files))
                result = self.fs.decrypt_tree(str(root), ctx)
                self.assertEqual(result["errors"], [])
                self.assertFalse(result["headerRemoved"])
                self.assertTrue((root / P.VOLUME_HEADER_NAME).exists())
                for name, content in files.items():
                    self.assertEqual((root / name).read_bytes(), content)

    def test_different_same_name_is_not_overwritten(self):
        for hide in (False, True):
            with self.subTest(hide=hide):
                root, ctx, _ = self.volume(hide)
                self.fs.encrypt_tree(str(root), ctx)
                before = self.encrypted_snapshot(root)
                path = root / "data.bin"
                path.write_bytes(b"new version")
                result = self.fs.encrypt_tree(str(root), ctx)
                self.assertEqual(len(result["errors"]), 1)
                self.assertEqual(path.read_bytes(), b"new version")
                self.assertEqual(self.encrypted_snapshot(root), before)

    def test_corrupt_existing_ciphertext_never_deletes_original(self):
        root, ctx, files = self.volume(False)
        self.fs.encrypt_tree(str(root), ctx, keep_originals=True)
        path = root / "data.bin.pqfc"
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        result = self.fs.encrypt_tree(str(root), ctx)
        self.assertTrue(any(error["path"] == "data.bin" for error in result["errors"]))
        self.assertEqual((root / "data.bin").read_bytes(), files["data.bin"])
        self.assertEqual(path.read_bytes(), data)

    def test_reuse_requires_full_authentication_even_without_verify_option(self):
        root, ctx, files = self.volume(False)
        self.fs.encrypt_tree(str(root), ctx, keep_originals=True)
        with mock.patch.object(self.pq, "decrypt_volume_stream", side_effect=P.PQError("auth failure")) as decrypt:
            result = self.fs.encrypt_tree(str(root), ctx, keep_originals=True, verify=False)
        self.assertEqual(decrypt.call_count, len(files))
        self.assertEqual(len(result["errors"]), len(files))
        for name, content in files.items():
            self.assertEqual((root / name).read_bytes(), content)

    def test_cancel_while_verifying_reused_output_keeps_source(self):
        root, ctx, files = self.volume(False)
        self.fs.encrypt_tree(str(root), ctx, keep_originals=True)
        before = self.encrypted_snapshot(root)
        cancel = threading.Event()

        def stop(event):
            if event["type"] == "verify-start":
                cancel.set()

        result = self.fs.encrypt_tree(str(root), ctx, on_event=stop, cancel=cancel)
        self.assertTrue(result["cancelled"])
        self.assertEqual(self.encrypted_snapshot(root), before)
        for name, content in files.items():
            self.assertEqual((root / name).read_bytes(), content)

    def test_repeat_after_encrypted_files_have_no_new_plaintext(self):
        for hide in (False, True):
            with self.subTest(hide=hide):
                root, ctx, files = self.volume(hide)
                self.fs.encrypt_tree(str(root), ctx)
                before = self.encrypted_snapshot(root)
                result = self.fs.encrypt_tree(str(root), ctx)
                self.assertEqual((result["files"], result["skipped"], result["errors"]), (0, len(files), []))
                self.assertEqual(self.encrypted_snapshot(root), before)

    def test_retry_after_original_delete_failure_reuses_committed_ciphertext(self):
        root, ctx, files = self.volume(False)
        remove = P._remove_file

        def fail_source(path):
            if Path(path).name == "data.bin":
                raise PermissionError("injected delete failure")
            return remove(path)

        with mock.patch.object(P, "_remove_file", side_effect=fail_source):
            failed = self.fs.encrypt_tree(str(root), ctx)
        self.assertEqual(len(failed["errors"]), 1)
        self.assertEqual((root / "data.bin").read_bytes(), files["data.bin"])
        before = self.encrypted_snapshot(root)
        result = self.fs.encrypt_tree(str(root), ctx)
        self.assertEqual((result["errors"], result.get("reused")), ([], 1))
        self.assertFalse((root / "data.bin").exists())
        self.assertEqual(self.encrypted_snapshot(root), before)

    def test_same_size_different_content_cannot_be_reused(self):
        root, ctx, files = self.volume(False)
        self.fs.encrypt_tree(str(root), ctx, keep_originals=True)
        source = root / "data.bin"
        changed = bytearray(files["data.bin"])
        changed[-1] ^= 1
        source.write_bytes(changed)
        before = self.encrypted_snapshot(root)
        result = self.fs.encrypt_tree(str(root), ctx)
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(source.read_bytes(), changed)
        self.assertEqual(self.encrypted_snapshot(root), before)

    def test_foreign_ciphertext_cannot_be_reused_even_with_identical_plaintext(self):
        root, ctx, files = self.volume(False)
        other = self.pq.new_volume()
        ciphertext = self.pq.encrypt_volume_bytes(other["vmk"], other["volumeId"], files["data.bin"])
        (root / "data.bin.pqfc").write_bytes(ciphertext)
        result = self.fs.encrypt_tree(str(root), ctx)
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual((root / "data.bin").read_bytes(), files["data.bin"])
        self.assertEqual((root / "data.bin.pqfc").read_bytes(), ciphertext)

    def test_source_changed_after_reuse_comparison_is_preserved(self):
        root, ctx, _ = self.volume(False)
        self.fs.encrypt_tree(str(root), ctx, keep_originals=True)
        source = root / "data.bin"
        check = P._unchanged
        checks = 0

        def change_after_comparison(path, expected):
            nonlocal checks
            if Path(path) == source:
                checks += 1
                if checks == 2:
                    source.write_bytes(b"changed before deletion")
            return check(path, expected)

        with mock.patch.object(P, "_unchanged", side_effect=change_after_comparison):
            result = self.fs.encrypt_tree(str(root), ctx)
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(source.read_bytes(), b"changed before deletion")

    def test_new_files_are_encrypted_alongside_reused_originals(self):
        for hide in (False, True):
            with self.subTest(hide=hide):
                root, ctx, files = self.volume(hide)
                self.fs.encrypt_tree(str(root), ctx, keep_originals=True)
                (root / "nested" / "new.txt").write_bytes(b"new")
                result = self.fs.encrypt_tree(str(root), ctx)
                self.assertEqual((result["files"], result.get("reused"), result["errors"]),
                                 (len(files) + 1, len(files), []))
                result = self.fs.decrypt_tree(str(root), ctx)
                self.assertEqual(result["errors"], [])
                self.assertEqual((root / "nested" / "new.txt").read_bytes(), b"new")
                for name, data in files.items():
                    self.assertEqual((root / name).read_bytes(), data)


class RepeatFolderUITests(unittest.TestCase):
    def setUp(self):
        import fake_tk
        fake_tk.install()
        P._load_tk()
        self.tk = fake_tk
        for answers in fake_tk.SCRIPT.values():
            answers.clear()
        self.patch = mock.patch.multiple(P, ARGON_MEM_KIB=8, ARGON_TIME=1, ARGON_PAR=1)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.tmp = tempfile.TemporaryDirectory(prefix="pqdisk-repeat-ui-")
        self.addCleanup(self.tmp.cleanup)
        self.root_dir = Path(self.tmp.name) / "data"
        self.root_dir.mkdir()
        (self.root_dir / "data.txt").write_bytes(b"original")
        self.window = fake_tk.Tk()
        self.app = P.App(self.window)
        self.addCleanup(self.window.destroy)
        self.pump(lambda: self.app.ready or self.app.selftest_failure)
        self.assertIsNone(self.app.selftest_failure)
        self.app.enc_path.set(str(self.root_dir))
        self.app.enc_slot_mode.set("pw")
        self.app.enc_pw.set(PASSWORD)
        self.app.enc_pw2.set(PASSWORD)
        self.app.enc_unlock.pw.set(PASSWORD)
        self.app.enc_hide.set(True)
        self.header_path = Path(self.tmp.name) / "selected.pqvolume"
        self.app.on_scan("enc")
        self.pump()

    def pump(self, until=None):
        until = until or (lambda: not self.app.busy)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.window.pump()
            if until():
                return
            time.sleep(0.005)
        self.fail("UI worker timed out: " + self.app.log_text.get())

    def encrypt(self):
        if not self.header_path.exists():
            self.tk.SCRIPT["asksaveasfilename"].append(str(self.header_path))
        self.app.on_enc_start()
        self.pump()

    def test_repeat_click_is_successful_noop(self):
        self.encrypt()
        before = RepeatFolderTests.encrypted_snapshot(self.root_dir)
        previous_logs = self.app.log_text.get()
        self.encrypt()
        self.assertNotIn("错误：", self.app.log_text.get()[len(previous_logs):])
        self.assertIn("无需重复加密", self.app.enc_done.cget("text"))
        self.assertEqual(RepeatFolderTests.encrypted_snapshot(self.root_dir), before)

    def test_new_files_are_found_without_manual_rescan(self):
        self.encrypt()
        (self.root_dir / "new.txt").write_bytes(b"new")
        self.assertEqual(self.app.enc_scan["files"], 0)
        self.encrypt()
        self.assertFalse((self.root_dir / "new.txt").exists())
        self.assertEqual(self.app.enc_scan["encrypted"], 2)

    def test_decrypt_then_encrypt_uses_current_header_and_scan(self):
        for _ in range(2):
            self.encrypt()
            self.assertFalse((self.root_dir / P.VOLUME_HEADER_NAME).exists())
            self.assertTrue(self.header_path.exists())
            saved = self.header_path.read_bytes()
            self.assertFalse((self.root_dir / "data.txt").exists())
            self.app.dec_path.set(str(self.root_dir))
            self.app.on_scan("dec")
            self.pump()
            self.app.dec_unlock.pw.set(PASSWORD)
            self.app.on_dec_start()
            self.pump()
            self.assertFalse((self.root_dir / P.VOLUME_HEADER_NAME).exists())
            self.assertEqual(self.header_path.read_bytes(), saved)
            self.assertEqual((self.root_dir / "data.txt").read_bytes(), b"original")

    def test_keep_then_repeat_in_ui_needs_no_manual_cleanup(self):
        self.app.enc_keep.set(True)
        self.encrypt()
        before = RepeatFolderTests.encrypted_snapshot(self.root_dir)
        self.app.enc_keep.set(False)
        self.encrypt()
        self.assertFalse((self.root_dir / "data.txt").exists())
        self.assertIn("复用", self.app.enc_done.cget("text"))
        self.assertEqual(RepeatFolderTests.encrypted_snapshot(self.root_dir), before)

    def test_editing_directory_field_does_not_encrypt_previously_scanned_root(self):
        new_root = Path(self.tmp.name) / "other"
        new_root.mkdir()
        (new_root / "new.txt").write_bytes(b"new")
        self.app.enc_path.set(str(new_root))
        self.encrypt()
        self.assertFalse((new_root / P.VOLUME_HEADER_NAME).exists())
        self.assertTrue(self.header_path.exists())
        self.assertFalse((new_root / "new.txt").exists())
        self.assertEqual((self.root_dir / "data.txt").read_bytes(), b"original")
        self.assertFalse((self.root_dir / P.VOLUME_HEADER_NAME).exists())

    def test_failed_rescan_does_not_start_encryption(self):
        with mock.patch.object(self.app.vfs, "scan_tree", side_effect=PermissionError("scan failed")), \
                mock.patch.object(self.app.vfs, "encrypt_tree") as encrypt:
            self.encrypt()
        encrypt.assert_not_called()
        self.assertEqual((self.root_dir / "data.txt").read_bytes(), b"original")
        self.assertFalse((self.root_dir / P.VOLUME_HEADER_NAME).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
