"""Regression coverage for existing/renamed headers and backup selection."""
import copy
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import pqdiskcrypt as P

SMALL = {"timeCost": 1, "memKiB": 8, "parallelism": 1}
PASSWORD = "Header-Detection-Original-2026!"
BACKUP_PASSWORD = "Header-Detection-Backup-2026!"


class HeaderFixtures:
    def make_volume(self, name="volume", hide=False):
        root = self.base / name
        root.mkdir()
        vol = self.pq.new_volume(hide_names=hide)
        self.pq.add_password_slot(vol["header"], vol["vmk"], PASSWORD, SMALL)
        self.fs.write_volume_header(str(root), vol["header"])
        files = {"data.bin": b"payload\x00" * 11000, "nested/note.txt": b"nested", "empty": b""}
        for relative, data in files.items():
            path = root / relative
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(data)
        ctx = {"vmk": vol["vmk"], "volumeId": vol["volumeId"], "hideNames": hide}
        result = self.fs.encrypt_tree(str(root), ctx)
        self.assertEqual(result["errors"], [])
        return root, vol, files

    def backup(self, root, header, name="pqdisk-backup.pqvolume", remove_canonical=True):
        path = root / name
        path.write_text(P.header_json(header), encoding="utf-8")
        if remove_canonical:
            (root / P.VOLUME_HEADER_NAME).unlink(missing_ok=True)
        return path

    def assert_restored(self, root, files):
        for relative, expected in files.items():
            self.assertEqual((root / relative).read_bytes(), expected)


class HeaderDetectionTests(HeaderFixtures, unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pqdisk-header-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.pq = P.PQCrypto()
        self.fs = P.VolumeFS(self.pq)

    def test_candidate_extensions_are_case_insensitive_and_content_validated(self):
        root, vol, _ = self.make_volume()
        names = ["a.pqvolume", "b.pqvolume.txt", "c.pqvolume.json", "D.PQVOLUME", "E.PQVOLUME.TXT"]
        for name in names:
            self.backup(root, vol["header"], name)
        (root / "invalid.pqvolume").write_bytes(b"not json")
        (root / "unrelated.json").write_text(P.header_json(vol["header"]), encoding="utf-8")
        candidates = self.fs.find_header_candidates(str(root))
        by_name = {Path(candidate["path"]).name: candidate for candidate in candidates}
        self.assertEqual(set(by_name), set(names) | {"invalid.pqvolume"})
        for name in names:
            self.assertEqual(by_name[name]["header"], vol["header"])
            self.assertIsNone(by_name[name]["error"])
        self.assertIsNone(by_name["invalid.pqvolume"]["header"])
        self.assertTrue(by_name["invalid.pqvolume"]["error"])

    def test_scan_keeps_complete_volume_ids_when_display_prefixes_collide(self):
        root = self.base / "mixed"
        root.mkdir()
        first = bytes.fromhex("112233445566" + "00" * 10)
        second = bytes.fromhex("112233445566" + "ff" * 10)
        vmk = bytearray(os.urandom(32))
        (root / "a.pqfc").write_bytes(self.pq.encrypt_volume_bytes(vmk, first, b"a"))
        (root / "b.pqfc").write_bytes(self.pq.encrypt_volume_bytes(vmk, second, b"b"))
        scan = self.fs.scan_tree(str(root))
        self.assertEqual(scan["volumeIds"], {first.hex(): 1, second.hex(): 1})
        self.assertEqual(scan["foreignVolumes"], {first.hex()[:12]: 2})

    def test_canonical_header_access_errors_are_not_missing(self):
        root, _, _ = self.make_volume()
        with mock.patch.object(self.fs, "read_file_bytes", side_effect=PermissionError("header denied")):
            status, header, error = self.fs.header_status(str(root))
        self.assertEqual(status, "invalid")
        self.assertIsNone(header)
        self.assertIn("header denied", error)
        with mock.patch.object(P.os, "lstat", side_effect=PermissionError("stat denied")):
            status, _, error = self.fs.header_status(str(root))
        self.assertEqual(status, "invalid")
        self.assertIn("stat denied", error)

    def test_uppercase_canonical_header_is_found(self):
        root, vol, _ = self.make_volume()
        original = root / P.VOLUME_HEADER_NAME
        staging = root / "header-stage"
        original.rename(staging)
        staging.rename(root / ".PQVOLUME")
        status, header, error = self.fs.header_status(str(root))
        self.assertEqual((status, header, error), ("ok", vol["header"], None))
        self.assertEqual(self.fs.find_header_candidates(str(root)), [])

    def test_parent_header_is_a_hint_and_not_a_child_header(self):
        root, _, _ = self.make_volume()
        child = root / "child"
        child.mkdir()
        self.assertEqual(self.fs.header_status(str(child)), ("none", None, None))
        self.assertEqual(Path(self.fs.parent_header_hint(str(child))), root / P.VOLUME_HEADER_NAME)
        self.assertEqual(self.fs.find_header_candidates(str(child)), [])


class HeaderDetectionUITests(HeaderFixtures, unittest.TestCase):
    def setUp(self):
        import fake_tk
        fake_tk.install()
        P._load_tk()
        for answers in fake_tk.SCRIPT.values():
            answers.clear()
        patch = mock.patch.multiple(P, ARGON_MEM_KIB=8, ARGON_TIME=1, ARGON_PAR=1)
        patch.start()
        self.addCleanup(patch.stop)
        self.tmp = tempfile.TemporaryDirectory(prefix="pqdisk-header-ui-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.window = fake_tk.Tk()
        self.app = P.App(self.window)
        self.addCleanup(self.window.destroy)
        self.pump(lambda: self.app.ready or self.app.selftest_failure)
        self.assertIsNone(self.app.selftest_failure)
        self.pq, self.fs = self.app.pq, self.app.vfs

    def pump(self, until=None):
        until = until or (lambda: not self.app.busy)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.window.pump()
            if until():
                return
            time.sleep(0.005)
        self.fail("UI worker timed out: " + self.app.log_text.get())

    def scan(self, root):
        self.app.dec_path.set(str(root))
        self.app.on_scan("dec")
        self.pump()

    def decrypt(self, password=PASSWORD):
        self.app.dec_unlock.pw.set(password)
        self.app.on_dec_start()
        self.pump()

    def test_one_matching_backup_autoloads_and_survives_full_decrypt(self):
        for hide in (False, True):
            with self.subTest(hide=hide):
                root, vol, files = self.make_volume("hidden" if hide else "visible", hide)
                backup = self.backup(root, vol["header"])
                self.scan(root)
                self.assertEqual(self.app.dec_header, vol["header"])
                self.assertEqual(self.app.dec_override, vol["header"])
                self.assertEqual(Path(self.app.dec_header_source), backup)
                self.assertEqual(self.app.dec_scan["encrypted"], len(files))
                self.assertFalse((root / P.VOLUME_HEADER_NAME).exists())
                self.decrypt()
                self.assert_restored(root, files)
                self.assertTrue(backup.exists())
                self.assertFalse((root / P.VOLUME_HEADER_NAME).exists())

    def test_txt_json_and_uppercase_backups_are_usable_from_scan(self):
        for index, name in enumerate(("backup.pqvolume.txt", "backup.pqvolume.json", "BACKUP.PQVOLUME")):
            with self.subTest(name=name):
                root, vol, files = self.make_volume("extension-%d" % index)
                backup = self.backup(root, vol["header"], name)
                self.scan(root)
                self.assertEqual(self.app.dec_header, vol["header"])
                self.assertEqual(Path(self.app.dec_header_source), backup)
                self.assertEqual(self.app.dec_scan["encrypted"], len(files))

    def test_matching_short_prefix_does_not_select_foreign_backup(self):
        root, vol, _ = self.make_volume()
        wrong = copy.deepcopy(vol["header"])
        volume_id = bytearray(vol["volumeId"])
        volume_id[-1] ^= 1
        wrong["volume_id"] = P.b64encode(volume_id)
        self.assertEqual(P.vol_id_short(wrong), P.vol_id_short(vol["header"]))
        self.backup(root, wrong)
        self.scan(root)
        self.assertIsNone(self.app.dec_header)
        self.assertIsNone(self.app.dec_override)
        self.assertFalse((root / P.VOLUME_HEADER_NAME).exists())

    def test_multiple_same_id_headers_with_different_slots_require_explicit_selection(self):
        root, vol, _ = self.make_volume()
        old = self.backup(root, vol["header"], "old.pqvolume")
        other = copy.deepcopy(vol["header"])
        other["slots"] = []
        self.pq.add_password_slot(other, vol["vmk"], BACKUP_PASSWORD, SMALL)
        new = self.backup(root, other, "new.pqvolume")
        self.scan(root)
        self.assertIsNone(self.app.dec_header)
        self.assertIsNone(self.app.dec_override)
        self.assertIsNotNone(self.app.dec_load_btn.visible)
        self.assertTrue(old.exists() and new.exists())

    def test_identical_canonical_and_backup_still_require_selection(self):
        root, vol, _ = self.make_volume()
        self.backup(root, vol["header"], remove_canonical=False)
        self.scan(root)
        self.assertIsNone(self.app.dec_header)
        self.assertIsNone(self.app.dec_override)

    def test_one_matching_header_is_used_when_other_backup_belongs_to_another_volume(self):
        root, vol, files = self.make_volume()
        other = self.pq.new_volume()
        self.pq.add_password_slot(other["header"], other["vmk"], BACKUP_PASSWORD, SMALL)
        self.backup(root, other["header"], "foreign.pqvolume", remove_canonical=False)
        self.scan(root)
        self.assertEqual(self.app.dec_header, vol["header"])
        self.assertEqual(self.app.dec_scan["encrypted"], len(files))

    def test_sole_canonical_header_remains_usable_without_ciphertext(self):
        root = self.base / "empty-volume"
        root.mkdir()
        vol = self.pq.new_volume()
        self.pq.add_password_slot(vol["header"], vol["vmk"], PASSWORD, SMALL)
        self.fs.write_volume_header(str(root), vol["header"])
        self.scan(root)
        self.assertEqual(self.app.dec_header, vol["header"])
        self.assertEqual(self.app.dec_scan["encrypted"], 0)

    def test_canonical_and_matching_backup_require_explicit_selection(self):
        root, vol, files = self.make_volume()
        alternate = copy.deepcopy(vol["header"])
        alternate["slots"] = []
        self.pq.add_password_slot(alternate, vol["vmk"], BACKUP_PASSWORD, SMALL)
        self.backup(root, alternate, remove_canonical=False)
        self.scan(root)
        self.assertIsNone(self.app.dec_header)
        self.assertIsNone(self.app.dec_override)
        self.assertIsNotNone(self.app.dec_load_btn.visible)

    def test_unreadable_canonical_is_reported_and_one_matching_backup_autoloads(self):
        root, vol, _ = self.make_volume()
        self.backup(root, vol["header"], remove_canonical=False)
        original_reader = self.fs.read_header_file

        def denied_canonical(path):
            if Path(path).name == P.VOLUME_HEADER_NAME:
                raise PermissionError("canonical header denied")
            return original_reader(path)

        with mock.patch.object(self.fs, "read_header_file", side_effect=denied_canonical):
            self.scan(root)
        self.assertEqual(self.app.dec_header, vol["header"])
        self.assertEqual(self.app.dec_override, vol["header"])
        self.assertIn("canonical header denied", self.app.log_text.get())

    def test_parent_header_only_suggests_root_without_loading_or_widening_scope(self):
        root, _, _ = self.make_volume()
        child = root / "nested"
        self.scan(child)
        self.assertEqual(Path(self.app.dec_dir), child)
        self.assertIsNone(self.app.dec_header)
        self.assertIsNone(self.app.dec_override)
        self.assertIn(str(root), self.app.log_text.get() + self.app.dec_scan_info.cget("text"))
        self.assertFalse((child / P.VOLUME_HEADER_NAME).exists())

    def test_switching_input_directory_drops_previous_backup_state(self):
        first, vol, first_files = self.make_volume("first")
        self.backup(first, vol["header"])
        second = self.base / "second"
        second.mkdir()
        (second / "untouched.txt").write_bytes(b"untouched")
        self.scan(first)
        self.assertIsNotNone(self.app.dec_override)
        self.app.dec_path.set(str(second))
        self.decrypt()
        self.assertEqual(Path(self.app.dec_dir), second)
        self.assertIsNone(self.app.dec_header)
        self.assertIsNone(self.app.dec_override)
        self.assertFalse(self.app.dec_header_source)
        self.assertEqual((second / "untouched.txt").read_bytes(), b"untouched")
        self.assertTrue(all(not (first / name).exists() for name in first_files))

    def test_same_id_manual_backup_really_supplies_its_own_password_slot(self):
        root, vol, files = self.make_volume()
        alternate = copy.deepcopy(vol["header"])
        alternate["slots"] = []
        self.pq.add_password_slot(alternate, vol["vmk"], BACKUP_PASSWORD, SMALL)
        backup = self.backup(root, alternate, remove_canonical=False)
        self.scan(root)
        self.app.on_dec_load_header(str(backup))
        self.pump()
        self.assertEqual(self.app.dec_header, alternate)
        self.assertEqual(self.app.dec_override, alternate)
        self.decrypt(BACKUP_PASSWORD)
        self.assert_restored(root, files)
        self.assertTrue((root / P.VOLUME_HEADER_NAME).exists())
        self.assertTrue(backup.exists())

    def test_manual_header_binds_to_current_input_directory(self):
        first, first_vol, first_files = self.make_volume("first")
        second, second_vol, second_files = self.make_volume("second")
        backup = self.backup(second, second_vol["header"])
        self.scan(first)
        self.app.dec_path.set(str(second))
        self.app.on_dec_load_header(str(backup))
        self.pump()
        self.assertEqual(Path(self.app.dec_dir), second)
        self.assertEqual(self.app.dec_header, second_vol["header"])
        self.decrypt()
        self.assert_restored(second, second_files)
        self.assertTrue(all(not (first / name).exists() for name in first_files))
        self.assertEqual(self.fs.read_volume_header(str(first)), first_vol["header"])

    def test_manual_choice_bypasses_case_ambiguity_without_writing_headers(self):
        root, vol, files = self.make_volume()
        backup = self.backup(root, vol["header"], remove_canonical=False)
        self.scan(root)
        with mock.patch.object(P, "_volume_header_path", side_effect=P.PQError("ambiguous", "AMBIGUOUS_HEADER")), \
                mock.patch.object(self.fs, "write_volume_header", side_effect=AssertionError("must not write")):
            self.app.on_dec_load_header(str(backup))
            self.pump()
            self.assertEqual(self.app.dec_header, vol["header"])
            self.assertEqual(Path(self.app.dec_header_source), backup)
            self.decrypt()
        self.assert_restored(root, files)
        self.assertTrue((root / P.VOLUME_HEADER_NAME).exists())
        self.assertTrue(backup.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
