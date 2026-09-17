"""Manual header destinations, retention, reuse and explicit volume renewal."""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]
import fake_tk
import pqdiskcrypt as P

PASSWORD = 'Manual-Header-Password-2026!'


class ManualHeaderUITests(unittest.TestCase):
    def setUp(self):
        fake_tk.install()
        P._load_tk()
        for answers in fake_tk.SCRIPT.values():
            answers.clear()
        patch = mock.patch.multiple(P, ARGON_MEM_KIB=8, ARGON_TIME=1, ARGON_PAR=1)
        patch.start()
        self.addCleanup(patch.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'data'
        self.root.mkdir()
        (self.root / 'note.txt').write_bytes(b'original payload')
        self.header = self.base / 'manually-selected.pqvolume'
        self.window = fake_tk.Tk()
        self.app = P.App(self.window)
        self.addCleanup(self.window.destroy)
        self.pump(lambda: self.app.ready or self.app.selftest_failure)
        self.assertIsNone(self.app.selftest_failure)
        self.app.enc_path.set(str(self.root))
        self.app.dec_path.set(str(self.root))
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
            time.sleep(.005)
        self.fail(self.app.log_text.get())

    def encrypt(self, initial=False):
        if initial:
            fake_tk.SCRIPT['asksaveasfilename'].append(str(self.header))
        self.app.on_enc_start()
        self.pump()

    def decrypt(self):
        self.app.on_dec_start()
        self.pump()

    def test_manual_external_save_and_reuse_keep_header_bytes_unchanged(self):
        for hide in (False, True):
            with self.subTest(hide=hide):
                self.app.enc_hide.set(hide)
                self.encrypt(initial=not self.header.exists())
                before = self.header.read_bytes()
                self.assertFalse((self.root / '.pqvolume').exists())
                self.assertFalse((self.root / 'note.txt').exists())
                self.decrypt()
                self.assertEqual((self.root / 'note.txt').read_bytes(), b'original payload')
                self.assertEqual(self.header.read_bytes(), before)
                with mock.patch.object(P.filedialog, 'asksaveasfilename', side_effect=AssertionError('no save on reuse')):
                    self.encrypt()
                self.assertFalse((self.root / 'note.txt').exists())
                self.assertEqual(self.header.read_bytes(), before)
                self.decrypt()

    def test_new_volume_replaces_previous_path_only_when_requested(self):
        self.encrypt(initial=True)
        old = self.app.vfs.read_header_file(str(self.header))
        self.decrypt()
        self.app.enc_recreate.set(True)
        with mock.patch.object(P.filedialog, 'asksaveasfilename', side_effect=AssertionError('reuse destination')):
            self.encrypt()
        new = self.app.vfs.read_header_file(str(self.header))
        self.assertNotEqual(new['volume_id'], old['volume_id'])
        self.assertFalse((self.root / '.pqvolume').exists())
        self.assertFalse((self.root / 'note.txt').exists())
        self.decrypt()
        self.assertEqual((self.root / 'note.txt').read_bytes(), b'original payload')

    def test_cancel_save_does_not_encrypt_or_create_header(self):
        self.encrypt()
        self.assertEqual((self.root / 'note.txt').read_bytes(), b'original payload')
        self.assertFalse(self.header.exists())
        self.assertFalse((self.root / '.pqvolume').exists())
        self.assertFalse(list(self.root.rglob('*.pqfc')))

    def test_save_failure_does_not_encrypt(self):
        with mock.patch.object(self.app.vfs, 'save_encryption_header', side_effect=OSError('disk full')):
            self.encrypt(initial=True)
        self.assertTrue((self.root / 'note.txt').exists())
        self.assertFalse(self.header.exists())
        self.assertFalse(list(self.root.rglob('*.pqfc')))

    def test_existing_unrelated_file_is_not_overwritten(self):
        self.header.write_bytes(b'important')
        self.encrypt(initial=True)
        self.assertEqual(self.header.read_bytes(), b'important')
        self.assertTrue((self.root / 'note.txt').exists())

    def test_pending_ciphertext_blocks_new_volume(self):
        self.encrypt(initial=True)
        before = self.header.read_bytes()
        self.app.enc_recreate.set(True)
        self.encrypt()
        self.assertEqual(self.header.read_bytes(), before)
        self.assertTrue((self.root / 'note.txt.pqfc').exists())

    def test_renamed_ciphertext_blocks_new_volume(self):
        self.encrypt(initial=True)
        before = self.header.read_bytes()
        (self.root / 'note.txt.pqfc').rename(self.root / 'saved.bin')
        self.app.enc_recreate.set(True)
        self.encrypt()
        self.assertEqual(self.header.read_bytes(), before)
        self.assertTrue((self.root / 'saved.bin').exists())

    def test_header_in_root_is_not_encrypted_or_deleted(self):
        self.header = self.root / 'chosen.pqvolume'
        self.encrypt(initial=True)
        before = self.header.read_bytes()
        self.decrypt()
        self.assertEqual(self.header.read_bytes(), before)
        self.assertFalse((self.root / '.pqvolume').exists())
        self.assertTrue((self.root / 'note.txt').exists())

    def test_hidden_names_reuse_then_renew_without_extra_header(self):
        self.app.enc_hide.set(True)
        self.encrypt(initial=True)
        self.assertTrue(self.app.vfs.read_header_file(str(self.header))['hide_names'])
        before = self.header.read_bytes()
        self.decrypt()
        self.encrypt()
        self.assertEqual(self.header.read_bytes(), before)
        self.decrypt()
        self.app.enc_recreate.set(True)
        self.encrypt()
        self.assertNotEqual(self.header.read_bytes(), before)
        self.decrypt()
        self.assertEqual((self.root / 'note.txt').read_bytes(), b'original payload')
        self.assertFalse((self.root / '.pqvolume').exists())

    def test_management_updates_selected_external_file(self):
        self.encrypt(initial=True)
        self.app.mg_open_dir(str(self.root))
        self.assertIsNotNone(self.app.mg_header)
        self.app.mg_unlock.pw.set(PASSWORD)
        self.app.on_mg_unlock()
        self.pump()
        self.app.mg_new_pw.set('Another-Manual-Password-2026!')
        self.app.mg_new_pw2.set('Another-Manual-Password-2026!')
        self.app.on_mg_add_pw()
        self.pump()
        self.assertEqual(len(self.app.vfs.read_header_file(str(self.header))['slots']), 2)
        self.app.on_mg_convert()
        self.pump()
        self.assertTrue(self.app.vfs.read_header_file(str(self.header))['hide_names'])
        self.assertFalse((self.root / '.pqvolume').exists())

    def test_missing_remembered_header_can_be_replaced_by_loading_backup(self):
        self.encrypt(initial=True)
        replacement = self.base / 'moved.pqvolume'
        self.header.rename(replacement)
        self.app.on_dec_load_header(str(replacement))
        self.pump()
        self.assertEqual(self.app.dec_header_source, str(replacement))
        self.decrypt()
        self.assertEqual((self.root / 'note.txt').read_bytes(), b'original payload')
        self.assertTrue(replacement.exists())

    def test_management_source_does_not_follow_decrypt_tab_choice(self):
        self.encrypt(initial=True)
        self.app.mg_open_dir(str(self.root))
        self.app.mg_unlock.pw.set(PASSWORD)
        self.app.on_mg_unlock()
        self.pump()
        alternate = self.base / 'alternate.pqvolume'
        alternate.write_bytes(self.header.read_bytes())
        alternate_before = alternate.read_bytes()
        self.app.on_dec_load_header(str(alternate))
        self.pump()
        self.app.mg_new_pw.set('New-Management-Password-2026!')
        self.app.mg_new_pw2.set('New-Management-Password-2026!')
        self.app.on_mg_add_pw()
        self.pump()
        self.assertEqual(alternate.read_bytes(), alternate_before)
        self.assertEqual(len(self.app.vfs.read_header_file(str(self.header))['slots']), 2)

    def test_conversion_does_not_move_nested_header(self):
        nested = self.root / 'headers'
        nested.mkdir()
        self.header = nested / 'chosen.pqvolume'
        self.encrypt(initial=True)
        before = self.header.read_bytes()
        self.app.mg_open_dir(str(self.root))
        self.app.mg_unlock.pw.set(PASSWORD)
        self.app.on_mg_unlock()
        self.pump()
        self.app.on_mg_convert()
        self.pump()
        self.assertEqual(self.header.read_bytes(), before)
        self.assertTrue((self.root / 'note.txt.pqfc').exists())
        self.assertFalse(self.app.vfs.read_header_file(str(self.header))['hide_names'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
