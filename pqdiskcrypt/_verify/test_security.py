"""Security regression tests. All files are synthetic and temporary."""
import base64
import copy
import errno
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pqdiskcrypt as P

SMALL = {"timeCost": 1, "memKiB": 8, "parallelism": 1}
VECTORS = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))


class SecurityCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pqdisk-security-")
        self.base = Path(self.tmp.name)
        self.root = self.base / "volume"
        self.root.mkdir()
        self.pq = P.PQCrypto()
        self.fs = P.VolumeFS(self.pq)

    def tearDown(self):
        self.tmp.cleanup()

    def volume(self, hide=False):
        vol = self.pq.new_volume(hide_names=hide)
        self.pq.add_password_slot(vol["header"], vol["vmk"], "test password", SMALL)
        self.fs.write_volume_header(str(self.root), vol["header"])
        ctx = {"vmk": vol["vmk"], "volumeId": vol["volumeId"], "hideNames": hide}
        return ctx, vol["header"]

    def snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*")
                if p.is_file() and p.name != P.LOCK_NAME}

    def assert_no_temp(self):
        self.assertFalse(any(p.name.startswith(P.TMP_PREFIX) for p in self.root.rglob("*")))

    def put_manifest(self, ctx, entries, directory="", target=None):
        obj = {"v": 1, "dir": directory, "entries": entries}
        ciphertext = self.pq.encrypt_volume_bytes(ctx["vmk"], ctx["volumeId"], json.dumps(obj).encode())
        (target or self.root / P.DIR_MANIFEST_NAME).write_bytes(ciphertext)


class NativeBackendTests(SecurityCase):
    def test_native_is_default_and_reference_is_not_called(self):
        self.assertIs(self.pq.mlkem, P.NativeMLKEM1024)
        self.assertIs(self.pq.mldsa, P.NativeMLDSA87)
        with mock.patch.object(P.MLKEM1024, "keygen", side_effect=AssertionError("Python fallback")), \
                mock.patch.object(P.MLDSA87, "sign", side_effect=AssertionError("Python fallback")):
            self.assertTrue(self.pq.self_test(SMALL))

    def test_native_known_answer_decapsulation(self):
        for vector in VECTORS["mlkem1024"]:
            sk = base64.b64decode(vector["sk"])
            for ct, result in (("ct", "ss_decaps"), ("ct_bad", "ss_bad")):
                self.assertEqual(P.NativeMLKEM1024.decapsulate(base64.b64decode(vector[ct]), sk),
                                 base64.b64decode(vector[result]))

    def test_native_verifies_legacy_signatures(self):
        for vector in VECTORS["mldsa87"]:
            for signature in vector["sigs"]:
                for field in ("sig_det", "sig_hedged"):
                    self.assertTrue(P.NativeMLDSA87.verify(base64.b64decode(signature[field]),
                        base64.b64decode(signature["msg"]), base64.b64decode(vector["pk"])))

    def test_no_silent_fallback_when_native_is_missing(self):
        import builtins
        original = builtins.__import__

        def deny(name, *args, **kwargs):
            if name.startswith("pqcrypto"):
                raise ImportError("missing backend")
            return original(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=deny), self.assertRaises(P.PQError):
            P.PQCrypto()

    def test_mixed_keypairs_rejected(self):
        original = VECTORS["keypairA"]["key"]
        other = VECTORS["keypairB"]["key"]
        for field in ("x25519_pub", "x25519_priv", "mlkem_pub", "mlkem_secret", "mldsa_pub", "mldsa_secret"):
            with self.subTest(field=field):
                key = dict(original, **{field: other[field]})
                with self.assertRaises(P.PQError):
                    self.pq.validate_key_obj(key)

    def test_invalid_mldsa_secret_encoding_rejected_before_signing(self):
        key = bytearray(base64.b64decode(VECTORS["keypairA"]["key"]["mldsa_secret"]))
        key[128] = 255
        with mock.patch.object(P.NativeMLDSA87, "backend") as backend, self.assertRaises(P.PQError):
            P.NativeMLDSA87.sign(b"test", key)
        backend.assert_not_called()

    def test_noncanonical_public_key_rejected(self):
        key = copy.deepcopy(VECTORS["keypairA"]["pub"])
        mk = bytearray(base64.b64decode(key["mlkem_pub"]))
        mk[:2] = b"\xff\xff"
        key["mlkem_pub"] = P.b64encode(mk)
        with self.assertRaises(P.PQError):
            self.pq.validate_pub(key)
        key = dict(VECTORS["keypairA"]["pub"], x25519_pub=P.b64encode(bytes(32)))
        with self.assertRaises(P.PQError):
            self.pq.validate_pub(key)


class InputTests(SecurityCase):
    def test_json_duplicates_nonfinite_and_depth_rejected(self):
        for raw in (b'{"slots":[],"slots":[]}', b'{"a":{"b":1,"b":2}}', b'{"x":NaN}',
                    b'{"x":Infinity}', b'{"x":1e999}', b'[' * 40 + b'0' + b']' * 40):
            with self.subTest(raw=raw[:30]), self.assertRaises(P.PQError):
                P.strict_json(raw)

    def test_json_file_limit_is_enforced_before_parsing(self):
        path = self.root / "huge.key"
        path.write_bytes(b" " * (P.MAX_JSON_BYTES + 1))
        with mock.patch.object(P, "strict_json") as parse, self.assertRaises(P.PQError):
            P.read_json_file(str(path))
        parse.assert_not_called()

    def test_bad_base64_padding_rejected(self):
        for value in ("AAAA=", "AAAA==", "AA=", "AAA==", "Zg===", "Zh=="):
            with self.subTest(value=value), self.assertRaises(P.PQError):
                P.b64decode(value)

    def test_kdf_types_and_resource_budgets(self):
        invalid = [(True, 8, 1), (1.0, 8, 1), ("1", 8, 1), (1, 8, True),
                   (1, 8, 2), (1, 512 * 1024 + 1, 1), (16, 512 * 1024, 1), (0, 8, 1)]
        backend = mock.Mock(side_effect=AssertionError("KDF executed"))
        pq = P.PQCrypto(argon2id=backend)
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(P.PQError):
                pq.argon2_raw("pw", bytes(16), *args)
        backend.assert_not_called()

    def test_slot_count_and_aggregate_work_budget(self):
        _, header = self.volume()
        h = copy.deepcopy(header)
        h["slots"] *= P.MAX_SLOTS + 1
        with self.assertRaises(P.PQError):
            self.pq.validate_volume_header(h)
        h = copy.deepcopy(header)
        h["slots"][0]["kdf_params"].update(t=4, m=256 * 1024, p=4)
        h["slots"] *= 5
        backend = mock.Mock(side_effect=AssertionError("KDF executed"))
        with mock.patch.object(self.pq, "argon2id", backend), self.assertRaises(P.PQError):
            self.pq.unlock_volume(h, password="pw")
        backend.assert_not_called()

    def test_wrapped_key_validation_precedes_kdf(self):
        container = VECTORS["wrapped_key"]["container"]
        mutations = [{"cipher": "other"}, {"kdf": "other"}, {"nonce": "AA=="},
                     {"ciphertext": "AA=="}, {"kdf_params": []}]
        for mutation in mutations:
            with self.subTest(mutation=mutation), mock.patch.object(self.pq, "argon2_raw") as derive:
                with self.assertRaises(P.PQError):
                    self.pq.unwrap_secret_key(dict(container, **mutation), "pw")
                derive.assert_not_called()

    def test_single_file_size_is_bounded(self):
        path = self.root / "large.bin"
        with path.open("wb") as f:
            f.truncate(P.MAX_SINGLE_FILE_BYTES + 1)
        with self.assertRaises(P.PQError):
            self.fs.read_file_bytes(str(path))


class ManifestTests(SecurityCase):
    def test_authenticated_traversal_and_reserved_names_never_write_outside(self):
        ctx, _ = self.volume(True)
        ident = "1234567890abcdef"
        cipher = self.root / (ident + P.ENC_EXT)
        cipher.write_bytes(self.pq.encrypt_volume_bytes(ctx["vmk"], ctx["volumeId"], b"secret"))
        names = ["../escaped.txt", "..\\escaped.txt", str(self.base / "escaped.txt"),
                 "C:\\escaped.txt", "C:escaped.txt", "\\\\server\\share", "data:stream",
                 ".", "..", "", "NUL.txt", "com1", "LPT¹.txt", "trailing.", "trailing ",
                 P.VOLUME_HEADER_NAME, P.DIR_MANIFEST_NAME, P.LOCK_NAME, P.TMP_PREFIX + "x", "bad\x00name"]
        for name in names:
            with self.subTest(name=name):
                self.put_manifest(ctx, {ident: {"n": name, "t": "f"}})
                before = self.snapshot()
                result = self.fs.decrypt_tree(str(self.root), ctx)
                self.assertTrue(result["errors"])
                self.assertEqual(self.snapshot(), before)
                self.assertFalse((self.base / "escaped.txt").exists())

    def test_malformed_entries_and_ids_fail_closed(self):
        ctx, _ = self.volume(True)
        cases = [{"../bad": {"n": "good", "t": "f"}}, {"a" * 16: []},
                 {"a" * 16: {"n": "good", "t": "x"}}, {"a" * 16: {"n": 7, "t": "f"}},
                 {"a" * 16: {"n": "a", "t": "f"}, "b" * 16: {"n": "A", "t": "f"}}]
        for entries in cases:
            with self.subTest(entries=entries):
                self.put_manifest(ctx, entries)
                with self.assertRaises(P.PQError):
                    self.fs._load_manifest(str(self.root), "", ctx)

    def test_bad_manifest_stops_conversion_before_rename(self):
        ctx, header = self.volume(True)
        cipher = self.root / ("a" * 16 + P.ENC_EXT)
        cipher.write_bytes(self.pq.encrypt_volume_bytes(ctx["vmk"], ctx["volumeId"], b"data"))
        self.put_manifest(ctx, {"a" * 16: {"n": "../escape", "t": "f"}})
        before = self.snapshot()
        result = self.fs.convert_names(str(self.root), header, ctx, False)
        self.assertFalse(result["completed"])
        self.assertEqual(self.snapshot(), before)

    def test_header_layout_mismatch_is_not_silently_accepted(self):
        ctx, _ = self.volume(True)
        self.put_manifest(ctx, {})
        result = self.fs.decrypt_tree(str(self.root), dict(ctx, hideNames=False))
        self.assertTrue(result["errors"])
        self.assertTrue((self.root / P.VOLUME_HEADER_NAME).exists())

    def test_extension_repair_validates_every_component(self):
        self.volume()
        outside = self.base / "outside"
        outside.write_bytes(b"untouched")
        for path in ("../outside", "..\\outside", str(outside), "C:outside", "x/../outside", "x//y"):
            with self.subTest(path=path):
                result = self.fs.fix_extensions(str(self.root), [path])
                self.assertTrue(result["errors"])
                self.assertEqual(outside.read_bytes(), b"untouched")
                self.assertFalse((self.base / "outside.pqfc").exists())


class FileSafetyTests(SecurityCase):
    def test_fsync_failure_preserves_plaintext(self):
        ctx, _ = self.volume()
        source = self.root / "data"
        source.write_bytes(os.urandom(100000))
        before = self.snapshot()
        with mock.patch.object(P.os, "fsync", side_effect=OSError(errno.EIO, "injected fsync failure")):
            result = self.fs.encrypt_tree(str(self.root), ctx)
        self.assertTrue(result["errors"])
        self.assertEqual(self.snapshot(), before)
        self.assert_no_temp()

    def test_fsync_failure_preserves_ciphertext_on_decryption(self):
        ctx, _ = self.volume()
        (self.root / "data").write_bytes(b"secret")
        self.assertFalse(self.fs.encrypt_tree(str(self.root), ctx)["errors"])
        before = self.snapshot()
        with mock.patch.object(P.os, "fsync", side_effect=OSError(errno.EIO, "injected fsync failure")):
            result = self.fs.decrypt_tree(str(self.root), ctx)
        self.assertTrue(result["errors"])
        self.assertEqual(self.snapshot(), before)
        self.assert_no_temp()

    def test_corrupt_last_chunk_does_not_publish_partial_plaintext(self):
        ctx, _ = self.volume()
        (self.root / "data").write_bytes(os.urandom(2 * 1024 * 1024))
        self.assertFalse(self.fs.encrypt_tree(str(self.root), ctx)["errors"])
        path = self.root / "data.pqfc"
        ciphertext = bytearray(path.read_bytes())
        ciphertext[-1] ^= 1
        path.write_bytes(ciphertext)
        before = self.snapshot()
        result = self.fs.decrypt_tree(str(self.root), ctx)
        self.assertTrue(result["errors"])
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / "data").exists())
        self.assert_no_temp()

    def test_failed_unhide_rename_keeps_manifest(self):
        ctx, header = self.volume(True)
        (self.root / "data").write_bytes(b"data")
        self.fs.encrypt_tree(str(self.root), ctx)
        before = self.snapshot()
        with mock.patch.object(P, "_publish", side_effect=OSError(errno.EACCES, "injected rename failure")):
            result = self.fs.convert_names(str(self.root), header, ctx, False)
        self.assertTrue(result["errors"])
        self.assertFalse(result["completed"])
        self.assertEqual(self.snapshot(), before)

    def test_verification_cannot_be_disabled_when_deleting(self):
        ctx, _ = self.volume()
        (self.root / "data").write_bytes(b"payload")
        with mock.patch.object(self.pq, "decrypt_volume_stream", side_effect=P.PQError("verify failed")) as verify:
            result = self.fs.encrypt_tree(str(self.root), ctx, verify=False)
        verify.assert_called_once()
        self.assertTrue(result["errors"])
        self.assertEqual((self.root / "data").read_bytes(), b"payload")
        self.assertFalse((self.root / "data.pqfc").exists())

    def test_valid_but_wrong_encrypted_content_fails_hash_verification(self):
        ctx, _ = self.volume()
        (self.root / "data").write_bytes(b"original")
        original = self.pq.encrypt_volume_stream

        def wrong(vmk, vid, source, sink, cancel=None, on_progress=None):
            data = source.read(100)
            return original(vmk, vid, P._MemReader(b"x" * len(data)), sink, cancel, on_progress)

        with mock.patch.object(self.pq, "encrypt_volume_stream", side_effect=wrong):
            result = self.fs.encrypt_tree(str(self.root), ctx)
        self.assertTrue(result["errors"])
        self.assertEqual((self.root / "data").read_bytes(), b"original")
        self.assert_no_temp()

    def test_source_change_after_read_preserves_new_source(self):
        ctx, _ = self.volume()
        source = self.root / "data"
        source.write_bytes(b"original")

        def change(event):
            if event["type"] == "verify-start":
                source.write_bytes(b"updated by another process")

        result = self.fs.encrypt_tree(str(self.root), ctx, on_event=change)
        self.assertTrue(result["errors"])
        self.assertEqual(source.read_bytes(), b"updated by another process")
        self.assertFalse((self.root / "data.pqfc").exists())
        self.assert_no_temp()

    def test_publish_race_never_overwrites_destination(self):
        ctx, _ = self.volume()
        (self.root / "data").write_bytes(b"original")

        def race(event):
            if event["type"] == "verify-start":
                (self.root / "data.pqfc").write_bytes(b"concurrent output")

        result = self.fs.encrypt_tree(str(self.root), ctx, on_event=race)
        self.assertTrue(result["errors"])
        self.assertEqual((self.root / "data.pqfc").read_bytes(), b"concurrent output")
        self.assertEqual((self.root / "data").read_bytes(), b"original")

    def test_existing_same_volume_ciphertext_is_preserved(self):
        ctx, _ = self.volume()
        (self.root / "data").write_bytes(b"version one")
        self.fs.encrypt_tree(str(self.root), ctx)
        ciphertext = (self.root / "data.pqfc").read_bytes()
        (self.root / "data").write_bytes(b"version two")
        result = self.fs.encrypt_tree(str(self.root), ctx)
        self.assertTrue(result["errors"])
        self.assertEqual((self.root / "data.pqfc").read_bytes(), ciphertext)
        self.assertEqual((self.root / "data").read_bytes(), b"version two")

    def test_cancel_before_commit_preserves_source(self):
        ctx, _ = self.volume()
        (self.root / "data").write_bytes(b"original")
        cancel = threading.Event()
        result = self.fs.encrypt_tree(str(self.root), ctx, cancel=cancel,
            on_event=lambda event: cancel.set() if event["type"] == "verify-start" else None)
        self.assertTrue(result["cancelled"])
        self.assertEqual((self.root / "data").read_bytes(), b"original")
        self.assertFalse((self.root / "data.pqfc").exists())
        self.assert_no_temp()

    def test_unknown_temp_files_are_never_swept(self):
        ctx, _ = self.volume()
        path = self.root / (P.TMP_PREFIX + "important")
        path.write_bytes(b"only surviving copy")
        self.fs.encrypt_tree(str(self.root), ctx)
        result = self.fs.decrypt_tree(str(self.root), ctx)
        self.assertEqual(path.read_bytes(), b"only surviving copy")
        self.assertFalse(result["headerRemoved"])

    def test_misnamed_ciphertext_prevents_header_removal(self):
        ctx, _ = self.volume()
        (self.root / "data").write_bytes(b"data")
        (self.root / "renamed.bin").write_bytes(self.pq.encrypt_volume_bytes(ctx["vmk"], ctx["volumeId"], b"hidden"))
        self.fs.encrypt_tree(str(self.root), ctx)
        # Put a same-volume ciphertext at an unrecognized extension after encryption.
        (self.root / "unexpected.bin").write_bytes(self.pq.encrypt_volume_bytes(ctx["vmk"], ctx["volumeId"], b"hidden"))
        result = self.fs.decrypt_tree(str(self.root), ctx)
        self.assertFalse(result["headerRemoved"])
        self.assertTrue((self.root / P.VOLUME_HEADER_NAME).exists())

    def test_foreign_header_is_never_removed(self):
        ctx, _ = self.volume()
        (self.root / "data").write_bytes(b"data")
        self.fs.encrypt_tree(str(self.root), ctx)
        _, header2 = self.volume()
        result = self.fs.decrypt_tree(str(self.root), ctx)
        self.assertFalse(result["headerRemoved"])
        self.assertEqual(self.fs.read_volume_header(str(self.root)), header2)

    def test_stale_encrypt_context_is_rejected(self):
        ctx, _ = self.volume()
        self.volume()
        (self.root / "data").write_bytes(b"data")
        with self.assertRaises(P.PQError):
            self.fs.encrypt_tree(str(self.root), ctx)
        self.assertEqual((self.root / "data").read_bytes(), b"data")

    def test_hardlinks_are_skipped_and_direct_reads_rejected(self):
        ctx, _ = self.volume()
        outside = self.base / "outside"
        outside.write_bytes(b"outside")
        os.link(outside, self.root / "linked")
        self.assertEqual(self.fs.scan_tree(str(self.root))["links"], 1)
        self.assertEqual(self.fs.encrypt_tree(str(self.root), ctx)["files"], 0)
        with self.assertRaises(P.PQError):
            self.fs.read_file_bytes(str(self.root / "linked"))
        self.assertEqual(outside.read_bytes(), b"outside")

    @unittest.skipUnless(os.name == "nt", "Windows reparse-point regression")
    def test_windows_junctions_in_sources_destinations_and_roots(self):
        ctx, _ = self.volume(True)
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret").write_bytes(b"outside")
        link = self.root / "junction"
        # The fixed command only creates a junction between test-owned paths.
        result = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
        self.assertEqual(result.returncode, 0, repr(result.stderr))
        try:
            self.assertEqual(self.fs.scan_tree(str(self.root))["links"], 1)
            with self.assertRaises(P.PQError):
                self.fs.scan_tree(str(link))
            with self.assertRaises(P.PQError):
                self.fs.write_file_bytes(str(link / "new"), b"bad")
            with self.assertRaises(P.PQError):
                self.fs.read_file_bytes(str(link / "secret"))
            self.assertEqual((outside / "secret").read_bytes(), b"outside")
            self.assertFalse((outside / "new").exists())
        finally:
            os.rmdir(link)

    @unittest.skipUnless(os.name == "nt", "Windows deny-write source handle")
    def test_windows_source_handle_denies_concurrent_writes(self):
        source = self.root / "data"
        source.write_bytes(b"original")
        with P._read_regular(str(source)):
            with self.assertRaises(PermissionError):
                source.write_bytes(b"bad")
        self.assertEqual(source.read_bytes(), b"original")

    @unittest.skipIf(os.name == "nt", "POSIX symlink regression")
    def test_posix_symlink_targets_rejected(self):
        self.volume()
        outside = self.base / "outside"
        outside.write_bytes(b"outside")
        link = self.root / "link"
        link.symlink_to(outside)
        with self.assertRaises(P.PQError):
            self.fs.write_file_bytes(str(link), b"bad")
        with self.assertRaises(P.PQError):
            self.fs.read_file_bytes(str(link))
        self.assertEqual(outside.read_bytes(), b"outside")

    def test_volume_lock_blocks_another_process_and_recovers(self):
        self.volume()
        code = ("import sys,pqdiskcrypt as p\n"
                "try:\n with p._volume_lock(sys.argv[1]): pass\n"
                "except p.PQError as e:\n sys.exit(17 if e.code=='VOLUME_BUSY' else 18)\n")
        env = dict(os.environ)
        env["PYTHONPATH"] = str(HERE.parent) + os.pathsep + env.get("PYTHONPATH", "")
        with P._volume_lock(str(self.root)):
            result = subprocess.run([sys.executable, "-c", code, str(self.root)], env=env, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 17, repr(result.stderr))
        result = subprocess.run([sys.executable, "-c", code, str(self.root)], env=env, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, repr(result.stderr))

    def test_private_temp_is_exclusive_and_private_on_posix(self):
        path, f = P._new_temp(str(self.root))
        try:
            f.close()
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            with mock.patch.object(P, "random_bytes", return_value=bytes.fromhex(Path(path).name[len(P.TMP_PREFIX):])):
                with self.assertRaises(P.PQError):
                    P._new_temp(str(self.root))
            self.assertEqual(Path(path).read_bytes(), b"")
        finally:
            f.close()
            os.unlink(path)

    @unittest.skipUnless(os.name == "nt", "Windows protected DACL")
    def test_windows_private_file_dacl_is_protected_and_restricted(self):
        import ctypes as c
        from ctypes import wintypes as w
        api = c.WinDLL("advapi32", use_last_error=True)
        kernel = c.WinDLL("kernel32", use_last_error=True)
        api.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, c.c_int, w.DWORD, c.c_void_p, c.c_void_p,
                                            c.POINTER(c.c_void_p), c.c_void_p, c.POINTER(c.c_void_p)]
        api.GetSecurityDescriptorControl.argtypes = [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)]
        api.GetAclInformation.argtypes = [c.c_void_p, c.c_void_p, w.DWORD, c.c_int]
        api.GetAce.argtypes = [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)]
        api.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
        kernel.LocalFree.argtypes = [c.c_void_p]
        path = self.root / "private.key"
        self.fs.write_file_bytes(str(path), b"private")
        dacl, descriptor = c.c_void_p(), c.c_void_p()
        self.assertEqual(api.GetNamedSecurityInfoW(str(path), 1, 4, None, None, c.byref(dacl), None, c.byref(descriptor)), 0)
        try:
            control, revision = w.WORD(), w.DWORD()
            self.assertTrue(api.GetSecurityDescriptorControl(descriptor, c.byref(control), c.byref(revision)))
            self.assertTrue(control.value & 0x1000)
            counts = (w.DWORD * 3)()
            self.assertTrue(api.GetAclInformation(dacl, counts, c.sizeof(counts), 2))
            self.assertEqual(counts[0], 2)
            sids = []
            for index in range(counts[0]):
                ace = c.c_void_p()
                self.assertTrue(api.GetAce(dacl, index, c.byref(ace)))
                self.assertEqual(c.c_ubyte.from_address(ace.value).value, 0)
                self.assertFalse(c.c_ubyte.from_address(ace.value + 1).value & 0x10)
                sid_text = w.LPWSTR()
                self.assertTrue(api.ConvertSidToStringSidW(ace.value + 8, c.byref(sid_text)))
                try:
                    sids.append(sid_text.value)
                finally:
                    kernel.LocalFree(c.cast(sid_text, c.c_void_p))
            self.assertIn("S-1-5-18", sids)
            self.assertEqual(sum(sid.startswith("S-1-5-21-") for sid in sids), 1)
            self.assertNotIn("S-1-1-0", sids)
            self.assertNotIn("S-1-5-32-545", sids)
        finally:
            kernel.LocalFree(descriptor)

    def test_failed_metadata_flush_preserves_existing_header(self):
        _, header = self.volume()
        before = (self.root / P.VOLUME_HEADER_NAME).read_bytes()
        header["label"] = "changed"
        with mock.patch.object(P.os, "fsync", side_effect=OSError(errno.EIO, "flush failed")):
            with self.assertRaises(OSError):
                self.fs.write_volume_header(str(self.root), header)
        self.assertEqual((self.root / P.VOLUME_HEADER_NAME).read_bytes(), before)
        self.assert_no_temp()

    def test_default_logging_does_not_write_home(self):
        self.assertIsNone(P.App.LOG_FILE)
        self.assertIsNone(P.App.DIAG_FILE)
        app = object.__new__(P.App)
        with mock.patch.object(P.VolumeFS, "write_file_bytes", side_effect=AssertionError("unexpected log write")):
            app._file_log("a sensitive filename")


if __name__ == "__main__":
    unittest.main(verbosity=2)
