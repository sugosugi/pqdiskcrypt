# pqdiskcrypt 桌面版验证脚本（可独立复现）
# 运行：进入解压后的目录，执行：  python _verify/test_pqdiskcrypt.py
# 依赖：Python ≥ 3.9 + cryptography；有 Node ≥ 20 时会额外用冻结的原 JS 实现做双向对拍。
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import pqdiskcrypt as P  # noqa: E402

VEC = json.load(open(os.path.join(HERE, "vectors.json"), encoding="utf-8"))
b64 = base64.b64decode
SMALL = {"timeCost": 1, "memKiB": 8, "parallelism": 1}
K = 64 * 1024


def det(label, n):
    import hashlib
    out = bytearray()
    k = 0
    while len(out) < n:
        out += hashlib.sha256(("%s:%d" % (label, k)).encode()).digest()
        k += 1
    return bytes(out[:n])


class TestPQCPrimitives(unittest.TestCase):
    def test_mlkem1024_against_noble(self):
        for v in VEC["mlkem1024"]:
            pk, sk = P.MLKEM1024.keygen(b64(v["seed"]))
            self.assertEqual(pk, b64(v["pk"]))
            self.assertEqual(sk, b64(v["sk"]))
            ct, ss = P.MLKEM1024.encapsulate(pk, b64(v["m"]))
            self.assertEqual((ct, ss), (b64(v["ct"]), b64(v["ss"])))
            self.assertEqual(P.MLKEM1024.decapsulate(ct, sk), b64(v["ss_decaps"]))
            self.assertEqual(P.MLKEM1024.decapsulate(b64(v["ct_bad"]), sk), b64(v["ss_bad"]))

    def test_mlkem1024_random_and_rejects(self):
        pk, sk = P.MLKEM1024.keygen()
        ct, ss = P.MLKEM1024.encapsulate(pk)
        self.assertEqual(P.MLKEM1024.decapsulate(ct, sk), ss)
        bad = bytearray(pk)
        bad[0:2] = b"\xff\xff"
        with self.assertRaises(P.PQError):
            P.MLKEM1024.encapsulate(bytes(bad))
        badsk = bytearray(sk)
        badsk[-40] ^= 1
        with self.assertRaises(P.PQError):
            P.MLKEM1024.decapsulate(ct, bytes(badsk))

    def test_mldsa87_against_noble(self):
        for v in VEC["mldsa87"]:
            pk, sk = P.MLDSA87.keygen(b64(v["seed"]))
            self.assertEqual((pk, sk), (b64(v["pk"]), b64(v["sk"])))
            self.assertEqual(P.MLDSA87.get_public_key(sk), pk)
            for s in v["sigs"]:
                m = b64(s["msg"])
                self.assertEqual(P.MLDSA87.sign(m, sk, deterministic=True), b64(s["sig_det"]))
                self.assertTrue(P.MLDSA87.verify(b64(s["sig_hedged"]), m, pk))
                bad = bytearray(b64(s["sig_det"]))
                bad[70] ^= 1
                self.assertFalse(P.MLDSA87.verify(bytes(bad), m, pk))
                self.assertFalse(P.MLDSA87.verify(b64(s["sig_det"]), m + b"x", pk))
            m1 = b64(v["sigs"][1]["msg"])
            self.assertEqual(P.MLDSA87.sign(m1, sk, ctx=v["ctx"].encode(), deterministic=True), b64(v["sig_ctx"]))
            self.assertTrue(P.MLDSA87.verify(b64(v["sig_ctx"]), m1, pk, ctx=v["ctx"].encode()))
            self.assertFalse(P.MLDSA87.verify(b64(v["sig_ctx"]), m1, pk))

    def test_mldsa87_hint_and_length_rejects(self):
        pk, sk = P.MLDSA87.keygen()
        sig = P.MLDSA87.sign(b"m", sk)
        self.assertTrue(P.MLDSA87.verify(sig, b"m", pk))
        self.assertFalse(P.MLDSA87.verify(sig[:-1], b"m", pk))
        bad = bytearray(sig)
        bad[-1] = 200  # hint index count > omega
        self.assertFalse(P.MLDSA87.verify(bytes(bad), b"m", pk))

    def test_argon2id_against_hash_wasm(self):
        for v in VEC["argon2id"]:
            self.assertEqual(P.argon2id_raw(v["password"].encode(), b64(v["salt"]), v["t"], v["m"], v["p"], 32), b64(v["out"]))


class TestCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pq = P.PQCrypto()
        cls.pl = {k: b64(v) for k, v in VEC["payloads"].items()}
        cls.kA, cls.kB = VEC["keypairA"], VEC["keypairB"]

    def test_selftest(self):
        self.assertTrue(self.pq.self_test(SMALL))

    def test_js_artifacts_decrypt(self):
        pq, pl, kA, kB = self.pq, self.pl, self.kA, self.kB
        self.assertEqual(pq.fingerprint(b64(kA["pub"]["x25519_pub"]), b64(kA["pub"]["mlkem_pub"])), kA["fingerprint"])
        self.assertEqual(pq.signer_fingerprint(b64(kA["pub"]["mldsa_pub"])), kA["signerFingerprint"])
        for k, ct in VEC["hybrid"].items():
            r = pq.decrypt(b64(ct), key_obj=kA["key"])
            self.assertEqual(r["plaintext"], pl[k])
            self.assertFalse(r["signed"])
        for k, ct in VEC["hybrid_signed"].items():
            r = pq.decrypt(b64(ct), key_obj=kA["key"])
            self.assertEqual((r["plaintext"], r["signed"], r["signerFingerprint"]), (pl[k], True, kB["signerFingerprint"]))
        for k, ct in VEC["password"]["files"].items():
            self.assertEqual(pq.decrypt(b64(ct), password=VEC["password"]["password"])["plaintext"], pl[k])
        with self.assertRaises(P.PQError) as cm:
            pq.decrypt(b64(VEC["password"]["files"]["p5"]), password="wrong")
        self.assertEqual(cm.exception.code, "BAD_PASSWORD")
        with self.assertRaises(P.PQError) as cm:
            pq.decrypt(b64(VEC["hybrid"]["p5"]), key_obj=kB["key"])
        self.assertEqual(cm.exception.code, "KEY_MISMATCH")
        self.assertEqual(pq.unwrap_secret_key(VEC["wrapped_key"]["container"], VEC["wrapped_key"]["passphrase"]), kA["key"])

    def test_js_volume_decrypt(self):
        pq, pl, kA, kB = self.pq, self.pl, self.kA, self.kB
        vol = VEC["volume"]
        hdr = vol["header"]
        vid, vmk = b64(hdr["volume_id"]), b64(vol["vmk"])
        for kw, idx in (({"password": vol["password"]}, 0), ({"key_obj": kA["key"]}, 1), ({"password": vol["password2"]}, 2)):
            r = pq.unlock_volume(hdr, **kw)
            self.assertEqual((bytes(r["vmk"]), r["slotIndex"]), (vmk, idx))
        with self.assertRaises(P.PQError):
            pq.unlock_volume(hdr, key_obj=kB["key"])
        with self.assertRaises(P.PQError):
            pq.unlock_volume(hdr, password="nope")
        for k, ct in vol["files"].items():
            self.assertEqual(pq.decrypt_volume_bytes(vmk, vid, b64(ct)), pl[k])
        self.assertEqual(json.loads(pq.decrypt_volume_bytes(vmk, vid, b64(vol["manifest_enc"]))), vol["manifest_plain"])

    def test_round_trips_and_rejects(self):
        pq, pl, kA, kB = self.pq, self.pl, self.kA, self.kB
        vol = pq.new_volume(hide_names=False)
        vmk, vid = vol["vmk"], vol["volumeId"]
        for k, p in pl.items():
            self.assertEqual(pq.decrypt(pq.encrypt_hybrid(kA["pub"], p), key_obj=kA["key"])["plaintext"], p)
            self.assertEqual(pq.decrypt(pq.encrypt_password("pw ✓", p, SMALL), password="pw ✓")["plaintext"], p)
            r = pq.decrypt(pq.encrypt_hybrid_signed(kA["pub"], p, kB["key"]), key_obj=kA["key"])
            self.assertEqual((r["plaintext"], r["signed"]), (p, True))
            ct = pq.encrypt_volume_bytes(vmk, vid, p)
            self.assertEqual(len(ct), pq.volume_ciphertext_length(len(p)))
            self.assertEqual(pq.decrypt_volume_bytes(vmk, vid, ct), p)
        ct = pq.encrypt_volume_bytes(vmk, vid, pl["p2b"])
        for mutate in (lambda x: x[:-1], lambda x: x + ct[-20:], lambda x: x[:80] + bytes([x[80] ^ 1]) + x[81:], lambda x: x[:20] + bytes([x[20] ^ 1]) + x[21:]):
            with self.assertRaises(P.PQError):
                pq.decrypt_volume_bytes(vmk, vid, mutate(ct))
        # block reordering: swap first two blocks
        hdr = P.VOLUME_HDR_LEN
        l1 = int.from_bytes(ct[hdr:hdr + 4], "big")
        b1 = ct[hdr:hdr + 4 + l1]
        l2 = int.from_bytes(ct[hdr + 4 + l1:hdr + 8 + l1], "big")
        b2 = ct[hdr + 4 + l1:hdr + 8 + l1 + l2]
        with self.assertRaises(P.PQError):
            pq.decrypt_volume_bytes(vmk, vid, ct[:hdr] + b2 + b1 + ct[hdr + 8 + l1 + l2:])
        other = pq.new_volume()
        with self.assertRaises(P.PQError) as cm:
            pq.decrypt_volume_bytes(other["vmk"], other["volumeId"], ct)
        self.assertEqual(cm.exception.code, "FOREIGN_VOLUME")
        with self.assertRaises(P.PQError) as cm:
            pq.decrypt_volume_bytes(other["vmk"], vid, ct)
        self.assertEqual(cm.exception.code, "KEY_MISMATCH")
        single = pq.encrypt_password("x", b"y", SMALL)
        with self.assertRaises(P.PQError) as cm:
            pq.decrypt_volume_bytes(vmk, vid, single)
        self.assertEqual(cm.exception.code, "NOT_VOLUME_FILE")
        with self.assertRaises(P.PQError):
            pq.decrypt(ct, password="x")  # legacy single-file path rejects mode 4

    def test_slots_and_header_validation(self):
        pq = self.pq
        vol = pq.new_volume(hide_names=True, label="x" * 300)
        self.assertEqual(len(vol["header"]["label"]), 200)
        pq.add_password_slot(vol["header"], vol["vmk"], "a", SMALL)
        pq.add_pubkey_slot(vol["header"], vol["vmk"], self.kA["pub"])
        h = json.loads(json.dumps(vol["header"]))
        pq.validate_volume_header(h)
        with self.assertRaises(P.PQError):
            pq.remove_slot(h, 5)
        pq.remove_slot(h, 0)
        with self.assertRaises(P.PQError):
            pq.remove_slot(h, 0)
        bad = json.loads(json.dumps(vol["header"]))
        bad["slots"][0]["kdf_params"]["m"] = 4 * 1024 * 1024 * 1024
        with self.assertRaises(P.PQError):
            pq.validate_volume_header(bad)
        bad = json.loads(json.dumps(vol["header"]))
        bad["slots"][0]["type"] = "future"
        with self.assertRaises(P.PQError):
            pq.validate_volume_header(bad)
        bad = json.loads(json.dumps(vol["header"]))
        bad["volume_id"] = P.b64encode(os.urandom(16))
        with self.assertRaises(P.PQError):
            pq.unlock_volume(bad, password="a")  # AAD binds the volume id
        bad = json.loads(json.dumps(vol["header"]))
        bad["slots"][0]["wrapped_key"] = P.b64encode(os.urandom(48))
        with self.assertRaises(P.PQError):
            pq.unlock_volume(bad, password="a")

    def test_password_hygiene(self):
        self.assertTrue(P.password_strength("123456")["blocked"])
        self.assertTrue(P.password_strength("short")["blocked"])
        self.assertTrue(P.password_strength("P@ssw0rd!!")["blocked"])
        self.assertFalse(P.password_strength("correct horse battery staple 2026")["blocked"])
        self.assertGreaterEqual(P.password_strength("correct horse battery staple 2026")["score"], 3)
        self.assertEqual(P.normalize_password("e\u0301"), "\u00e9")
        self.assertTrue(P.password_hints(" pad ")[0].startswith("口令首尾"))
        self.assertIsNone(P.kdf_cost_exceeds_default(4, 256 * 1024, 4))
        self.assertIsNotNone(P.kdf_cost_exceeds_default(4, 1024 * 1024, 4))

    def test_strict_base64(self):
        for bad in ["QR==", "A", "QUJD!", "QUJ", "QQ=="[:-1] + "=" * 3]:
            with self.assertRaises(P.PQError):
                P.b64decode(bad)
        self.assertEqual(P.b64decode("QUI="), b"AB")
        self.assertEqual(P.b64decode("QUI"), b"AB")
        self.assertEqual(P.b64decode("QUJD\n"), b"ABC")

    def test_streaming_reader_semantics(self):
        r = P.ByteReader(P._MemReader(b"abcdef"))
        self.assertEqual(r.read_exact(4), b"abcd")
        self.assertFalse(r.at_eof())
        with self.assertRaises(P.PQError):
            r.read_exact(4)
        r = P.ByteReader(P._MemReader(b"abcd"))
        self.assertEqual(r.read_exact(4), b"abcd")
        self.assertTrue(r.at_eof())
        self.assertIsNone(r.read_exact(4))


def seed_tree(root):
    files = {
        "readme.txt": b"hello disk", "empty.bin": b"", "exact64k.bin": os.urandom(K), "64k+1.bin": os.urandom(K + 1),
        "big 3.5MB.bin": os.urandom(K * 56 + 12345), ".dotfile": b"dot",
        "照片/家庭 2026/IMG_0001.jpg": os.urandom(300000), "照片/家庭 2026/IMG_0002.jpg": os.urandom(1),
        "照片/notes.md": b"# notes", "docs/a/b/c/deep.txt": b"deep", "docs/合同.pdf": os.urandom(70000),
        "old.pqfc": b"not really a container, just a name",
    }
    for p, b in files.items():
        fp = os.path.join(root, p)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "wb") as f:
            f.write(b)
    os.makedirs(os.path.join(root, "emptydir"))
    os.makedirs(os.path.join(root, "System Volume Information"))
    with open(os.path.join(root, "System Volume Information", "IndexerVolumeGuid"), "wb") as f:
        f.write(b"guid")
    return files


def snapshot(root):
    out = {}
    for d, _dirs, fs in os.walk(root):
        for f in fs:
            if f == P.LOCK_NAME:
                continue
            p = os.path.join(d, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root).replace(os.sep, "/")] = fh.read()
    return out


class TestVolumeEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pq = P.PQCrypto()
        cls.vfs = P.VolumeFS(cls.pq)

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pqdisk-test-")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _vol(self, hide=False, pw="pw"):
        vol = self.pq.new_volume(hide_names=hide, label="测试卷")
        self.pq.add_password_slot(vol["header"], vol["vmk"], pw, SMALL)
        self.vfs.write_volume_header(self.root, vol["header"])
        return {"vmk": vol["vmk"], "volumeId": vol["volumeId"], "hideNames": hide}, vol["header"]

    def test_full_round_trip_both_modes(self):
        for hide in (False, True):
            self.tearDown()
            self.setUp()
            files = seed_tree(self.root)
            ctx, header = self._vol(hide)
            st = self.vfs.scan_tree(self.root, volume_id=ctx["volumeId"])
            self.assertEqual((st["files"], st["skippedDirs"]), (len(files), ["System Volume Information"]))
            self.assertEqual(st["largest"], K * 56 + 12345)
            mt = os.stat(os.path.join(self.root, "readme.txt")).st_mtime_ns
            res = self.vfs.encrypt_tree(self.root, ctx, verify=True)
            self.assertEqual((res["files"], res["errors"], res["cancelled"]), (len(files), [], False))
            snap = snapshot(self.root)
            self.assertFalse(any(p in snap for p in files))
            self.assertTrue(all(k.endswith(".pqfc") or k.endswith(".pqdir") or k in (".pqvolume", "System Volume Information/IndexerVolumeGuid") for k in snap))
            if hide:
                self.assertFalse(any(k.endswith("readme.txt.pqfc") for k in snap))
                self.assertTrue(all(len(os.path.basename(k)) == 21 for k in snap if k.endswith(".pqfc")))
            else:
                self.assertEqual(os.stat(os.path.join(self.root, "readme.txt.pqfc")).st_mtime_ns, mt)
            st2 = self.vfs.scan_tree(self.root, volume_id=ctx["volumeId"])
            self.assertEqual((st2["files"], st2["encrypted"]), (0, len(files)))
            res2 = self.vfs.encrypt_tree(self.root, ctx)
            self.assertEqual((res2["files"], res2["skipped"]), (0, len(files)))
            with open(os.path.join(self.root, "照片", "late.txt") if not hide else os.path.join(self.root, "late.txt"), "wb") as f:
                f.write(b"late")
            files["照片/late.txt" if not hide else "late.txt"] = b"late"
            self.assertEqual(self.vfs.encrypt_tree(self.root, ctx)["files"], 1)
            dres = self.vfs.decrypt_tree(self.root, ctx)
            self.assertEqual((dres["files"], dres["errors"], dres["warnings"], dres["headerRemoved"]), (len(files), [], [], False))
            snap = snapshot(self.root)
            self.assertTrue(all(snap.get(p) == b for p, b in files.items()))
            self.assertFalse(any(k.endswith(".pqfc") or k.endswith(".pqdir") for k in snap if k != "old.pqfc"))
            self.assertTrue(os.path.isdir(os.path.join(self.root, "emptydir")))
            if not hide:
                self.assertEqual(os.stat(os.path.join(self.root, "readme.txt")).st_mtime_ns, mt)

    def test_keep_originals_dry_run(self):
        files = seed_tree(self.root)
        ctx, _ = self._vol()
        res = self.vfs.encrypt_tree(self.root, ctx, keep_originals=True)
        self.assertEqual(res["files"], len(files))
        snap = snapshot(self.root)
        self.assertTrue(all(p in snap for p in files) and "readme.txt.pqfc" in snap)
        res2 = self.vfs.encrypt_tree(self.root, ctx, keep_originals=True)
        self.assertEqual((res2["files"], res2["reused"], res2["errors"]), (len(files), len(files), []))
        self.assertEqual(snapshot(self.root), snap)  # Existing ciphertext is never silently replaced.
        dres = self.vfs.decrypt_tree(self.root, ctx, keep_originals=True)
        self.assertEqual((dres["files"], dres["skipped"]), (0, len(files) + 1))  # never overwrite existing plaintext (+1: old.pqfc is not a container)

    def test_cancel_leaves_no_half_written_files(self):
        files = seed_tree(self.root)
        ctx, _ = self._vol()
        cancel = threading.Event()
        n = [0]

        def ev(e):
            if e["type"] == "file-done":
                n[0] += 1
                if n[0] == 3:
                    cancel.set()
        res = self.vfs.encrypt_tree(self.root, ctx, on_event=ev, cancel=cancel)
        self.assertTrue(res["cancelled"])
        self.assertEqual(res["files"], 3)
        snap = snapshot(self.root)
        enc = sum(1 for k in snap if k.endswith(".pqfc") and k != "old.pqfc")
        plain = sum(1 for k in snap if k in files)
        self.assertEqual(enc + plain, len(files))
        self.assertFalse(any(P.TMP_PREFIX in k for k in snap))
        self.assertTrue(os.path.exists(os.path.join(self.root, ".pqvolume")))
        res = self.vfs.encrypt_tree(self.root, ctx)
        self.assertEqual((res["files"] + res["skipped"], res["errors"]), (len(files), []))

    def test_verify_catches_corrupted_output(self):
        seed_tree(self.root)
        ctx, _ = self._vol()
        orig = self.pq.encrypt_volume_stream

        def corrupt(vmk, vid, readable, sink, cancel=None, on_progress=None):
            r = orig(vmk, vid, readable, sink, cancel, on_progress)
            sink.write(b"\x00\x00\x00\x20" + b"\x00" * 32)
            return r
        self.pq.encrypt_volume_stream = corrupt
        try:
            res = self.vfs.encrypt_tree(self.root, ctx, verify=True)
        finally:
            self.pq.encrypt_volume_stream = orig
        self.assertEqual((res["files"], len(res["errors"])), (0, 12))
        snap = snapshot(self.root)
        self.assertTrue("readme.txt" in snap and "docs/合同.pdf" in snap)
        self.assertFalse(any(k.endswith(".pqfc") and k != "old.pqfc" for k in snap) or any(P.TMP_PREFIX in k for k in snap))

    def test_disk_full_simulation(self):
        seed_tree(self.root)
        ctx, _ = self._vol()
        with mock.patch.object(P.BufferedSink, "flush", side_effect=OSError(28, "No space left on device")):
            res = self.vfs.encrypt_tree(self.root, ctx)
        self.assertEqual(res["files"], 0)
        self.assertEqual(len(res["errors"]), 12)
        snap = snapshot(self.root)
        self.assertIn("readme.txt", snap)
        self.assertFalse(any(P.TMP_PREFIX in k for k in snap))

    def test_foreign_files_name_conflicts_and_manifest_loss(self):
        files = seed_tree(self.root)
        other = self.pq.new_volume()
        with open(os.path.join(self.root, "foreign.pqfc"), "wb") as f:
            f.write(self.pq.encrypt_volume_bytes(other["vmk"], other["volumeId"], b"x"))
        with open(os.path.join(self.root, "single.pqfc"), "wb") as f:
            f.write(self.pq.encrypt_password("p", b"y", SMALL))
        os.makedirs(os.path.join(self.root, "clash.txt.pqfc"))
        ctx, header = self._vol(hide=True)
        res = self.vfs.encrypt_tree(self.root, ctx)
        self.assertEqual((res["foreign"], res["files"], res["errors"]), (2, len(files), []))
        self.assertTrue(os.path.exists(os.path.join(self.root, "foreign.pqfc")) and os.path.exists(os.path.join(self.root, "single.pqfc")))
        dirs = [d for d in os.listdir(self.root) if os.path.isdir(os.path.join(self.root, d)) and len(d) == 16 and any(n.endswith(".pqfc") for n in os.listdir(os.path.join(self.root, d)))]
        os.remove(os.path.join(self.root, dirs[0], ".pqdir"))
        dres = self.vfs.decrypt_tree(self.root, ctx)
        self.assertEqual((dres["files"], dres["skipped"], len(dres["warnings"]), dres["headerRemoved"]), (len(files), 2, 1, False))
        self.assertTrue(os.path.exists(os.path.join(self.root, ".pqvolume")))

    def test_normal_mode_name_conflict_and_foreign(self):
        files = seed_tree(self.root)
        ctx, _ = self._vol()
        other = self.pq.new_volume()
        foreign = self.pq.encrypt_volume_bytes(other["vmk"], other["volumeId"], b"someone else's file")
        with open(os.path.join(self.root, "readme.txt.pqfc"), "wb") as f:
            f.write(foreign)
        res = self.vfs.encrypt_tree(self.root, ctx)
        self.assertEqual((len(res["errors"]), res["foreign"], res["files"]), (1, 1, len(files) - 1))
        self.assertIn("未覆盖", res["errors"][0]["message"])
        self.assertTrue(os.path.exists(os.path.join(self.root, "readme.txt")))
        with open(os.path.join(self.root, "readme.txt.pqfc"), "rb") as f:
            self.assertEqual(f.read(), foreign)
        # a plain file merely named *.pqfc is ordinary data: encrypted first so x.pqfc never collides with x
        self.assertTrue(os.path.exists(os.path.join(self.root, "old.pqfc.pqfc")))

    def test_leftover_temp_files_are_preserved(self):
        seed_tree(self.root)
        ctx, _ = self._vol()
        with open(os.path.join(self.root, P.TMP_PREFIX + "deadbeef"), "wb") as f:
            f.write(b"partial")
        st = self.vfs.scan_tree(self.root, volume_id=ctx["volumeId"])
        self.assertEqual(st["tmpLeft"], 1)
        self.vfs.encrypt_tree(self.root, ctx)
        self.assertEqual(snapshot(self.root)[P.TMP_PREFIX + "deadbeef"], b"partial")

    @unittest.skipIf(not hasattr(os, "symlink") or os.name == "nt", "symlink test on POSIX only")
    def test_symlinks_are_skipped(self):
        files = seed_tree(self.root)
        outside = tempfile.mkdtemp()
        with open(os.path.join(outside, "secret.txt"), "wb") as f:
            f.write(b"outside")
        os.symlink(outside, os.path.join(self.root, "linkdir"))
        os.symlink(os.path.join(outside, "secret.txt"), os.path.join(self.root, "linkfile"))
        ctx, _ = self._vol()
        st = self.vfs.scan_tree(self.root, volume_id=ctx["volumeId"])
        self.assertEqual((st["files"], st["links"]), (len(files), 2))
        res = self.vfs.encrypt_tree(self.root, ctx)
        self.assertEqual((res["files"], res["errors"]), (len(files), []))
        with open(os.path.join(outside, "secret.txt"), "rb") as f:
            self.assertEqual(f.read(), b"outside")
        shutil.rmtree(outside)

    def test_dry_run_then_decrypt_keeps_manifests_and_header(self):
        # Regression: skipped ciphertexts (target already exists) used to count as "clean", so the
        # header and every .pqdir were deleted while the files stayed encrypted.
        files = seed_tree(self.root)
        ctx, _ = self._vol(hide=True)
        self.vfs.encrypt_tree(self.root, ctx, keep_originals=True)
        dres = self.vfs.decrypt_tree(self.root, ctx)
        self.assertEqual((dres["files"], dres["kept"], dres["headerRemoved"], dres["errors"]), (0, len(files), False, []))
        self.assertTrue(os.path.exists(os.path.join(self.root, ".pqvolume")))
        self.assertGreaterEqual(sum(1 for k in snapshot(self.root) if k.endswith(".pqdir")), 4)
        for p in files:
            os.remove(os.path.join(self.root, p))
        dres = self.vfs.decrypt_tree(self.root, ctx)
        self.assertEqual((dres["files"], dres["warnings"], dres["headerRemoved"]), (len(files), [], False))
        self.assertTrue(all(snapshot(self.root).get(p) == b for p, b in files.items()))

    def test_file_dir_name_conflict_across_runs(self):
        files = seed_tree(self.root)
        ctx, _ = self._vol(hide=True)
        self.vfs.encrypt_tree(self.root, ctx)
        with open(os.path.join(self.root, "docs"), "wb") as f:  # a file named like a migrated directory
            f.write(b"i am a file now")
        with open(os.path.join(self.root, "readme.txt"), "wb") as f:  # and a new file with an old file's name
            f.write(b"second readme")
        original = snapshot(self.root)
        result = self.vfs.encrypt_tree(self.root, ctx)
        self.assertTrue(any(e["path"] == "readme.txt" for e in result["errors"]))
        for path, content in original.items():
            if path.endswith(".pqfc"):
                self.assertEqual(snapshot(self.root)[path], content)
        os.remove(os.path.join(self.root, "readme.txt"))
        dres = self.vfs.decrypt_tree(self.root, ctx)
        self.assertEqual((dres["errors"], dres["kept"], len(dres["warnings"]), dres["headerRemoved"]), ([], 0, 1, False))
        snap = snapshot(self.root)
        self.assertEqual(snap["docs"], b"i am a file now")
        alt = [k for k in snap if k.startswith("docs (目录")]
        self.assertTrue(alt and any(k.endswith("/合同.pdf") for k in alt))
        self.assertEqual(snap["readme.txt"], files["readme.txt"])
        self.assertFalse(any(k.endswith(".pqfc") and k != "old.pqfc" for k in snap))
        self.assertTrue(os.path.exists(os.path.join(self.root, ".pqvolume")))

    def test_scan_reports_foreign_volumes_damaged_and_unreadable(self):
        seed_tree(self.root)
        ctx, header = self._vol()
        v1 = self.pq.new_volume()
        v2 = self.pq.new_volume()
        for name, vol in (("x1.pqfc", v1), ("x2.pqfc", v1), ("y.pqfc", v2)):
            with open(os.path.join(self.root, name), "wb") as f:
                f.write(self.pq.encrypt_volume_bytes(vol["vmk"], vol["volumeId"], b"z"))
        with open(os.path.join(self.root, "single.pqfc"), "wb") as f:
            f.write(self.pq.encrypt_password("p", b"q", SMALL))
        with open(os.path.join(self.root, "cut.pqfc"), "wb") as f:
            f.write(self.pq.encrypt_volume_bytes(ctx["vmk"], ctx["volumeId"], b"z")[:40])
        self.assertEqual(self.vfs.encrypt_tree(self.root, ctx)["errors"], [])
        st = self.vfs.scan_tree(self.root, volume_id=ctx["volumeId"])
        self.assertEqual(st["encrypted"], 12)
        self.assertEqual(st["foreignVolumes"], {P.hexs(v1["volumeId"])[:12]: 2, P.hexs(v2["volumeId"])[:12]: 1})
        self.assertEqual((st["singleMode"], st["damaged"], st["notContainer"]), (1, ["cut.pqfc"], 0))
        # a foreign volume decrypted with its own header must leave the directory's header alone
        ctx1 = {"vmk": v1["vmk"], "volumeId": v1["volumeId"], "hideNames": False}
        res = self.vfs.decrypt_tree(self.root, ctx1, remove_header=False)
        self.assertEqual((res["files"], res["headerRemoved"]), (2, False))
        self.assertTrue(os.path.exists(os.path.join(self.root, ".pqvolume")) and os.path.exists(os.path.join(self.root, "x1")))
        status, h, err = self.vfs.header_status(self.root)
        self.assertEqual((status, h["volume_id"]), ("ok", header["volume_id"]))
        with open(os.path.join(self.root, ".pqvolume"), "wb") as f:
            f.write(b"{ broken")
        self.assertEqual(self.vfs.header_status(self.root)[0], "invalid")
        if os.name != "nt" and os.geteuid() != 0:
            os.chmod(os.path.join(self.root, "y.pqfc"), 0)
            st = self.vfs.scan_tree(self.root, volume_id=ctx["volumeId"])
            self.assertEqual(len(st["unreadable"]), 1)
            os.chmod(os.path.join(self.root, "y.pqfc"), 0o644)

    def test_diagnose_tree_classifies_by_content(self):
        files = seed_tree(self.root)
        ctx, header = self._vol()
        v1 = self.pq.new_volume()
        with open(os.path.join(self.root, "other.pqfc"), "wb") as f:
            f.write(self.pq.encrypt_volume_bytes(v1["vmk"], v1["volumeId"], b"z"))
        with open(os.path.join(self.root, "single.pqfc"), "wb") as f:
            f.write(self.pq.encrypt_password("p", b"q", SMALL))
        self.vfs.encrypt_tree(self.root, ctx)
        os.rename(os.path.join(self.root, "readme.txt.pqfc"), os.path.join(self.root, "readme.bak"))
        d = self.vfs.diagnose_tree(self.root, header)
        c = d["counts"]
        self.assertEqual(c["本卷密文"], len(files) - 1)
        self.assertEqual(c["本卷密文但扩展名不是 .pqfc"], 1)
        self.assertEqual(c["其它卷密文"], 1)
        self.assertEqual(c["单文件模式密文（v2 模式 2）"], 1)
        self.assertEqual(c["系统目录（跳过）"], 1)
        self.assertEqual(d["misnamed"], ["readme.bak"])
        self.assertTrue(any("卷 ID " + P.hexs(v1["volumeId"])[:12] in ln for ln in d["lines"]))
        r = self.vfs.fix_extensions(self.root, d["misnamed"])
        self.assertEqual((r["renamed"], r["errors"]), (["readme.bak"], []))
        st = self.vfs.scan_tree(self.root, volume_id=ctx["volumeId"])
        self.assertEqual(st["encrypted"], len(files))
        dres = self.vfs.decrypt_tree(self.root, ctx)
        self.assertEqual(dres["errors"], [])
        with open(os.path.join(self.root, "readme.bak"), "rb") as f:
            self.assertEqual(f.read(), b"hello disk")

    def test_header_backup_json_matches_js_style(self):
        ctx, header = self._vol()
        text = P.header_json(header)
        self.assertEqual(json.loads(text), header)
        self.assertTrue(text.startswith('{\n  "format": "pqdisk-volume-v1",'))


class TestNameConversion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pq = P.PQCrypto()
        cls.vfs = P.VolumeFS(cls.pq)

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pqdisk-conv-")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _vol(self, hide):
        vol = self.pq.new_volume(hide_names=hide)
        self.pq.add_password_slot(vol["header"], vol["vmk"], "pw", SMALL)
        self.vfs.write_volume_header(self.root, vol["header"])
        return {"vmk": vol["vmk"], "volumeId": vol["volumeId"], "hideNames": hide}, self.vfs.read_volume_header(self.root)

    def test_toggle_chain_both_directions(self):
        for start_hidden in (False, True):
            self.tearDown()
            self.setUp()
            files = seed_tree(self.root)
            ctx, hdr = self._vol(start_hidden)
            other = self.pq.new_volume()
            with open(os.path.join(self.root, "foreign.pqfc"), "wb") as f:
                f.write(self.pq.encrypt_volume_bytes(other["vmk"], other["volumeId"], b"x"))
            self.assertEqual(self.vfs.encrypt_tree(self.root, ctx)["errors"], [])
            with open(os.path.join(self.root, "late.txt"), "wb") as f:
                f.write(b"late")
            before = sorted(v for k, v in snapshot(self.root).items() if k.endswith(".pqfc"))
            for _ in range(3):
                target = not hdr["hide_names"]
                res = self.vfs.convert_names(self.root, hdr, ctx, target)
                self.assertTrue(res["completed"], res)
                hdr = self.vfs.read_volume_header(self.root)
                self.assertEqual(hdr["hide_names"], target)
                snap = snapshot(self.root)
                if target:
                    self.assertTrue(all(len(os.path.basename(k)) == 21 for k in snap if k.endswith(".pqfc") and k != "foreign.pqfc"))
                    self.assertTrue(any(k.endswith(".pqdir") for k in snap))
                else:
                    self.assertIn("照片/家庭 2026/IMG_0001.jpg.pqfc", snap)
                    self.assertFalse(any(k.endswith(".pqdir") for k in snap))
                self.assertIn("foreign.pqfc", snap)
                self.assertIn("late.txt", snap)
                self.assertEqual(sorted(v for k, v in snap.items() if k.endswith(".pqfc")), before)
                ctx["hideNames"] = target
            with self.subTest(start_hidden=start_hidden):
                dres = self.vfs.decrypt_tree(self.root, ctx)
                self.assertEqual((dres["errors"], dres["warnings"], dres["headerRemoved"]), ([], [], False))
                self.assertTrue(all(snapshot(self.root).get(p) == b for p, b in files.items()))

    def test_unhide_conflict_aborts_without_changes(self):
        seed_tree(self.root)
        ctx, hdr = self._vol(True)
        self.vfs.encrypt_tree(self.root, ctx)
        with open(os.path.join(self.root, "readme.txt.pqfc"), "wb") as f:
            f.write(b"blocker")
        before = snapshot(self.root)
        with self.assertRaises(P.PQError) as cm:
            self.vfs.convert_names(self.root, hdr, ctx, False)
        self.assertIn("名字冲突", str(cm.exception))
        self.assertEqual(snapshot(self.root), before)
        self.assertTrue(self.vfs.read_volume_header(self.root)["hide_names"])

    def test_same_state_rejected(self):
        ctx, hdr = self._vol(False)
        with self.assertRaises(P.PQError):
            self.vfs.convert_names(self.root, hdr, ctx, False)


class TestCrossCheckWithNode(unittest.TestCase):
    def test_js_reads_python_artifacts(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node 不可用，跳过 JS 读 Python 产物的对拍")
        pq = P.PQCrypto()
        pl = {k: b64(v) for k, v in VEC["payloads"].items()}
        e = P.b64encode
        kp = pq.generate_keypair()
        signer = pq.generate_keypair()
        A = {"payloads": VEC["payloads"], "keypair": kp, "signer": signer, "mlkem": [], "mldsa": []}
        for _ in range(2):
            pk, sk = P.MLKEM1024.keygen()
            ct, ss = P.MLKEM1024.encapsulate(pk)
            A["mlkem"].append({"pk": e(pk), "sk": e(sk), "ct": e(ct), "ss": e(ss)})
            dpk, dsk = P.MLDSA87.keygen()
            m = os.urandom(50)
            sig = P.MLDSA87.sign(m, dsk)
            bad = bytearray(sig)
            bad[5] ^= 1
            A["mldsa"].append({"pk": e(dpk), "sk": e(dsk), "msg": e(m), "sig": e(sig), "sig_bad": e(bytes(bad))})
        A["hybrid"] = {k: e(pq.encrypt_hybrid(kp["pub"], p)) for k, p in pl.items()}
        A["hybrid_signed"] = {k: e(pq.encrypt_hybrid_signed(kp["pub"], p, signer["key"])) for k, p in pl.items()}
        A["password"] = {"password": "py-口令 ✓", "files": {k: e(pq.encrypt_password("py-口令 ✓", p, SMALL)) for k, p in pl.items()}}
        A["wrapped_key"] = {"passphrase": "wrap-me", "container": pq.wrap_secret_key(kp["key"], "wrap-me", SMALL)}
        vol = pq.new_volume(hide_names=True, label="Python 卷")
        pq.add_password_slot(vol["header"], vol["vmk"], "vol-口令", SMALL)
        pq.add_pubkey_slot(vol["header"], vol["vmk"], kp["pub"])
        manifest = {"v": 1, "dir": "0123456789abcdef", "entries": {"00000000000000aa": {"n": "照片.jpg", "t": "f"}}}
        A["volume"] = {"header": vol["header"], "vmk": e(vol["vmk"]), "password": "vol-口令",
                       "files": {k: e(pq.encrypt_volume_bytes(vol["vmk"], vol["volumeId"], p)) for k, p in pl.items()},
                       "manifest_plain": manifest,
                       "manifest_enc": e(pq.encrypt_volume_bytes(vol["vmk"], vol["volumeId"], json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode()))}
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "artifacts.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(A, f, ensure_ascii=False)
        try:
            r = subprocess.run([node, os.path.join(HERE, "crosscheck.mjs"), path], capture_output=True, text=True, encoding="utf-8", timeout=300)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        print(r.stdout)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_js_engine_on_disk_then_python_decrypts(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node 不可用")
        tmp = tempfile.mkdtemp(prefix="pqdisk-js-")
        try:
            files = seed_tree(tmp)
            r = subprocess.run([node, os.path.join(HERE, "js-encrypt-dir.mjs"), tmp, "js-口令 ✓"], capture_output=True, text=True, encoding="utf-8", timeout=600)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            pq = P.PQCrypto()
            vfs = P.VolumeFS(pq)
            header = vfs.read_volume_header(tmp)
            self.assertTrue(header["hide_names"])
            snap = snapshot(tmp)
            self.assertFalse(any(p in snap for p in files))
            u = pq.unlock_volume(header, password="js-口令 ✓")
            st = vfs.scan_tree(tmp, volume_id=u["volumeId"])
            self.assertEqual(st["encrypted"], len(files))
            res = vfs.decrypt_tree(tmp, {"vmk": u["vmk"], "volumeId": u["volumeId"], "hideNames": True})
            self.assertEqual((res["files"], res["errors"], res["warnings"], res["headerRemoved"]), (len(files), [], [], False))
            snap = snapshot(tmp)
            self.assertTrue(all(snap.get(p) == b for p, b in files.items()))
            print("  ✓ 浏览器版引擎（JS，隐藏文件名）加密的目录树由 Python 版完整还原")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestUISmoke(unittest.TestCase):
    def test_ui_smoke(self):
        env = dict(os.environ, PYTHONUTF8="1")
        r = subprocess.run([sys.executable, os.path.join(HERE, "ui_smoke.py")], capture_output=True, text=True, encoding="utf-8", env=env, timeout=180)
        print(r.stdout[-3000:])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    print("pqdiskcrypt 桌面版验证（Python %s；Argon2id 后端：%s）" % (sys.version.split()[0], P.argon2_backend_name()))
    unittest.main(verbosity=2)
