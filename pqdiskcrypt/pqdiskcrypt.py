#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pqdiskcrypt · 抗量子硬盘加密工具（桌面版，单文件，不需要浏览器）

把移动硬盘 / U 盘 / 任意文件夹原地逐文件加密。卷主密钥由 Argon2id 口令和 / 或
X25519 + ML-KEM-1024 抗量子公钥保护（密钥槽，可随时增删而无需重新加密）；每个文件
独立密钥，AES-256-GCM 64 KiB 分块流式认证加密，带密钥承诺。磁盘格式与浏览器版
pqdiskcrypt（卷格式 pqdisk-volume-v1 / 文件格式 v2 卷模式）逐字节兼容。

运行：  python pqdiskcrypt.py            图形界面（tkinter，Python 自带）
        python pqdiskcrypt.py --selftest  只跑启动自检并退出
依赖：  python -m pip install -r requirements.txt
        ML-KEM-1024 与 ML-DSA-87 使用 pqcrypto / PQClean 原生后端。
        内置纯 Python 实现仅保留作测试参照，不作为运行时后备。
打包：  pip install pyinstaller && pyinstaller --onefile --windowed pqdiskcrypt.py
"""

import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import shutil
import stat
import sys
import threading
import time
import unicodedata
from contextlib import contextmanager
from functools import wraps
from datetime import datetime, timezone

APP_NAME = "pqdiskcrypt"
APP_VERSION = "5.4.4"

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.exceptions import InvalidTag
    HAVE_CRYPTOGRAPHY = True
    CRYPTOGRAPHY_IMPORT_ERROR = None
except Exception as _e:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False
    CRYPTOGRAPHY_IMPORT_ERROR = _e


class PQError(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def random_bytes(n):
    return secrets.token_bytes(n)


def bytes_equal(a, b):
    return hmac.compare_digest(bytes(a), bytes(b))


def wipe(*bufs):
    for b in bufs:
        if isinstance(b, (bytearray, memoryview)):
            try:
                for i in range(len(b)):
                    b[i] = 0
            except Exception:
                pass


def u16be(n):
    return bytes(((n >> 8) & 0xFF, n & 0xFF))


def u32be(n):
    return n.to_bytes(4, "big")


_B64_RE = re.compile(r"^[A-Za-z0-9+/]*$")
MAX_JSON_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_SINGLE_FILE_BYTES = 128 * 1024 * 1024
MAX_SLOTS = 16


def strict_json(raw, limit=MAX_JSON_BYTES):
    if len(raw) > limit:
        raise PQError("JSON exceeds the size limit", "INPUT_LIMIT")

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out

    def bad_constant(value):
        raise ValueError("non-finite JSON number")

    try:
        text = raw.decode("utf-8-sig") if isinstance(raw, bytes) else raw
        obj = json.loads(text, object_pairs_hook=pairs, parse_constant=bad_constant)
        pending = [(obj, 0)]
        count = 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if depth > 32 or count > 300000:
                raise ValueError("JSON structure exceeds limits")
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("non-finite JSON number")
            if isinstance(value, dict):
                pending.extend((v, depth + 1) for v in value.values())
            elif isinstance(value, list):
                pending.extend((v, depth + 1) for v in value)
        return obj
    except (ValueError, UnicodeError, RecursionError) as e:
        raise PQError("Invalid or ambiguous JSON", "INVALID_JSON") from e


def b64encode(b):
    return base64.b64encode(bytes(b)).decode("ascii")


def b64decode(s):
    """Strict base64: canonical residual bits, valid charset, optional '=' padding, trailing ASCII whitespace allowed."""
    if not isinstance(s, str):
        raise PQError("Base64 解码失败：输入不是字符串")
    if len(s) > MAX_JSON_BYTES:
        raise PQError("Base64 exceeds the size limit", "INPUT_LIMIT")
    s = s.rstrip("\r\n\t ")
    pad = 0
    while s.endswith("="):
        s = s[:-1]
        pad += 1
    if pad > 2:
        raise PQError("Base64 解码失败：填充非法")
    if len(s) % 4 == 1:
        raise PQError("Base64 解码失败：长度非法")
    if not _B64_RE.match(s):
        raise PQError("Base64 解码失败：含非法字符")
    rem = len(s) % 4
    if pad and pad != (4 - rem) % 4:
        raise PQError("Base64 解码失败：填充非法")
    if rem:
        last = base64.b64decode(s[-1] + "A==" if rem == 1 else s[-rem:] + "=" * (4 - rem))
        # residual bits of the final character must be zero
        v = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".index(s[-1])
        keep = 2 if rem == 3 else 4
        if v & ((1 << keep) - 1):
            raise PQError("Base64 解码失败：非规范编码")
        del last
    return base64.b64decode(s + "=" * ((4 - rem) % 4))


def hexs(b):
    return bytes(b).hex()


def iso_now():
    d = datetime.now(timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (d.microsecond // 1000)


# ---------------------------------------------------------------------------
# ML-KEM-1024 (FIPS 203), pure Python
# ---------------------------------------------------------------------------
_KQ = 3329
_KK = 4
_KETA1 = 2
_KETA2 = 2
_KDU = 11
_KDV = 5


def _bitrev7(i):
    r = 0
    for _ in range(7):
        r = (r << 1) | (i & 1)
        i >>= 1
    return r


_KZETA = [pow(17, _bitrev7(i), _KQ) for i in range(128)]
_KGAMMA = [pow(17, 2 * _bitrev7(i) + 1, _KQ) for i in range(128)]
_CBD2 = [((n & 1) + ((n >> 1) & 1) - ((n >> 2) & 1) - ((n >> 3) & 1)) % _KQ for n in range(16)]


def _k_ntt(f):
    f = list(f)
    q = _KQ
    k = 1
    ln = 128
    while ln >= 2:
        for start in range(0, 256, 2 * ln):
            z = _KZETA[k]
            k += 1
            for j in range(start, start + ln):
                t = z * f[j + ln] % q
                f[j + ln] = (f[j] - t) % q
                f[j] = (f[j] + t) % q
        ln >>= 1
    return f


def _k_intt(f):
    f = list(f)
    q = _KQ
    k = 127
    ln = 2
    while ln <= 128:
        for start in range(0, 256, 2 * ln):
            z = _KZETA[k]
            k -= 1
            for j in range(start, start + ln):
                t = f[j]
                f[j] = (t + f[j + ln]) % q
                f[j + ln] = z * (f[j + ln] - t) % q
        ln <<= 1
    return [x * 3303 % q for x in f]


def _k_mul(f, g):
    q = _KQ
    h = [0] * 256
    for i in range(128):
        a0 = f[2 * i]
        a1 = f[2 * i + 1]
        b0 = g[2 * i]
        b1 = g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 % q * _KGAMMA[i]) % q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % q
    return h


def _padd(f, g, q):
    return [(a + b) % q for a, b in zip(f, g)]


def _psub(f, g, q):
    return [(a - b) % q for a, b in zip(f, g)]


def _bits_encode(d, coeffs):
    v = 0
    for x in reversed(coeffs):
        v = (v << d) | x
    return v.to_bytes(32 * d, "little")


def _bits_decode(d, data, n=256):
    v = int.from_bytes(data, "little")
    m = (1 << d) - 1
    return [(v >> (i * d)) & m for i in range(n)]


def _k_compress(d, x):
    return (((x << (d + 1)) + _KQ) // (2 * _KQ)) & ((1 << d) - 1)


def _k_decompress(d, y):
    return (_KQ * y + (1 << (d - 1))) >> d


def _k_sample_ntt(seed34):
    out = []
    n = 504
    while True:
        buf = hashlib.shake_128(seed34).digest(n)
        out = []
        i = 0
        while i + 3 <= len(buf) and len(out) < 256:
            b0, b1, b2 = buf[i], buf[i + 1], buf[i + 2]
            d1 = b0 + 256 * (b1 & 15)
            d2 = (b1 >> 4) + 16 * b2
            if d1 < _KQ:
                out.append(d1)
            if d2 < _KQ and len(out) < 256:
                out.append(d2)
            i += 3
        if len(out) >= 256:
            return out[:256]
        n *= 2


def _k_cbd2(prf_bytes):
    v = int.from_bytes(prf_bytes, "little")
    return [_CBD2[(v >> (4 * i)) & 15] for i in range(256)]


def _k_prf(sigma, n, eta):
    return hashlib.shake_256(sigma + bytes([n])).digest(64 * eta)


def _k_gen_matrix(rho, transpose=False):
    a = [[None] * _KK for _ in range(_KK)]
    for i in range(_KK):
        for j in range(_KK):
            a[i][j] = _k_sample_ntt(rho + bytes([j, i]))
    if transpose:
        return [[a[j][i] for j in range(_KK)] for i in range(_KK)]
    return a


def _kpke_keygen(d):
    g = hashlib.sha3_512(d + bytes([_KK])).digest()
    rho, sigma = g[:32], g[32:]
    a = _k_gen_matrix(rho)
    s = [_k_ntt(_k_cbd2(_k_prf(sigma, i, _KETA1))) for i in range(_KK)]
    e = [_k_ntt(_k_cbd2(_k_prf(sigma, _KK + i, _KETA1))) for i in range(_KK)]
    t = []
    for i in range(_KK):
        acc = e[i]
        for j in range(_KK):
            acc = _padd(acc, _k_mul(a[i][j], s[j]), _KQ)
        t.append(acc)
    ek = b"".join(_bits_encode(12, p) for p in t) + rho
    dk = b"".join(_bits_encode(12, p) for p in s)
    return ek, dk


def _kpke_encrypt(ek, m, r):
    t = [_bits_decode(12, ek[384 * i:384 * (i + 1)]) for i in range(_KK)]
    rho = ek[384 * _KK:384 * _KK + 32]
    at = _k_gen_matrix(rho, transpose=True)
    y = [_k_ntt(_k_cbd2(_k_prf(r, i, _KETA1))) for i in range(_KK)]
    e1 = [_k_cbd2(_k_prf(r, _KK + i, _KETA2)) for i in range(_KK)]
    e2 = _k_cbd2(_k_prf(r, 2 * _KK, _KETA2))
    u = []
    for i in range(_KK):
        acc = [0] * 256
        for j in range(_KK):
            acc = _padd(acc, _k_mul(at[i][j], y[j]), _KQ)
        u.append(_padd(_k_intt(acc), e1[i], _KQ))
    acc = [0] * 256
    for j in range(_KK):
        acc = _padd(acc, _k_mul(t[j], y[j]), _KQ)
    mu = [_k_decompress(1, x) for x in _bits_decode(1, m)]
    v = _padd(_padd(_k_intt(acc), e2, _KQ), mu, _KQ)
    c1 = b"".join(_bits_encode(_KDU, [_k_compress(_KDU, x) for x in p]) for p in u)
    c2 = _bits_encode(_KDV, [_k_compress(_KDV, x) for x in v])
    return c1 + c2


def _kpke_decrypt(dk, c):
    ul = 32 * _KDU
    u = [[_k_decompress(_KDU, x) for x in _bits_decode(_KDU, c[ul * i:ul * (i + 1)])] for i in range(_KK)]
    v = [_k_decompress(_KDV, x) for x in _bits_decode(_KDV, c[ul * _KK:ul * _KK + 32 * _KDV])]
    s = [_bits_decode(12, dk[384 * i:384 * (i + 1)]) for i in range(_KK)]
    acc = [0] * 256
    for i in range(_KK):
        acc = _padd(acc, _k_mul(s[i], _k_ntt(u[i])), _KQ)
    w = _psub(v, _k_intt(acc), _KQ)
    return _bits_encode(1, [_k_compress(1, x) for x in w])


MLKEM1024_PK_LEN = 1568
MLKEM1024_SK_LEN = 3168
MLKEM1024_CT_LEN = 1568


class MLKEM1024:
    """Deterministic entry points (seed / message) exist for test vectors; the default is random."""

    lengths = {"publicKey": MLKEM1024_PK_LEN, "secretKey": MLKEM1024_SK_LEN, "cipherText": MLKEM1024_CT_LEN}

    @staticmethod
    def keygen(seed=None):
        seed = random_bytes(64) if seed is None else bytes(seed)
        if len(seed) != 64:
            raise PQError("ML-KEM 种子长度应为 64 字节")
        ek, dk = _kpke_keygen(seed[:32])
        sk = dk + ek + hashlib.sha3_256(ek).digest() + seed[32:]
        return ek, sk

    @staticmethod
    def encapsulate(ek, m=None):
        ek = bytes(ek)
        if len(ek) != MLKEM1024_PK_LEN:
            raise PQError("ML-KEM 公钥长度异常")
        for i in range(_KK):
            for x in _bits_decode(12, ek[384 * i:384 * (i + 1)]):
                if x >= _KQ:
                    raise PQError("ML-KEM 公钥编码非法（模数检查失败）")
        m = random_bytes(32) if m is None else bytes(m)
        g = hashlib.sha3_512(m + hashlib.sha3_256(ek).digest()).digest()
        k, r = g[:32], g[32:]
        return _kpke_encrypt(ek, m, r), k

    @staticmethod
    def decapsulate(ct, sk):
        ct = bytes(ct)
        sk = bytes(sk)
        if len(ct) != MLKEM1024_CT_LEN or len(sk) != MLKEM1024_SK_LEN:
            raise PQError("ML-KEM 密文 / 私钥长度异常")
        dk = sk[:384 * _KK]
        ek = sk[384 * _KK:768 * _KK + 32]
        h = sk[768 * _KK + 32:768 * _KK + 64]
        z = sk[768 * _KK + 64:]
        if not bytes_equal(hashlib.sha3_256(ek).digest(), h):
            raise PQError("ML-KEM 私钥损坏（公钥哈希不匹配）")
        m2 = _kpke_decrypt(dk, ct)
        g = hashlib.sha3_512(m2 + h).digest()
        k2, r2 = g[:32], g[32:]
        kbar = hashlib.shake_256(z + ct).digest(32)
        c2 = _kpke_encrypt(ek, m2, r2)
        return k2 if bytes_equal(ct, c2) else kbar


# ---------------------------------------------------------------------------
# ML-DSA-87 (FIPS 204), pure Python
# ---------------------------------------------------------------------------
_DQ = 8380417
_DK = 8
_DL = 7
_DETA = 2
_DTAU = 60
_DBETA = _DTAU * _DETA
_DGAMMA1 = 1 << 19
_DGAMMA2 = (_DQ - 1) // 32
_DOMEGA = 75
_DD = 13
_DCTILDE = 64
_DM = (_DQ - 1) // (2 * _DGAMMA2)


def _bitrev8(i):
    r = 0
    for _ in range(8):
        r = (r << 1) | (i & 1)
        i >>= 1
    return r


_DZETA = [pow(1753, _bitrev8(i), _DQ) for i in range(256)]


def _d_ntt(w):
    w = list(w)
    q = _DQ
    m = 0
    ln = 128
    while ln >= 1:
        for start in range(0, 256, 2 * ln):
            m += 1
            z = _DZETA[m]
            for j in range(start, start + ln):
                t = z * w[j + ln] % q
                w[j + ln] = (w[j] - t) % q
                w[j] = (w[j] + t) % q
        ln >>= 1
    return w


def _d_intt(w):
    w = list(w)
    q = _DQ
    m = 256
    ln = 1
    while ln < 256:
        for start in range(0, 256, 2 * ln):
            m -= 1
            z = q - _DZETA[m]
            for j in range(start, start + ln):
                t = w[j]
                w[j] = (t + w[j + ln]) % q
                w[j + ln] = z * (t - w[j + ln]) % q
        ln <<= 1
    return [x * 8347681 % q for x in w]


def _d_mul(a, b):
    q = _DQ
    return [x * y % q for x, y in zip(a, b)]


def _d_center(x):
    return x - _DQ if x > (_DQ - 1) // 2 else x


def _d_norm_ok(p, bound):
    half = (_DQ - 1) // 2
    q = _DQ
    for x in p:
        if x > half:
            x = q - x
        if x >= bound:
            return False
    return True


def _d_decompose(r):
    rp = r % _DQ
    r0 = rp % (2 * _DGAMMA2)
    if r0 > _DGAMMA2:
        r0 -= 2 * _DGAMMA2
    if rp - r0 == _DQ - 1:
        return 0, r0 - 1
    return (rp - r0) // (2 * _DGAMMA2), r0


def _d_highbits(r):
    return _d_decompose(r)[0]


def _d_lowbits(r):
    return _d_decompose(r)[1]


def _d_make_hint(z, r):
    return 1 if _d_highbits(r) != _d_highbits((r + z) % _DQ) else 0


def _d_use_hint(h, r):
    r1, r0 = _d_decompose(r)
    if h == 1:
        return (r1 + 1) % _DM if r0 > 0 else (r1 - 1) % _DM
    return r1


def _d_power2round(r):
    rp = r % _DQ
    r0 = rp % (1 << _DD)
    if r0 > (1 << (_DD - 1)):
        r0 -= 1 << _DD
    return (rp - r0) >> _DD, r0


def _d_rej_ntt_poly(seed34):
    n = 840
    while True:
        buf = hashlib.shake_128(seed34).digest(n)
        out = []
        for i in range(0, len(buf) - 2, 3):
            t = buf[i] | (buf[i + 1] << 8) | ((buf[i + 2] & 0x7F) << 16)
            if t < _DQ:
                out.append(t)
                if len(out) == 256:
                    return out
        n *= 2


def _d_rej_bounded_poly(seed34):
    n = 272
    while True:
        buf = hashlib.shake_256(seed34).digest(n)
        out = []
        for b in buf:
            for z in (b & 15, b >> 4):
                if z < 15:
                    out.append((2 - z % 5) % _DQ)
                    if len(out) == 256:
                        return out
        n *= 2


def _d_bitpack(coeffs, a, b):
    d = (a + b).bit_length()
    return _bits_encode(d, [b - _d_center(x % _DQ) for x in coeffs])


def _d_bitunpack(data, a, b):
    d = (a + b).bit_length()
    return [b - z for z in _bits_decode(d, data)]


def _d_sample_in_ball(ctilde):
    c = [0] * 256
    n = 8 + 256
    while True:
        buf = hashlib.shake_256(ctilde).digest(n)
        signs = int.from_bytes(buf[:8], "little")
        pos = 8
        ok = True
        for i in range(256 - _DTAU, 256):
            while True:
                if pos >= len(buf):
                    ok = False
                    break
                j = buf[pos]
                pos += 1
                if j <= i:
                    break
            if not ok:
                break
            c[i] = c[j]
            c[j] = (_DQ - 1) if (signs >> (i - (256 - _DTAU))) & 1 else 1
        if ok:
            return c
        c = [0] * 256
        n *= 2


def _d_expand_a(rho):
    return [[_d_rej_ntt_poly(rho + bytes([s, r])) for s in range(_DL)] for r in range(_DK)]


def _d_hint_pack(h):
    y = bytearray(_DOMEGA + _DK)
    idx = 0
    for i in range(_DK):
        for j in range(256):
            if h[i][j]:
                y[idx] = j
                idx += 1
        y[_DOMEGA + i] = idx
    return bytes(y)


def _d_hint_unpack(y):
    h = [[0] * 256 for _ in range(_DK)]
    idx = 0
    for i in range(_DK):
        end = y[_DOMEGA + i]
        if end < idx or end > _DOMEGA:
            return None
        first = idx
        while idx < end:
            if idx > first and y[idx - 1] >= y[idx]:
                return None
            h[i][y[idx]] = 1
            idx += 1
    for i in range(idx, _DOMEGA):
        if y[i] != 0:
            return None
    return h


MLDSA87_PK_LEN = 2592
MLDSA87_SK_LEN = 4896
MLDSA87_SIG_LEN = 4627


class MLDSA87:
    lengths = {"publicKey": MLDSA87_PK_LEN, "secretKey": MLDSA87_SK_LEN, "signature": MLDSA87_SIG_LEN}

    @staticmethod
    def keygen(seed=None):
        xi = random_bytes(32) if seed is None else bytes(seed)
        if len(xi) != 32:
            raise PQError("ML-DSA 种子长度应为 32 字节")
        h = hashlib.shake_256(xi + bytes([_DK, _DL])).digest(128)
        rho, rhop, kk = h[:32], h[32:96], h[96:]
        s1 = [_d_rej_bounded_poly(rhop + bytes([r & 0xFF, r >> 8])) for r in range(_DL)]
        s2 = [_d_rej_bounded_poly(rhop + bytes([(r + _DL) & 0xFF, (r + _DL) >> 8])) for r in range(_DK)]
        a = _d_expand_a(rho)
        s1h = [_d_ntt(p) for p in s1]
        t1 = []
        t0 = []
        for i in range(_DK):
            acc = [0] * 256
            for j in range(_DL):
                acc = _padd(acc, _d_mul(a[i][j], s1h[j]), _DQ)
            t = _padd(_d_intt(acc), s2[i], _DQ)
            hi = []
            lo = []
            for x in t:
                r1, r0 = _d_power2round(x)
                hi.append(r1)
                lo.append(r0)
            t1.append(hi)
            t0.append(lo)
        pk = rho + b"".join(_bits_encode(10, p) for p in t1)
        tr = hashlib.shake_256(pk).digest(64)
        sk = (rho + kk + tr
              + b"".join(_d_bitpack(p, _DETA, _DETA) for p in s1)
              + b"".join(_d_bitpack(p, _DETA, _DETA) for p in s2)
              + b"".join(_d_bitpack(p, (1 << (_DD - 1)) - 1, 1 << (_DD - 1)) for p in t0))
        return pk, sk

    @staticmethod
    def _sk_decode(sk):
        sk = bytes(sk)
        if len(sk) != MLDSA87_SK_LEN:
            raise PQError("ML-DSA 私钥长度异常")
        o = 0
        rho, kk, tr = sk[0:32], sk[32:64], sk[64:128]
        o = 128
        s1 = []
        for _ in range(_DL):
            p = _d_bitunpack(sk[o:o + 96], _DETA, _DETA)
            o += 96
            if any(x < -_DETA or x > _DETA for x in p):
                raise PQError("ML-DSA 私钥编码非法")
            s1.append([x % _DQ for x in p])
        s2 = []
        for _ in range(_DK):
            p = _d_bitunpack(sk[o:o + 96], _DETA, _DETA)
            o += 96
            if any(x < -_DETA or x > _DETA for x in p):
                raise PQError("ML-DSA 私钥编码非法")
            s2.append([x % _DQ for x in p])
        t0 = []
        for _ in range(_DK):
            p = _d_bitunpack(sk[o:o + 416], (1 << (_DD - 1)) - 1, 1 << (_DD - 1))
            o += 416
            t0.append([x % _DQ for x in p])
        return rho, kk, tr, s1, s2, t0

    @staticmethod
    def get_public_key(sk):
        rho, kk, tr, s1, s2, t0 = MLDSA87._sk_decode(sk)
        a = _d_expand_a(rho)
        s1h = [_d_ntt(p) for p in s1]
        t1 = []
        for i in range(_DK):
            acc = [0] * 256
            for j in range(_DL):
                acc = _padd(acc, _d_mul(a[i][j], s1h[j]), _DQ)
            t = _padd(_d_intt(acc), s2[i], _DQ)
            t1.append([_d_power2round(x)[0] for x in t])
        return rho + b"".join(_bits_encode(10, p) for p in t1)

    @staticmethod
    def _message(msg, ctx):
        ctx = b"" if ctx is None else bytes(ctx)
        if len(ctx) > 255:
            raise PQError("ML-DSA 上下文串不能超过 255 字节")
        return b"\x00" + bytes([len(ctx)]) + ctx + bytes(msg)

    @staticmethod
    def sign(msg, sk, ctx=None, deterministic=False):
        rho, kk, tr, s1, s2, t0 = MLDSA87._sk_decode(sk)
        mp = MLDSA87._message(msg, ctx)
        a = _d_expand_a(rho)
        s1h = [_d_ntt(p) for p in s1]
        s2h = [_d_ntt(p) for p in s2]
        t0h = [_d_ntt(p) for p in t0]
        mu = hashlib.shake_256(tr + mp).digest(64)
        rnd = bytes(32) if deterministic else random_bytes(32)
        rhopp = hashlib.shake_256(kk + rnd + mu).digest(64)
        kappa = 0
        q = _DQ
        while True:
            y = []
            for r in range(_DL):
                v = hashlib.shake_256(rhopp + bytes([(kappa + r) & 0xFF, (kappa + r) >> 8])).digest(640)
                y.append([x % q for x in _d_bitunpack(v, _DGAMMA1 - 1, _DGAMMA1)])
            kappa += _DL
            yh = [_d_ntt(p) for p in y]
            w = []
            for i in range(_DK):
                acc = [0] * 256
                for j in range(_DL):
                    acc = _padd(acc, _d_mul(a[i][j], yh[j]), q)
                w.append(_d_intt(acc))
            w1 = [[_d_highbits(x) for x in p] for p in w]
            w1enc = b"".join(_bits_encode(4, p) for p in w1)
            ctilde = hashlib.shake_256(mu + w1enc).digest(_DCTILDE)
            ch = _d_ntt(_d_sample_in_ball(ctilde))
            z = []
            bad = False
            for i in range(_DL):
                zi = _padd(y[i], _d_intt(_d_mul(ch, s1h[i])), q)
                if not _d_norm_ok(zi, _DGAMMA1 - _DBETA):
                    bad = True
                    break
                z.append(zi)
            if bad:
                continue
            h = []
            ones = 0
            for i in range(_DK):
                cs2 = _d_intt(_d_mul(ch, s2h[i]))
                wcs2 = _psub(w[i], cs2, q)
                r0 = [_d_lowbits(x) for x in wcs2]
                if not _d_norm_ok([x % q for x in r0], _DGAMMA2 - _DBETA):
                    bad = True
                    break
                ct0 = _d_intt(_d_mul(ch, t0h[i]))
                if not _d_norm_ok(ct0, _DGAMMA2):
                    bad = True
                    break
                hi = []
                for j in range(256):
                    hb = _d_make_hint((q - ct0[j]) % q, (wcs2[j] + ct0[j]) % q)
                    hi.append(hb)
                    ones += hb
                h.append(hi)
            if bad or ones > _DOMEGA:
                continue
            zenc = b"".join(_d_bitpack(p, _DGAMMA1 - 1, _DGAMMA1) for p in z)
            return ctilde + zenc + _d_hint_pack(h)

    @staticmethod
    def verify(sig, msg, pk, ctx=None):
        sig = bytes(sig)
        pk = bytes(pk)
        if len(sig) != MLDSA87_SIG_LEN or len(pk) != MLDSA87_PK_LEN:
            return False
        rho = pk[:32]
        t1 = [_bits_decode(10, pk[32 + 320 * i:32 + 320 * (i + 1)]) for i in range(_DK)]
        ctilde = sig[:_DCTILDE]
        o = _DCTILDE
        z = []
        for _ in range(_DL):
            z.append([x % _DQ for x in _d_bitunpack(sig[o:o + 640], _DGAMMA1 - 1, _DGAMMA1)])
            o += 640
        h = _d_hint_unpack(sig[o:])
        if h is None:
            return False
        for p in z:
            if not _d_norm_ok(p, _DGAMMA1 - _DBETA):
                return False
        tr = hashlib.shake_256(pk).digest(64)
        mu = hashlib.shake_256(tr + MLDSA87._message(msg, ctx)).digest(64)
        ch = _d_ntt(_d_sample_in_ball(ctilde))
        zh = [_d_ntt(p) for p in z]
        a = _d_expand_a(rho)
        w1p = []
        q = _DQ
        for i in range(_DK):
            acc = [0] * 256
            for j in range(_DL):
                acc = _padd(acc, _d_mul(a[i][j], zh[j]), q)
            ct1 = _d_mul(ch, _d_ntt([(x << _DD) % q for x in t1[i]]))
            wa = _d_intt(_psub(acc, ct1, q))
            w1p.append([_d_use_hint(h[i][j], wa[j]) for j in range(256)])
        w1enc = b"".join(_bits_encode(4, p) for p in w1p)
        c2 = hashlib.shake_256(mu + w1enc).digest(_DCTILDE)
        return bytes_equal(ctilde, c2)


# ---------------------------------------------------------------------------
# Argon2id binding (cryptography >= 44 with OpenSSL >= 3.2, or argon2-cffi)
# ---------------------------------------------------------------------------
class NativeMLKEM1024:
    """Wire-compatible PQClean backend; never falls back to Python arithmetic."""

    @staticmethod
    def backend():
        try:
            from pqcrypto.kem import ml_kem_1024
            return ml_kem_1024
        except ImportError as e:
            raise PQError("需要原生 pqcrypto 后端；请执行 python -m pip install -r requirements.txt", "NO_PQ_BACKEND") from e

    @staticmethod
    def validate_public(pk):
        if len(pk) != MLKEM1024_PK_LEN:
            raise PQError("ML-KEM public key length is invalid")
        for i in range(0, 1536, 3):
            a = pk[i] | ((pk[i + 1] & 15) << 8)
            b = (pk[i + 1] >> 4) | (pk[i + 2] << 4)
            if a >= 3329 or b >= 3329:
                raise PQError("Non-canonical ML-KEM public key")

    @classmethod
    def keygen(cls):
        return cls.backend().generate_keypair()

    @classmethod
    def encapsulate(cls, pk):
        cls.validate_public(pk)
        return cls.backend().encrypt(bytes(pk))

    @classmethod
    def decapsulate(cls, ct, sk):
        if len(sk) != MLKEM1024_SK_LEN or len(ct) != MLKEM1024_CT_LEN:
            raise PQError("ML-KEM secret key or ciphertext length is invalid")
        if not bytes_equal(hashlib.sha3_256(sk[1536:3104]).digest(), sk[3104:3136]):
            raise PQError("ML-KEM secret key hash is invalid")
        return cls.backend().decrypt(bytes(sk), bytes(ct))


class NativeMLDSA87:
    lengths = {"publicKey": MLDSA87_PK_LEN, "secretKey": MLDSA87_SK_LEN, "signature": MLDSA87_SIG_LEN}

    @staticmethod
    def backend():
        try:
            from pqcrypto.sign import ml_dsa_87
            return ml_dsa_87
        except ImportError as e:
            raise PQError("需要原生 pqcrypto 后端；请执行 python -m pip install -r requirements.txt", "NO_PQ_BACKEND") from e

    @classmethod
    def keygen(cls):
        return cls.backend().generate_keypair()

    @classmethod
    def sign(cls, msg, sk):
        if len(sk) != MLDSA87_SK_LEN:
            raise PQError("Invalid ML-DSA secret-key length")
        for i in range(128, 1568, 3):
            packed = int.from_bytes(sk[i:i + 3], "little")
            if any(((packed >> j) & 7) > 4 for j in range(0, 24, 3)):
                raise PQError("Invalid ML-DSA secret-key encoding")
        return cls.backend().sign(bytes(sk), bytes(msg))

    @classmethod
    def verify(cls, sig, msg, pk):
        if len(sig) != MLDSA87_SIG_LEN or len(pk) != MLDSA87_PK_LEN:
            return False
        return cls.backend().verify(bytes(pk), bytes(msg), bytes(sig))


_ARGON_BACKEND = None


def _argon2_backend():
    global _ARGON_BACKEND
    if _ARGON_BACKEND is not None:
        return _ARGON_BACKEND
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

        def via_cryptography(password, salt, t, m_kib, p, hash_len):
            return Argon2id(salt=bytes(salt), length=hash_len, iterations=t, lanes=p, memory_cost=m_kib).derive(bytes(password))
        via_cryptography(b"probe", b"0" * 16, 1, 8, 1, 32)
        _ARGON_BACKEND = ("cryptography", via_cryptography)
        return _ARGON_BACKEND
    except Exception:
        pass
    try:
        from argon2.low_level import hash_secret_raw, Type

        def via_cffi(password, salt, t, m_kib, p, hash_len):
            return hash_secret_raw(bytes(password), bytes(salt), time_cost=t, memory_cost=m_kib, parallelism=p, hash_len=hash_len, type=Type.ID, version=19)
        via_cffi(b"probe", b"0" * 16, 1, 8, 1, 32)
        _ARGON_BACKEND = ("argon2-cffi", via_cffi)
        return _ARGON_BACKEND
    except Exception:
        pass
    raise PQError("没有可用的 Argon2id 实现：请安装 cryptography>=44（pip install -U cryptography）或 argon2-cffi。")


def argon2id_raw(password, salt, t, m_kib, p, hash_len=32):
    PQCrypto.assert_argon_sane(t, m_kib, p)
    name, fn = _argon2_backend()
    return fn(password, salt, t, m_kib, p, hash_len)


def argon2_backend_name():
    try:
        return _argon2_backend()[0]
    except PQError:
        return None


# ---------------------------------------------------------------------------
# Constants and wire format (identical to pqcore.js, format v2 + volume mode 4)
# ---------------------------------------------------------------------------
MAGIC = b"PQFCRYPT"
VERSION = 2
MODE_HYBRID = 1
MODE_PASSWORD = 2
MODE_HYBRID_SIGNED = 3
MODE_VOLUME = 4

VOLUME_ID_LEN = 16
VMK_LEN = 32
VOLUME_FORMAT = "pqdisk-volume-v1"
SLOT_PASSWORD = "password"
SLOT_PUBKEY = "pubkey"

CHUNK_SIZE = 64 * 1024
KEY_LEN = 32
COMMIT_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
X25519_LEN = 32
MAX_BLOCK = CHUNK_SIZE + TAG_LEN
VOLUME_HDR_LEN = len(MAGIC) + 2 + VOLUME_ID_LEN + SALT_LEN + COMMIT_LEN

ARGON_TIME = 4
ARGON_MEM_KIB = 256 * 1024
ARGON_PAR = 4
ARGON_MEM_CAP_KIB = 512 * 1024
ARGON_TIME_CAP = 16
ARGON_PAR_CAP = 16
ARGON_WORK_CAP = 2 * 1024 * 1024
ARGON_VOLUME_WORK_CAP = 4 * 1024 * 1024

SIG_ALG_MLDSA87 = 1
SIG_ENVELOPE_HDR_MAX = 1 + 2 + MLDSA87_PK_LEN + 2 + MLDSA87_SIG_LEN

DS_HYBRID = b"pqfilecrypt:v2:hybrid-kem:x25519+ml-kem-1024"
DS_PW = b"pqfilecrypt:v2:password-kdf:argon2id"
DS_KEYWRAP = b"pqfilecrypt:v2:keywrap-kdf:argon2id"
DS_FP = b"pqfilecrypt:v2:public-key-fingerprint"
DS_SIGN = b"pqfilecrypt:v2:sender-auth:ml-dsa-87"
DS_SIG_FP = b"pqfilecrypt:v2:signer-fingerprint"
DS_VOL_FILE = b"pqdisk:v1:file-key:vmk"
DS_VOL_PW = b"pqdisk:v1:slot-kdf:argon2id"
DS_VOL_HYBRID = b"pqdisk:v1:slot-kem:x25519+ml-kem-1024"
DS_VOL_WRAP = b"pqdisk:v1:slot-wrap:aes-256-gcm"

KEYWRAP_ALG = "pqfilecrypt-key-v2"
KEYWRAP_AAD = KEYWRAP_ALG.encode()

SELFTEST_ARGON = {"timeCost": 1, "memKiB": 8, "parallelism": 1}


def _pw_bytes(pw):
    raw = pw.encode("utf-8") if isinstance(pw, str) else bytes(pw)
    if len(raw) > 4096:
        raise PQError("Password exceeds 4096 UTF-8 bytes", "INPUT_LIMIT")
    return raw


def _nonce(counter, is_last):
    return counter.to_bytes(11, "big") + (b"\x01" if is_last else b"\x00")


def _read_full(f, n):
    parts = []
    got = 0
    while got < n:
        b = f.read(n - got)
        if not b:
            break
        parts.append(b)
        got += len(b)
    return b"".join(parts)


class ByteReader:
    """Pull reader over a binary file object: read_exact(n) returns None on clean EOF, raises on a short tail."""

    def __init__(self, f):
        self.f = f
        self.buf = b""

    def _fill(self, n):
        while len(self.buf) < n:
            b = self.f.read(max(n - len(self.buf), 1 << 16))
            if not b:
                return False
            self.buf += b
        return True

    def read_exact(self, n):
        if not self._fill(n):
            if not self.buf:
                return None
            raise PQError("文件意外结束（可能已损坏或被截断）")
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def at_eof(self):
        return not self._fill(1)


class BytesSink:
    def __init__(self):
        self.parts = []

    def write(self, b):
        self.parts.append(bytes(b))

    def getvalue(self):
        return b"".join(self.parts)


def _check_cancel(cancel):
    if cancel is not None and cancel.is_set():
        raise PQError("已取消", "ABORTED")


class PQCrypto:
    def __init__(self, mlkem=NativeMLKEM1024, mldsa=NativeMLDSA87, argon2id=argon2id_raw):
        if not HAVE_CRYPTOGRAPHY:
            raise PQError("缺少 cryptography 库（pip install cryptography）：" + str(CRYPTOGRAPHY_IMPORT_ERROR))
        self.mlkem = mlkem
        self.mldsa = mldsa
        self.argon2id = argon2id
        if mlkem is NativeMLKEM1024:
            mlkem.backend()
        if mldsa is NativeMLDSA87:
            mldsa.backend()

    # ---- primitives ------------------------------------------------------
    @staticmethod
    def sha256(b):
        return hashlib.sha256(b).digest()

    @staticmethod
    def sha512(b):
        return hashlib.sha512(b).digest()

    @staticmethod
    def _aes_encrypt(key, nonce, aad, data):
        return AESGCM(bytes(key)).encrypt(nonce, bytes(data), aad)

    @staticmethod
    def _aes_decrypt(key, nonce, aad, data):
        return AESGCM(bytes(key)).decrypt(nonce, bytes(data), aad)

    @staticmethod
    def _split(h64):
        return h64[:KEY_LEN], h64[KEY_LEN:KEY_LEN + COMMIT_LEN]

    # ---- streaming AEAD kernel ---------------------------------------------
    def encrypt_stream(self, key, header, data):
        sink = BytesSink()
        self.encrypt_stream_to(key, header, _MemReader(data), sink)
        return sink.getvalue()

    def decrypt_stream(self, key, header, body):
        sink = BytesSink()
        self.decrypt_stream_to(key, header, ByteReader(_MemReader(body)), sink)
        return sink.getvalue()

    def encrypt_stream_to(self, key, header, readable, sink, cancel=None, on_progress=None):
        aes = AESGCM(bytes(key))
        i = 0
        bytes_in = 0
        bytes_out = 0
        pending = _read_full(readable, CHUNK_SIZE)
        while True:
            _check_cancel(cancel)
            if len(pending) < CHUNK_SIZE:
                chunk, last = pending, True
            else:
                nxt = _read_full(readable, CHUNK_SIZE)
                if not nxt:
                    chunk, last = pending, True
                else:
                    chunk, last = pending, False
                    pending = nxt
            blob = aes.encrypt(_nonce(i, last), chunk, header)
            sink.write(u32be(len(blob)))
            sink.write(blob)
            i += 1
            bytes_in += len(chunk)
            bytes_out += 4 + len(blob)
            if on_progress:
                on_progress(len(chunk))
            if last:
                break
        return {"blocks": i, "bytesIn": bytes_in, "bytesOut": bytes_out}

    def decrypt_stream_to(self, key, header, reader, sink, cancel=None, on_progress=None):
        aes = AESGCM(bytes(key))
        i = 0
        bytes_out = 0
        while True:
            _check_cancel(cancel)
            lenb = reader.read_exact(4)
            if lenb is None:
                if i == 0:
                    raise PQError("密文为空或已损坏")
                break
            clen = int.from_bytes(lenb, "big")
            if clen < TAG_LEN or clen > MAX_BLOCK:
                raise PQError("密文块长度异常（文件可能已损坏或被篡改）")
            block = reader.read_exact(clen)
            if block is None:
                raise PQError("文件意外结束（可能已损坏或被截断）")
            is_last = reader.at_eof()
            try:
                pt = aes.decrypt(_nonce(i, is_last), block, header)
            except Exception:
                raise PQError("认证失败：文件被篡改 / 被截断，或密钥 / 口令不正确。", "AUTH_FAILED")
            if sink is not None:
                sink.write(pt)
            i += 1
            bytes_out += len(pt)
            if on_progress:
                on_progress(len(pt))
        return {"blocks": i, "bytesOut": bytes_out}

    # ---- key derivation ------------------------------------------------------
    def hybrid_derive(self, ss_mlkem, ss_x25519, mlkem_ct, mlkem_pk, eph_pk, recip_pk, salt, label=DS_HYBRID):
        return self._split(self.sha512(label + ss_mlkem + ss_x25519 + mlkem_ct + mlkem_pk + eph_pk + recip_pk + salt))

    def argon2_raw(self, password, salt, t, m_kib, p, hash_len=KEY_LEN):
        self.assert_argon_sane(t, m_kib, p)
        if not self.argon2id:
            raise PQError("口令模式需要 Argon2id 实现")
        return bytes(self.argon2id(_pw_bytes(password), salt, t, m_kib, p, hash_len))

    def password_derive(self, master):
        return self._split(self.sha512(DS_PW + master))

    def keywrap_derive(self, master):
        return self._split(self.sha512(DS_KEYWRAP + master))

    # ---- X25519 -----------------------------------------------------------------
    @staticmethod
    def x25519_generate_raw():
        k = X25519PrivateKey.generate()
        return k.public_key().public_bytes_raw(), k.private_bytes_raw()

    @staticmethod
    def x25519_exchange(priv_raw, peer_pub_raw):
        return X25519PrivateKey.from_private_bytes(bytes(priv_raw)).exchange(X25519PublicKey.from_public_bytes(bytes(peer_pub_raw)))

    # ---- headers ------------------------------------------------------------------
    @staticmethod
    def build_header_hybrid(eph_pub, mlkem_ct, salt, commit, mode=MODE_HYBRID):
        return MAGIC + bytes([VERSION, mode]) + eph_pub + u16be(len(mlkem_ct)) + mlkem_ct + salt + commit

    @staticmethod
    def build_header_password(salt, t, m_kib, p, commit):
        return MAGIC + bytes([VERSION, MODE_PASSWORD]) + salt + bytes([t]) + u32be(m_kib) + bytes([p]) + commit

    @staticmethod
    def build_header_volume(volume_id, file_salt, commit):
        return MAGIC + bytes([VERSION, MODE_VOLUME]) + volume_id + file_salt + commit

    @staticmethod
    def parse_header(buf):
        buf = bytes(buf)

        def need(n, off):
            if off + n > len(buf):
                raise PQError("文件头不完整")
        need(len(MAGIC), 0)
        if not bytes_equal(buf[:len(MAGIC)], MAGIC):
            raise PQError("不是有效的 PQFCRYPT 文件（魔数不匹配）")
        o = len(MAGIC)
        need(2, o)
        version, mode = buf[o], buf[o + 1]
        o += 2
        if version != VERSION:
            raise PQError("不支持的文件版本：%d（本工具仅支持格式 v%d，不兼容旧版 / pqfilecrypt.py）" % (version, VERSION))
        info = {"version": version, "mode": mode}
        if mode in (MODE_HYBRID, MODE_HYBRID_SIGNED):
            need(X25519_LEN, o)
            info["ephPub"] = buf[o:o + X25519_LEN]
            o += X25519_LEN
            need(2, o)
            ctlen = (buf[o] << 8) | buf[o + 1]
            o += 2
            if ctlen != MLKEM1024_CT_LEN:
                raise PQError("文件头损坏：ML-KEM 密文长度异常")
            need(ctlen, o)
            info["mlkemCt"] = buf[o:o + ctlen]
            o += ctlen
            need(SALT_LEN, o)
            info["salt"] = buf[o:o + SALT_LEN]
            o += SALT_LEN
            need(COMMIT_LEN, o)
            info["commit"] = buf[o:o + COMMIT_LEN]
            o += COMMIT_LEN
        elif mode == MODE_PASSWORD:
            need(SALT_LEN, o)
            info["salt"] = buf[o:o + SALT_LEN]
            o += SALT_LEN
            need(6, o)
            info["timeCost"] = buf[o]
            info["memKiB"] = int.from_bytes(buf[o + 1:o + 5], "big")
            info["parallelism"] = buf[o + 5]
            o += 6
            need(COMMIT_LEN, o)
            info["commit"] = buf[o:o + COMMIT_LEN]
            o += COMMIT_LEN
        elif mode == MODE_VOLUME:
            need(VOLUME_ID_LEN, o)
            info["volumeId"] = buf[o:o + VOLUME_ID_LEN]
            o += VOLUME_ID_LEN
            need(SALT_LEN, o)
            info["salt"] = buf[o:o + SALT_LEN]
            o += SALT_LEN
            need(COMMIT_LEN, o)
            info["commit"] = buf[o:o + COMMIT_LEN]
            o += COMMIT_LEN
        else:
            raise PQError("未知模式：%d" % mode)
        info["raw"] = buf[:o]
        info["bodyOffset"] = o
        return info

    @staticmethod
    def probe_header(buf):
        buf = bytes(buf) if buf is not None else b""
        if len(buf) < len(MAGIC) + 2 or buf[:len(MAGIC)] != MAGIC:
            return {"ok": False}
        version, mode = buf[len(MAGIC)], buf[len(MAGIC) + 1]
        info = {"ok": True, "version": version, "mode": mode, "volumeId": None}
        if version == VERSION and mode == MODE_VOLUME and len(buf) >= VOLUME_HDR_LEN:
            info["volumeId"] = buf[len(MAGIC) + 2:len(MAGIC) + 2 + VOLUME_ID_LEN]
        return info

    # ---- key pairs (JSON objects) -----------------------------------------------
    def generate_keypair(self):
        x_pub, x_priv = self.x25519_generate_raw()
        mk_pub, mk_sec = self.mlkem.keygen()
        have_dsa = self.mldsa is not None
        d_pub = d_sec = None
        if have_dsa:
            d_pub, d_sec = self.mldsa.keygen()
        pub = {
            "v": 3 if have_dsa else 2,
            "alg": "X25519+ML-KEM-1024+ML-DSA-87" if have_dsa else "X25519+ML-KEM-1024",
            "x25519_pub": b64encode(x_pub),
            "mlkem_pub": b64encode(mk_pub),
        }
        if have_dsa:
            pub["mldsa_pub"] = b64encode(d_pub)
        key = dict(pub)
        key["x25519_priv"] = b64encode(x_priv)
        key["mlkem_secret"] = b64encode(mk_sec)
        if have_dsa:
            key["mldsa_secret"] = b64encode(d_sec)
        return {
            "pub": pub, "key": key,
            "fingerprint": self.fingerprint(x_pub, mk_pub),
            "signerFingerprint": self.signer_fingerprint(d_pub) if have_dsa else None,
        }

    def fingerprint(self, *parts):
        d = self.sha256(DS_FP + b"".join(parts))[:16]
        return ":".join("%02x" % b for b in d)

    def signer_fingerprint(self, mldsa_pub):
        d = self.sha256(DS_SIG_FP + mldsa_pub)[:16]
        return ":".join("%02x" % b for b in d)

    # ---- strict validation ------------------------------------------------------
    @staticmethod
    def assert_argon_sane(t, m_kib, p):
        if any(type(v) is not int for v in (t, m_kib, p)):
            raise PQError("Argon2 parameters must be integers (not strings, floats or booleans)")
        if not (1 <= t <= ARGON_TIME_CAP):
            raise PQError("Argon2 时间参数超出允许范围")
        if not (1 <= p <= ARGON_PAR_CAP):
            raise PQError("Argon2 并行度超出允许范围")
        if not (8 <= m_kib <= ARGON_MEM_CAP_KIB):
            raise PQError("Argon2 内存参数超出允许范围（已拒绝，以防内存耗尽攻击）")
        if m_kib < 8 * p or t * m_kib > ARGON_WORK_CAP:
            raise PQError("Argon2 parameters exceed the work budget or require m >= 8*p", "KDF_LIMIT")

    @staticmethod
    def validate_pub(pub):
        if not isinstance(pub, dict) or not pub.get("x25519_pub") or not pub.get("mlkem_pub"):
            raise PQError("这不是有效的 .pub 公钥文件")
        x = b64decode(pub["x25519_pub"])
        m = b64decode(pub["mlkem_pub"])
        if len(x) != X25519_LEN:
            raise PQError("公钥无效：X25519 公钥长度应为 32 字节")
        if len(m) != MLKEM1024_PK_LEN:
            raise PQError("公钥无效：ML-KEM-1024 公钥长度应为 %d 字节" % MLKEM1024_PK_LEN)
        NativeMLKEM1024.validate_public(m)
        try:
            PQCrypto.x25519_exchange(random_bytes(32), x)
        except ValueError as e:
            raise PQError("Invalid low-order X25519 public key") from e
        d = None
        if pub.get("mldsa_pub"):
            d = b64decode(pub["mldsa_pub"])
            if len(d) != MLDSA87_PK_LEN:
                raise PQError("公钥无效：ML-DSA-87 公钥长度应为 %d 字节" % MLDSA87_PK_LEN)
        return {"x": x, "m": m, "d": d}

    def validate_key_obj(self, obj):
        if not isinstance(obj, dict) or not obj.get("x25519_priv") or not obj.get("mlkem_secret"):
            raise PQError("这不是有效的 .key 私钥文件")
        if not obj.get("x25519_pub") or not obj.get("mlkem_pub"):
            raise PQError("私钥文件缺少对应公钥字段（v2 私钥需同时包含公钥）")
        x_priv = b64decode(obj["x25519_priv"])
        mk_sec = b64decode(obj["mlkem_secret"])
        x_pub = b64decode(obj["x25519_pub"])
        mk_pub = b64decode(obj["mlkem_pub"])
        if len(x_priv) != X25519_LEN:
            raise PQError("私钥无效：X25519 私钥长度应为 32 字节")
        if len(mk_sec) != MLKEM1024_SK_LEN:
            raise PQError("私钥无效：ML-KEM-1024 私钥长度应为 %d 字节" % MLKEM1024_SK_LEN)
        if len(x_pub) != X25519_LEN:
            raise PQError("私钥无效：内含 X25519 公钥长度异常")
        if len(mk_pub) != MLKEM1024_PK_LEN:
            raise PQError("私钥无效：内含 ML-KEM 公钥长度异常")
        d_pub = d_sec = None
        if obj.get("mldsa_secret") or obj.get("mldsa_pub"):
            if not obj.get("mldsa_secret") or not obj.get("mldsa_pub"):
                raise PQError("私钥无效：ML-DSA 公钥 / 私钥字段必须成对出现")
            d_sec = b64decode(obj["mldsa_secret"])
            d_pub = b64decode(obj["mldsa_pub"])
            if len(d_sec) != MLDSA87_SK_LEN:
                raise PQError("私钥无效：ML-DSA-87 私钥长度应为 %d 字节" % MLDSA87_SK_LEN)
            if len(d_pub) != MLDSA87_PK_LEN:
                raise PQError("私钥无效：内含 ML-DSA 公钥长度异常")
        actual_x = X25519PrivateKey.from_private_bytes(x_priv).public_key().public_bytes_raw()
        if not bytes_equal(actual_x, x_pub) or not bytes_equal(mk_sec[1536:3104], mk_pub):
            raise PQError("Private key does not match its public key", "KEY_MISMATCH")
        ct, ss = self.mlkem.encapsulate(mk_pub)
        if not bytes_equal(ss, self.mlkem.decapsulate(ct, mk_sec)):
            raise PQError("ML-KEM keypair consistency check failed", "KEY_MISMATCH")
        if d_sec is not None:
            if self.mldsa is None:
                raise PQError("Cannot validate the ML-DSA private key without a native backend")
            if not bytes_equal(d_sec[:32], d_pub[:32]) or not bytes_equal(d_sec[64:128], hashlib.shake_256(d_pub).digest(64)):
                raise PQError("ML-DSA public-key hash mismatch", "KEY_MISMATCH")
            challenge = b"pqdisk:keypair-check:v1:" + random_bytes(32)
            if not self.mldsa.verify(self.mldsa.sign(challenge, d_sec), challenge, d_pub):
                raise PQError("ML-DSA keypair consistency check failed", "KEY_MISMATCH")
        return {"xPriv": x_priv, "mkSecret": mk_sec, "xPub": x_pub, "mkPub": mk_pub, "dPub": d_pub, "dSecret": d_sec}

    # ---- single-file modes (kept for format completeness / tests) -------------------
    def _hybrid_encrypt_core(self, recipient_pub, data, mode):
        p = self.validate_pub(recipient_pub)
        eph_pub, eph_priv = self.x25519_generate_raw()
        ss_x = self.x25519_exchange(eph_priv, p["x"])
        mlkem_ct, ss_k = self.mlkem.encapsulate(p["m"])
        salt = random_bytes(SALT_LEN)
        enc_key, commit = self.hybrid_derive(ss_k, ss_x, mlkem_ct, p["m"], eph_pub, p["x"], salt)
        header = self.build_header_hybrid(eph_pub, mlkem_ct, salt, commit, mode)
        return header + self.encrypt_stream(enc_key, header, data)

    def encrypt_hybrid(self, recipient_pub, data):
        return self._hybrid_encrypt_core(recipient_pub, data, MODE_HYBRID)

    def encrypt_password(self, password, data, params=None):
        params = params or {}
        t = params.get("timeCost", ARGON_TIME)
        m = params.get("memKiB", ARGON_MEM_KIB)
        p = params.get("parallelism", ARGON_PAR)
        salt = random_bytes(SALT_LEN)
        master = self.argon2_raw(password, salt, t, m, p)
        enc_key, commit = self.password_derive(master)
        header = self.build_header_password(salt, t, m, p, commit)
        return header + self.encrypt_stream(enc_key, header, data)

    def signed_message(self, recip_x_pub, recip_mk_pub, sender_dsa_pub, plaintext):
        return DS_SIGN + recip_x_pub + recip_mk_pub + sender_dsa_pub + self.sha512(plaintext)

    @staticmethod
    def build_signed_envelope(sender_dsa_pub, signature, plaintext):
        return bytes([SIG_ALG_MLDSA87]) + u16be(len(sender_dsa_pub)) + sender_dsa_pub + u16be(len(signature)) + signature + plaintext

    @staticmethod
    def parse_signed_envelope(buf):
        o = 0

        def need(n):
            if o + n > len(buf):
                raise PQError("签名封套不完整（文件可能已损坏）")
        need(1)
        alg = buf[0]
        o = 1
        if alg != SIG_ALG_MLDSA87:
            raise PQError("未知的签名算法标识：%d" % alg)
        need(2)
        pk_len = (buf[o] << 8) | buf[o + 1]
        o += 2
        if pk_len != MLDSA87_PK_LEN:
            raise PQError("签名封套损坏：发件人公钥长度异常")
        need(pk_len)
        sender = buf[o:o + pk_len]
        o += pk_len
        need(2)
        sig_len = (buf[o] << 8) | buf[o + 1]
        o += 2
        if sig_len != MLDSA87_SIG_LEN:
            raise PQError("签名封套损坏：签名长度异常")
        need(sig_len)
        sig = buf[o:o + sig_len]
        o += sig_len
        if o > SIG_ENVELOPE_HDR_MAX:
            raise PQError("签名封套头过大（已拒绝）")
        return {"senderDsaPub": sender, "signature": sig, "plaintext": buf[o:]}

    def encrypt_hybrid_signed(self, recipient_pub, data, signer_key_obj):
        if self.mldsa is None:
            raise PQError("签名需要 ML-DSA 实现")
        p = self.validate_pub(recipient_pub)
        sk = self.validate_key_obj(signer_key_obj)
        if not sk["dSecret"] or not sk["dPub"]:
            raise PQError("用于签名的私钥不含 ML-DSA 签名密钥")
        msg = self.signed_message(p["x"], p["m"], sk["dPub"], data)
        signature = self.mldsa.sign(msg, sk["dSecret"])
        envelope = self.build_signed_envelope(sk["dPub"], signature, data)
        return self._hybrid_encrypt_core(recipient_pub, envelope, MODE_HYBRID_SIGNED)

    def decrypt(self, file_bytes, password=None, key_obj=None):
        file_bytes = bytes(file_bytes)
        hdr = self.parse_header(file_bytes)
        body = file_bytes[hdr["bodyOffset"]:]
        recip_x_pub = recip_mk_pub = None
        if hdr["mode"] == MODE_PASSWORD:
            if password is None:
                raise PQError("该文件为口令模式，请提供口令。")
            self.assert_argon_sane(hdr["timeCost"], hdr["memKiB"], hdr["parallelism"])
            master = self.argon2_raw(password, hdr["salt"], hdr["timeCost"], hdr["memKiB"], hdr["parallelism"])
            enc_key, commit = self.password_derive(master)
        elif hdr["mode"] in (MODE_HYBRID, MODE_HYBRID_SIGNED):
            if key_obj is None:
                raise PQError("该文件为混合公钥模式，请提供你的私钥文件 (.key)。")
            k = self.validate_key_obj(key_obj)
            recip_x_pub, recip_mk_pub = k["xPub"], k["mkPub"]
            ss_x = self.x25519_exchange(k["xPriv"], hdr["ephPub"])
            ss_k = self.mlkem.decapsulate(hdr["mlkemCt"], k["mkSecret"])
            enc_key, commit = self.hybrid_derive(ss_k, ss_x, hdr["mlkemCt"], k["mkPub"], hdr["ephPub"], k["xPub"], hdr["salt"])
        else:
            raise PQError("未知模式：%d" % hdr["mode"])
        if not bytes_equal(commit, hdr["commit"]):
            if hdr["mode"] == MODE_PASSWORD:
                raise PQError("口令错误，或文件已损坏 / 被篡改。", "BAD_PASSWORD")
            raise PQError("私钥与此文件不匹配，或文件已损坏 / 被篡改。", "KEY_MISMATCH")
        decrypted = self.decrypt_stream(enc_key, hdr["raw"], body)
        if hdr["mode"] == MODE_HYBRID_SIGNED:
            if self.mldsa is None:
                raise PQError("此文件含发件人签名，但没有 ML-DSA 验证实现。")
            env = self.parse_signed_envelope(decrypted)
            msg = self.signed_message(recip_x_pub, recip_mk_pub, env["senderDsaPub"], env["plaintext"])
            if not self.mldsa.verify(env["signature"], msg, env["senderDsaPub"]):
                raise PQError("发件人签名验证失败：文件可能被篡改，或并非声称的发件人 / 收件人。")
            return {"plaintext": env["plaintext"], "mode": hdr["mode"], "signed": True,
                    "signerFingerprint": self.signer_fingerprint(env["senderDsaPub"]),
                    "signerPublicKey": b64encode(env["senderDsaPub"])}
        return {"plaintext": decrypted, "mode": hdr["mode"], "signed": False}

    # ---- private key at rest (.key container v2) --------------------------------------
    @staticmethod
    def is_wrapped_key(obj):
        return isinstance(obj, dict) and obj.get("alg") == KEYWRAP_ALG and isinstance(obj.get("ciphertext"), str)

    def wrap_secret_key(self, key_obj, passphrase, params=None):
        if not passphrase:
            raise PQError("用于保护私钥的口令不能为空")
        self.validate_key_obj(key_obj)
        params = params or {}
        t = params.get("timeCost", ARGON_TIME)
        m = params.get("memKiB", ARGON_MEM_KIB)
        p = params.get("parallelism", ARGON_PAR)
        salt = random_bytes(SALT_LEN)
        master = self.argon2_raw(passphrase, salt, t, m, p)
        enc_key, commit = self.keywrap_derive(master)
        iv = random_bytes(NONCE_LEN)
        pt = json.dumps(key_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ct = self._aes_encrypt(enc_key, iv, KEYWRAP_AAD, pt)
        return {
            "alg": KEYWRAP_ALG,
            "note": "口令保护的 pqfilecrypt 私钥（格式 v2）；在本工具“解密”页载入即可（需口令）。",
            "kdf": "argon2id",
            "kdf_params": {"t": t, "m": m, "p": p, "salt": b64encode(salt)},
            "commit": b64encode(commit),
            "cipher": "AES-256-GCM",
            "nonce": b64encode(iv),
            "ciphertext": b64encode(ct),
        }

    def unwrap_secret_key(self, container, passphrase):
        if not self.is_wrapped_key(container):
            raise PQError("这不是受口令保护的 v2 私钥文件")
        if not passphrase:
            raise PQError("请输入解锁私钥的口令")
        if container.get("kdf") != "argon2id" or container.get("cipher") != "AES-256-GCM":
            raise PQError("Unsupported private-key container algorithms")
        p = container.get("kdf_params")
        if not isinstance(p, dict):
            raise PQError("Invalid private-key KDF parameters")
        salt = b64decode(p.get("salt") or "")
        if len(salt) != SALT_LEN:
            raise PQError("私钥容器损坏：salt 长度异常")
        t, m, par = p.get("t"), p.get("m"), p.get("p")
        self.assert_argon_sane(t, m, par)
        iv = b64decode(container.get("nonce") or "")
        ciphertext = b64decode(container["ciphertext"])
        if len(iv) != NONCE_LEN or not TAG_LEN <= len(ciphertext) <= MAX_JSON_BYTES // 2:
            raise PQError("Invalid private-key ciphertext or nonce")
        stored_commit = b64decode(container.get("commit") or "")
        if len(stored_commit) != COMMIT_LEN:
            raise PQError("私钥容器损坏：承诺值长度异常")
        master = self.argon2_raw(passphrase, salt, t, m, par)
        enc_key, commit = self.keywrap_derive(master)
        if not bytes_equal(commit, stored_commit):
            raise PQError("口令错误，或私钥文件已损坏 / 被篡改。", "BAD_PASSWORD")
        iv = b64decode(container.get("nonce") or "")
        if len(iv) != NONCE_LEN:
            raise PQError("私钥容器损坏：nonce 长度异常")
        try:
            pt = self._aes_decrypt(enc_key, iv, KEYWRAP_AAD, ciphertext)
        except Exception:
            raise PQError("口令错误，或私钥文件已损坏 / 被篡改。", "BAD_PASSWORD")
        try:
            obj = strict_json(pt)
        except Exception:
            raise PQError("私钥容器解密后内容不是有效 JSON")
        self.validate_key_obj(obj)
        return obj

    # ---- volume mode: VMK, key slots, per-file keys --------------------------------------
    def volume_file_derive(self, vmk, volume_id, file_salt):
        if len(vmk) != VMK_LEN:
            raise PQError("卷主密钥长度异常")
        return self._split(self.sha512(DS_VOL_FILE + bytes(vmk) + volume_id + file_salt))

    @staticmethod
    def new_volume(hide_names=False, label=""):
        vmk = bytearray(random_bytes(VMK_LEN))
        volume_id = random_bytes(VOLUME_ID_LEN)
        header = {
            "format": VOLUME_FORMAT,
            "volume_id": b64encode(volume_id),
            "created": iso_now(),
            "label": str(label or "")[:200],
            "hide_names": bool(hide_names),
            "slots": [],
        }
        return {"vmk": vmk, "volumeId": volume_id, "header": header}

    @staticmethod
    def _slot_aad(volume_id, slot_type):
        return DS_VOL_WRAP + volume_id + bytes([1 if slot_type == SLOT_PASSWORD else 2])

    def _wrap_vmk(self, enc_key, aad, vmk):
        iv = random_bytes(NONCE_LEN)
        return iv, self._aes_encrypt(enc_key, iv, aad, bytes(vmk))

    def _unwrap_vmk(self, enc_key, aad, iv, ct):
        try:
            pt = self._aes_decrypt(enc_key, iv, aad, ct)
        except Exception:
            raise PQError("密钥槽解封失败：卷头已损坏 / 被篡改")
        if len(pt) != VMK_LEN:
            raise PQError("密钥槽解封结果长度异常")
        return bytearray(pt)

    def validate_volume_header(self, h):
        if not isinstance(h, dict) or h.get("format") != VOLUME_FORMAT:
            raise PQError("这不是有效的 pqdisk 卷头（.pqvolume）")
        volume_id = b64decode(h.get("volume_id") or "")
        if len(volume_id) != VOLUME_ID_LEN:
            raise PQError("卷头损坏：卷 ID 长度异常")
        if not isinstance(h.get("hide_names"), bool):
            raise PQError("卷头损坏：缺少 hide_names 标志")
        slots = h.get("slots")
        if not isinstance(slots, list) or not slots:
            raise PQError("卷头不含任何密钥槽，无法解锁")
        if len(slots) > MAX_SLOTS:
            raise PQError("Too many volume key slots", "INPUT_LIMIT")
        if not isinstance(h.get("label", ""), str) or len(h.get("label", "")) > 200:
            raise PQError("Invalid volume label")
        total_work = 0

        def len_is(s, n, what):
            b = b64decode(s or "")
            if len(b) != n:
                raise PQError("卷头损坏：" + what + "长度异常")
            return b
        for i, s in enumerate(slots):
            at = "密钥槽 #%d " % (i + 1)
            if not isinstance(s, dict):
                raise PQError("卷头损坏：" + at + "格式异常")
            len_is(s.get("commit"), COMMIT_LEN, at + "承诺值")
            len_is(s.get("nonce"), NONCE_LEN, at + "nonce")
            len_is(s.get("wrapped_key"), VMK_LEN + TAG_LEN, at + "包裹密钥")
            if s.get("type") == SLOT_PASSWORD:
                p = s.get("kdf_params")
                if not isinstance(p, dict):
                    raise PQError("Invalid slot KDF parameters")
                if s.get("kdf") != "argon2id":
                    raise PQError("卷头损坏：" + at + "KDF 未知")
                len_is(p.get("salt"), SALT_LEN, at + "salt")
                self.assert_argon_sane(p.get("t"), p.get("m"), p.get("p"))
                total_work += p["t"] * p["m"]
                if total_work > ARGON_VOLUME_WORK_CAP:
                    raise PQError("Volume password slots exceed the total KDF work budget", "KDF_LIMIT")
            elif s.get("type") == SLOT_PUBKEY:
                len_is(s.get("eph_x25519_pub"), X25519_LEN, at + "临时公钥")
                len_is(s.get("mlkem_ct"), MLKEM1024_CT_LEN, at + "ML-KEM 密文")
                len_is(s.get("salt"), SALT_LEN, at + "salt")
            else:
                raise PQError("卷头含不支持的密钥槽类型“%s”（可能由更新版本创建）" % str(s.get("type")))
        return {"volumeId": volume_id}

    def add_password_slot(self, header, vmk, password, params=None):
        if not password:
            raise PQError("口令不能为空")
        volume_id = b64decode(header.get("volume_id") or "")
        if len(volume_id) != VOLUME_ID_LEN:
            raise PQError("卷头损坏：卷 ID 长度异常")
        params = params or {}
        t = params.get("timeCost", ARGON_TIME)
        m = params.get("memKiB", ARGON_MEM_KIB)
        p = params.get("parallelism", ARGON_PAR)
        salt = random_bytes(SALT_LEN)
        master = self.argon2_raw(password, salt, t, m, p)
        enc_key, commit = self._split(self.sha512(DS_VOL_PW + master))
        iv, ct = self._wrap_vmk(enc_key, self._slot_aad(volume_id, SLOT_PASSWORD), vmk)
        slot = {
            "type": SLOT_PASSWORD, "kdf": "argon2id",
            "kdf_params": {"t": t, "m": m, "p": p, "salt": b64encode(salt)},
            "commit": b64encode(commit), "nonce": b64encode(iv), "wrapped_key": b64encode(ct),
            "created": iso_now(),
        }
        candidate = dict(header, slots=list(header.get("slots", [])) + [slot])
        self.validate_volume_header(candidate)
        header["slots"] = candidate["slots"]
        return slot

    def add_pubkey_slot(self, header, vmk, recipient_pub):
        volume_id = b64decode(header.get("volume_id") or "")
        if len(volume_id) != VOLUME_ID_LEN:
            raise PQError("卷头损坏：卷 ID 长度异常")
        p = self.validate_pub(recipient_pub)
        eph_pub, eph_priv = self.x25519_generate_raw()
        ss_x = self.x25519_exchange(eph_priv, p["x"])
        mlkem_ct, ss_k = self.mlkem.encapsulate(p["m"])
        salt = random_bytes(SALT_LEN)
        enc_key, commit = self.hybrid_derive(ss_k, ss_x, mlkem_ct, p["m"], eph_pub, p["x"], salt, label=DS_VOL_HYBRID)
        iv, ct = self._wrap_vmk(enc_key, self._slot_aad(volume_id, SLOT_PUBKEY), vmk)
        slot = {
            "type": SLOT_PUBKEY, "alg": "X25519+ML-KEM-1024",
            "fingerprint": self.fingerprint(p["x"], p["m"]),
            "eph_x25519_pub": b64encode(eph_pub), "mlkem_ct": b64encode(mlkem_ct), "salt": b64encode(salt),
            "commit": b64encode(commit), "nonce": b64encode(iv), "wrapped_key": b64encode(ct),
            "created": iso_now(),
        }
        candidate = dict(header, slots=list(header.get("slots", [])) + [slot])
        self.validate_volume_header(candidate)
        header["slots"] = candidate["slots"]
        return slot

    def remove_slot(self, header, index):
        self.validate_volume_header(header)
        if not (0 <= index < len(header["slots"])):
            raise PQError("密钥槽序号无效")
        if len(header["slots"]) <= 1:
            raise PQError("不能删除最后一个密钥槽：那会让整个卷永久无法解锁")
        return header["slots"].pop(index)

    def unlock_volume(self, header, password=None, key_obj=None):
        volume_id = self.validate_volume_header(header)["volumeId"]
        if password is not None:
            tried = 0
            for i, s in enumerate(header["slots"]):
                if s.get("type") != SLOT_PASSWORD:
                    continue
                tried += 1
                p = s["kdf_params"]
                master = self.argon2_raw(password, b64decode(p["salt"]), p["t"], p["m"], p["p"])
                enc_key, commit = self._split(self.sha512(DS_VOL_PW + master))
                if not bytes_equal(commit, b64decode(s["commit"])):
                    continue
                vmk = self._unwrap_vmk(enc_key, self._slot_aad(volume_id, SLOT_PASSWORD), b64decode(s["nonce"]), b64decode(s["wrapped_key"]))
                return {"vmk": vmk, "slotIndex": i, "volumeId": volume_id}
            if tried == 0:
                raise PQError("此卷没有口令密钥槽，请改用私钥解锁。", "NO_SLOT")
            raise PQError("口令错误，或卷头已损坏 / 被篡改。", "BAD_PASSWORD")
        if key_obj is not None:
            k = self.validate_key_obj(key_obj)
            tried = 0
            for i, s in enumerate(header["slots"]):
                if s.get("type") != SLOT_PUBKEY:
                    continue
                tried += 1
                eph_pub = b64decode(s["eph_x25519_pub"])
                mlkem_ct = b64decode(s["mlkem_ct"])
                try:
                    ss_x = self.x25519_exchange(k["xPriv"], eph_pub)
                    ss_k = self.mlkem.decapsulate(mlkem_ct, k["mkSecret"])
                except Exception:
                    continue
                enc_key, commit = self.hybrid_derive(ss_k, ss_x, mlkem_ct, k["mkPub"], eph_pub, k["xPub"], b64decode(s["salt"]), label=DS_VOL_HYBRID)
                if not bytes_equal(commit, b64decode(s["commit"])):
                    continue
                vmk = self._unwrap_vmk(enc_key, self._slot_aad(volume_id, SLOT_PUBKEY), b64decode(s["nonce"]), b64decode(s["wrapped_key"]))
                return {"vmk": vmk, "slotIndex": i, "volumeId": volume_id}
            if tried == 0:
                raise PQError("此卷没有公钥密钥槽，请改用口令解锁。", "NO_SLOT")
            raise PQError("此私钥与卷的任何公钥槽都不匹配，或卷头已损坏 / 被篡改。", "KEY_MISMATCH")
        raise PQError("解锁卷需要提供口令或私钥")

    # ---- volume files: streaming / whole-buffer --------------------------------------------
    def encrypt_volume_stream(self, vmk, volume_id, readable, sink, cancel=None, on_progress=None):
        file_salt = random_bytes(SALT_LEN)
        enc_key, commit = self.volume_file_derive(vmk, volume_id, file_salt)
        header = self.build_header_volume(volume_id, file_salt, commit)
        sink.write(header)
        r = self.encrypt_stream_to(enc_key, header, readable, sink, cancel, on_progress)
        r["bytesOut"] += len(header)
        return r

    def open_volume_stream(self, vmk, volume_id, reader):
        head = reader.read_exact(len(MAGIC) + 2)
        if head is None:
            raise PQError("文件为空，不是有效的加密文件")
        p = self.probe_header(head)
        if not p["ok"]:
            raise PQError("不是本工具的加密文件（魔数不匹配）", "NOT_PQFC")
        if p["version"] != VERSION or p["mode"] != MODE_VOLUME:
            raise PQError("这不是卷模式文件（可能是单文件模式或其它版本）", "NOT_VOLUME_FILE")
        rest = reader.read_exact(VOLUME_HDR_LEN - len(head))
        if rest is None:
            raise PQError("文件头不完整")
        hdr = self.parse_header(head + rest)
        if not bytes_equal(hdr["volumeId"], volume_id):
            raise PQError("此文件属于另一个加密卷", "FOREIGN_VOLUME")
        enc_key, commit = self.volume_file_derive(vmk, volume_id, hdr["salt"])
        if not bytes_equal(commit, hdr["commit"]):
            raise PQError("卷主密钥与此文件不匹配：文件已损坏 / 被篡改。", "KEY_MISMATCH")
        return hdr, enc_key

    def decrypt_volume_stream(self, vmk, volume_id, reader, sink, cancel=None, on_progress=None):
        hdr, enc_key = self.open_volume_stream(vmk, volume_id, reader)
        return self.decrypt_stream_to(enc_key, hdr["raw"], reader, sink, cancel, on_progress)

    def encrypt_volume_bytes(self, vmk, volume_id, data):
        sink = BytesSink()
        self.encrypt_volume_stream(vmk, volume_id, _MemReader(data), sink)
        return sink.getvalue()

    def decrypt_volume_bytes(self, vmk, volume_id, data):
        sink = BytesSink()
        self.decrypt_volume_stream(vmk, volume_id, ByteReader(_MemReader(data)), sink)
        return sink.getvalue()

    @staticmethod
    def volume_ciphertext_length(n):
        blocks = max(1, -(-n // CHUNK_SIZE))
        return VOLUME_HDR_LEN + n + blocks * (4 + TAG_LEN)

    # ---- startup self-test -------------------------------------------------------------------
    def self_test(self, argon2_params=None):
        ap = argon2_params or SELFTEST_ARGON
        T = "pqfilecrypt self-test ✔ 自检".encode("utf-8")
        r1, r2 = random_bytes(32), random_bytes(32)
        if bytes_equal(r1, r2):
            raise PQError("RNG 两次输出相同")
        if not any(r1):
            raise PQError("RNG 输出全零")

        kpk, ksk = self.mlkem.keygen()
        if len(kpk) != MLKEM1024_PK_LEN or len(ksk) != MLKEM1024_SK_LEN:
            raise PQError("ML-KEM 公/私钥长度不符（非 ML-KEM-1024）")
        ct, ss = self.mlkem.encapsulate(kpk)
        if len(ct) != MLKEM1024_CT_LEN or len(ss) != KEY_LEN:
            raise PQError("ML-KEM 密文/共享密钥长度异常")
        if not bytes_equal(ss, self.mlkem.decapsulate(ct, ksk)):
            raise PQError("ML-KEM 封装/解封共享密钥不一致")

        kp = self.generate_keypair()
        c = self.encrypt_hybrid(kp["pub"], T)
        if not bytes_equal(self.decrypt(c, key_obj=kp["key"])["plaintext"], T):
            raise PQError("混合模式往返结果不匹配")
        bad = bytearray(c)
        bad[-1] ^= 0xFF
        try:
            self.decrypt(bytes(bad), key_obj=kp["key"])
            raise PQError("混合模式未能拒绝被篡改的密文")
        except Exception as e:
            if isinstance(e, PQError) and "未能拒绝" in str(e):
                raise
        cont = self.wrap_secret_key(kp["key"], "self-test", ap)
        un = self.unwrap_secret_key(cont, "self-test")
        if un["x25519_priv"] != kp["key"]["x25519_priv"] or un["mlkem_secret"] != kp["key"]["mlkem_secret"]:
            raise PQError("私钥容器封装/解封不一致")

        if self.mldsa is not None:
            L = self.mldsa.lengths
            if L["publicKey"] != MLDSA87_PK_LEN or L["secretKey"] != MLDSA87_SK_LEN or L["signature"] != MLDSA87_SIG_LEN:
                raise PQError("ML-DSA 参数集长度不符（非 ML-DSA-87）")
            dpk, dsk = self.mldsa.keygen()
            dm = "pqfilecrypt sign self-test ✔".encode("utf-8")
            ds = self.mldsa.sign(dm, dsk)
            if len(ds) != MLDSA87_SIG_LEN:
                raise PQError("ML-DSA 签名长度异常")
            if not self.mldsa.verify(ds, dm, dpk):
                raise PQError("ML-DSA 签名往返验证失败")
            dbad = bytearray(ds)
            dbad[0] ^= 0xFF
            if self.mldsa.verify(bytes(dbad), dm, dpk):
                raise PQError("ML-DSA 未能拒绝被篡改的签名")
            sct = self.encrypt_hybrid_signed(kp["pub"], T, kp["key"])
            sres = self.decrypt(sct, key_obj=kp["key"])
            if not sres["signed"] or not bytes_equal(sres["plaintext"], T):
                raise PQError("签名模式端到端往返 / 验签失败")
            if sres["signerPublicKey"] != kp["key"]["mldsa_pub"]:
                raise PQError("验签返回的发件人公钥与预期不一致")
            sbad = bytearray(sct)
            sbad[-1] ^= 0xFF
            try:
                self.decrypt(bytes(sbad), key_obj=kp["key"])
                raise PQError("签名模式未能拒绝被篡改的密文")
            except Exception as e:
                if isinstance(e, PQError) and "未能拒绝" in str(e):
                    raise

        ctp = self.encrypt_password("self-test-pw", T, ap)
        if not bytes_equal(self.decrypt(ctp, password="self-test-pw")["plaintext"], T):
            raise PQError("口令模式往返结果不匹配")
        try:
            self.decrypt(ctp, password="wrong-pw")
            raise PQError("口令模式未能拒绝错误口令")
        except PQError as e:
            if e.code != "BAD_PASSWORD":
                raise

        vol = self.new_volume(hide_names=True, label="self-test")
        self.add_password_slot(vol["header"], vol["vmk"], "vol-pw", ap)
        owner = self.generate_keypair()
        self.add_pubkey_slot(vol["header"], vol["vmk"], owner["pub"])
        self.validate_volume_header(vol["header"])
        u1 = self.unlock_volume(vol["header"], password="vol-pw")
        if not bytes_equal(u1["vmk"], vol["vmk"]) or u1["slotIndex"] != 0:
            raise PQError("卷口令槽解锁结果不一致")
        u2 = self.unlock_volume(vol["header"], key_obj=owner["key"])
        if not bytes_equal(u2["vmk"], vol["vmk"]) or u2["slotIndex"] != 1:
            raise PQError("卷公钥槽解锁结果不一致")
        for kw in ({"password": "wrong"}, {"key_obj": self.generate_keypair()["key"]}):
            try:
                self.unlock_volume(vol["header"], **kw)
                raise PQError("卷模式未能拒绝错误口令 / 不匹配的私钥")
            except PQError as e:
                if e.code not in ("BAD_PASSWORD", "KEY_MISMATCH"):
                    raise
        big = bytes((i * 31) & 0xFF for i in range(CHUNK_SIZE + 7))
        ctv = self.encrypt_volume_bytes(vol["vmk"], vol["volumeId"], big)
        if not bytes_equal(self.decrypt_volume_bytes(vol["vmk"], vol["volumeId"], ctv), big):
            raise PQError("卷模式往返不一致")
        if len(ctv) != self.volume_ciphertext_length(len(big)):
            raise PQError("卷模式密文长度估算与实际不符")
        ct0 = self.encrypt_volume_bytes(vol["vmk"], vol["volumeId"], b"")
        if self.decrypt_volume_bytes(vol["vmk"], vol["volumeId"], ct0) != b"":
            raise PQError("卷模式空文件往返失败")
        badv = bytearray(ctv)
        badv[-1] ^= 0xFF
        for data in (bytes(badv), ctv[:-3]):
            try:
                self.decrypt_volume_bytes(vol["vmk"], vol["volumeId"], data)
                raise PQError("卷模式未能拒绝被篡改 / 截断的密文")
            except Exception as e:
                if isinstance(e, PQError) and "未能拒绝" in str(e):
                    raise
        other = self.new_volume()
        try:
            self.decrypt_volume_bytes(other["vmk"], other["volumeId"], ctv)
            raise PQError("卷模式未能识别属于别的卷的文件")
        except PQError as e:
            if e.code != "FOREIGN_VOLUME":
                raise
        try:
            self.decrypt_volume_bytes(other["vmk"], vol["volumeId"], ctv)
            raise PQError("卷模式未能拒绝错误的卷主密钥")
        except PQError as e:
            if e.code != "KEY_MISMATCH":
                raise
        wipe(vol["vmk"], u1["vmk"], u2["vmk"], other["vmk"])
        return True


class _MemReader:
    def __init__(self, data):
        self.data = bytes(data)
        self.pos = 0

    def read(self, n=-1):
        if n is None or n < 0:
            n = len(self.data) - self.pos
        out = self.data[self.pos:self.pos + n]
        self.pos += len(out)
        return out


# ---------------------------------------------------------------------------
# Password hygiene (heuristic, same rules as pqcore.js)
# ---------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "p@ssw0rd", "123456", "1234567", "12345678",
    "123456789", "1234567890", "12345678910", "qwerty", "qwerty123", "qwertyuiop", "abc123", "abcd1234",
    "111111", "11111111", "000000", "00000000", "88888888", "66666666", "123123", "123321", "654321",
    "1q2w3e4r", "1qaz2wsx", "zxcvbnm", "asdfgh", "asdfghjkl", "iloveyou", "admin", "admin123", "root",
    "letmein", "welcome", "monkey", "dragon", "sunshine", "princess", "football", "baseball", "master",
    "hello", "freedom", "whatever", "trustno1", "woaini", "woaini1314", "5201314", "1314520", "a123456",
    "123456a", "a12345678", "123456abc", "aa123456", "qq123456", "7758521", "1234qwer", "12qwaszx",
}
WEAK_FRAGMENTS = ["qwerty", "asdf", "zxcv", "1qaz", "2wsx", "password", "admin", "letmein", "iloveyou", "woaini", "1314", "520", "abc123", "123456"]


def normalize_password(pw):
    return unicodedata.normalize("NFC", str(pw if pw is not None else ""))


def password_hints(pw):
    s = str(pw if pw is not None else "")
    hints = []
    if s and (s[0].isspace() or s[-1].isspace()):
        hints.append("口令首尾含空白字符，跨设备输入时极易遗漏")
    if any("\uFF01" <= ch <= "\uFF5E" or ch == "\u3000" for ch in s):
        hints.append("含全角字符（可能是输入法处于全角模式），请确认是有意为之")
    if unicodedata.normalize("NFC", s) != s:
        hints.append("口令含组合字符，已按 Unicode NFC 统一表示以免跨设备无法解密")
    return hints


def password_strength(pw):
    import math
    s = normalize_password(pw)
    chars = list(s)
    res = {"length": len(chars), "bits": 0, "score": 0, "label": "—", "blocked": False, "reason": "", "warnings": []}
    if not chars:
        res["blocked"] = True
        res["reason"] = "口令不能为空"
        return res
    lower = upper = digit = symbol = other = 0
    for ch in chars:
        c = ord(ch)
        if 0x61 <= c <= 0x7A:
            lower += 1
        elif 0x41 <= c <= 0x5A:
            upper += 1
        elif 0x30 <= c <= 0x39:
            digit += 1
        elif c < 0x80:
            symbol += 1
        else:
            other += 1
    pool = (26 if lower else 0) + (26 if upper else 0) + (10 if digit else 0) + (33 if symbol else 0)
    ascii_n = lower + upper + digit + symbol
    bits = ascii_n * math.log2(pool) if ascii_n else 0.0
    bits += other * 7
    runs = 0
    for i in range(1, len(chars)):
        a, b = ord(chars[i - 1]), ord(chars[i])
        if b == a or b == a + 1 or b == a - 1:
            runs += 1
    bits -= runs * 3
    low = s.lower()
    for f in WEAK_FRAGMENTS:
        if f in low:
            bits -= 10
    uniq = len(set(chars))
    if uniq <= 2:
        bits = min(bits, 10)
    elif uniq <= 4:
        bits = min(bits, 24)
    bits = max(0, int(math.floor(bits + 0.5)))
    res["bits"] = bits
    if low in COMMON_PASSWORDS or re.sub(r"[^a-z0-9@]", "", low) in COMMON_PASSWORDS:
        res["blocked"] = True
        res["reason"] = "这是公开泄露榜单上的极常见口令，会被瞬间猜中"
    elif len(chars) < 8:
        res["blocked"] = True
        res["reason"] = "口令至少需要 8 个字符（推荐 12 个以上，或使用随机生成的口令）"
    if bits < 28:
        res["score"], res["label"] = 0, "很弱"
    elif bits < 40:
        res["score"], res["label"] = 1, "弱"
    elif bits < 60:
        res["score"], res["label"] = 2, "一般"
    elif bits < 80:
        res["score"], res["label"] = 3, "较强"
    else:
        res["score"], res["label"] = 4, "强"
    if ascii_n and not other and digit == ascii_n:
        res["warnings"].append("纯数字口令（生日 / 手机号类）极易被穷举")
    if lower and not upper and not digit and not symbol and not other and len(chars) < 16:
        res["warnings"].append("仅小写字母且较短，建议加长或混入其它字符")
    res["warnings"].extend(password_hints(pw))
    return res


def fmt_kib(kib):
    try:
        k = int(kib)
    except Exception:
        k = 0
    return "%d KiB" % k if k < 1024 else "%d MiB" % int(round(k / 1024))


def kdf_cost_exceeds_default(t, m_kib, p):
    try:
        mem, tc, par = int(m_kib or 0), int(t or 0), int(p or 0)
    except Exception:
        mem = tc = par = 0
    if mem > 2 * ARGON_MEM_KIB or tc > 2 * ARGON_TIME or par > 2 * ARGON_PAR:
        return ("此文件声明的口令派生参数为 内存 %s / t=%d / p=%d，明显高于本工具默认值（%s / t=%d / p=%d）。"
                "这些参数由文件本身决定，可能是对方刻意设置，也可能是恶意文件试图让程序长时间卡死或内存耗尽。"
                % (fmt_kib(mem), tc, par, fmt_kib(ARGON_MEM_KIB), ARGON_TIME, ARGON_PAR))
    return None


# ---------------------------------------------------------------------------
# Directory-tree engine on the real filesystem (same layout and rules as pqvolume.js)
#   root/.pqvolume        volume header (JSON)
#   <name>.pqfc           normal mode: encrypted in place, names visible
#   <16-hex-id>.pqfc      hidden-name mode: files and directories renamed to random ids
#   <id>/.pqdir           per-directory encrypted manifest (id -> original name)
# Per file: write temp -> fsync -> re-read and verify (optional) -> atomic replace -> delete original.
# ---------------------------------------------------------------------------
VOLUME_HEADER_NAME = ".pqvolume"


def _is_volume_header_name(name):
    """Match the reserved volume-header name on case-sensitive filesystems too."""
    return isinstance(name, str) and name.casefold() == VOLUME_HEADER_NAME.casefold()


def _volume_header_path(root):
    """Return the on-disk header path, tolerating a case-only rename."""
    _check_path(root)
    path = os.path.join(root, VOLUME_HEADER_NAME)
    try:
        os.lstat(path)
        return path
    except FileNotFoundError:
        pass
    matches = [name for name in os.listdir(root) if _is_volume_header_name(name)]
    if len(matches) > 1:
        raise PQError("目录内有多个大小写不同的卷头，请明确选择要使用的卷头", "AMBIGUOUS_HEADER")
    if matches:
        return os.path.join(root, matches[0])
    return path


DIR_MANIFEST_NAME = ".pqdir"
ENC_EXT = ".pqfc"
TMP_PREFIX = ".pqdisk.tmp."
LOCK_NAME = ".pqdisk.lock"
ID_BYTES = 8
SYSTEM_DIRS = {
    "System Volume Information", "$RECYCLE.BIN", "$Recycle.Bin", "Recovery",
    ".Spotlight-V100", ".fseventsd", ".Trashes", ".TemporaryItems", ".DocumentRevisions-V100",
    "lost+found",
}


def _join(base, name):
    return base + "/" + name if base else name


def _is_link(entry):
    try:
        # Windows DirEntry.stat() may report st_nlink=0; lstat queries the file.
        st = os.lstat(entry.path)
        return _is_reparse(st) or (stat.S_ISREG(st.st_mode) and st.st_nlink != 1)
    except OSError:
        return True


def _is_reparse(st):
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)


def _check_path(path, missing=False):
    """Reject links/reparse points in every existing component, including the root."""
    path = os.path.abspath(path)
    parts = []
    current = path
    while True:
        parts.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    leaf = None
    for part in reversed(parts):
        try:
            st = os.lstat(part)
        except FileNotFoundError:
            if missing and part == path:
                return None
            raise
        if _is_reparse(st):
            raise PQError("拒绝符号链接、联接点或重解析点：" + part, "UNSAFE_PATH")
        if part != path and not stat.S_ISDIR(st.st_mode):
            raise PQError("Path parent is not a directory", "UNSAFE_PATH")
        leaf = st
    return leaf


def _regular(st):
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise PQError("拒绝特殊文件或硬链接文件", "UNSAFE_PATH")


def _component(name):
    if (not isinstance(name, str) or not name or name in (".", "..")
            or any(ord(c) < 32 or c in '/\\:<>"|?*' for c in name)
            or name.endswith((".", " ")) or len(name.encode("utf-8")) > 255):
        raise PQError("目录清单包含不安全或不可移植的文件名", "UNSAFE_PATH")
    folded = name.casefold()
    device = folded.split(".")[0]
    if (device in {"con", "prn", "aux", "nul", "clock$", "conin$", "conout$"}
            or re.fullmatch(r"(?:com|lpt)[1-9¹²³]", device)
            or folded in {VOLUME_HEADER_NAME, DIR_MANIFEST_NAME, LOCK_NAME}
            or folded.startswith(TMP_PREFIX)):
        raise PQError("目录清单包含保留文件名", "UNSAFE_PATH")
    return name


def _validate_manifest(m, dir_id):
    if (not isinstance(m, dict) or type(m.get("v")) is not int or m["v"] != 1
            or m.get("dir") != dir_id or not isinstance(m.get("entries"), dict)
            or len(m["entries"]) > 50000):
        raise PQError("目录清单格式或目录 ID 异常", "INVALID_MANIFEST")
    names = set()
    for ident, ent in m["entries"].items():
        if (not isinstance(ident, str) or re.fullmatch(r"[0-9a-f]{16}", ident) is None
                or not isinstance(ent, dict) or set(ent) != {"n", "t"}
                or ent["t"] not in ("f", "d")):
            raise PQError("目录清单条目异常", "INVALID_MANIFEST")
        name = _component(ent["n"])
        key = (ent["t"], unicodedata.normalize("NFC", name).casefold())
        if key in names:
            raise PQError("目录清单含重复或大小写冲突的文件名", "INVALID_MANIFEST")
        names.add(key)
    return m


def _windows_open(path, create=False, lock=False):
    import ctypes as c
    from ctypes import wintypes as w
    import msvcrt
    kernel = c.WinDLL("kernel32", use_last_error=True)
    advapi = c.WinDLL("advapi32", use_last_error=True)
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.LocalFree.argtypes = [c.c_void_p]
    kernel.GetCurrentProcess.restype = w.HANDLE
    sd = c.c_void_p()
    sa = None
    if create:
        class SecurityAttributes(c.Structure):
            _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]
        token = w.HANDLE()
        advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
        advapi.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
        advapi.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p]
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token)):
            raise c.WinError(c.get_last_error())
        sid_text = w.LPWSTR()
        try:
            size = w.DWORD()
            advapi.GetTokenInformation(token, 1, None, 0, c.byref(size))
            buf = c.create_string_buffer(size.value)
            if not advapi.GetTokenInformation(token, 1, buf, size, c.byref(size)):
                raise c.WinError(c.get_last_error())
            sid = c.cast(buf, c.POINTER(c.c_void_p))[0]
            if not advapi.ConvertSidToStringSidW(sid, c.byref(sid_text)):
                raise c.WinError(c.get_last_error())
            sddl = "D:P(A;;FA;;;SY)(A;;FA;;;%s)" % sid_text.value
            if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(sd), None):
                raise c.WinError(c.get_last_error())
            sa = SecurityAttributes(c.sizeof(SecurityAttributes), sd, False)
        finally:
            if sid_text:
                kernel.LocalFree(c.cast(sid_text, c.c_void_p))
            kernel.CloseHandle(token)
    try:
        access = 0xC0000000 if create or lock else 0x80000000
        handle = kernel.CreateFileW(path, access, 3 if lock else 1,
                                    c.byref(sa) if sa else None, 1 if create else 3, 0x200080, None)
        if handle == w.HANDLE(-1).value:
            raise c.WinError(c.get_last_error())
        try:
            return msvcrt.open_osfhandle(handle, os.O_BINARY | (os.O_RDWR if create or lock else os.O_RDONLY))
        except BaseException:
            kernel.CloseHandle(handle)
            raise
    finally:
        if sd:
            kernel.LocalFree(sd)


@contextmanager
def _read_regular(path):
    before = _check_path(path)
    _regular(before)
    fd = (_windows_open(os.path.abspath(path)) if os.name == "nt" else
          os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)))
    with os.fdopen(fd, "rb") as f:
        opened = os.fstat(f.fileno())
        _regular(opened)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise PQError("File changed while opening", "SOURCE_CHANGED")
        _check_path(path)
        yield f


def _new_temp(directory):
    _check_path(directory)
    for _ in range(32):
        path = os.path.join(directory, TMP_PREFIX + random_bytes(16).hex())
        try:
            fd = (_windows_open(os.path.abspath(path), create=True) if os.name == "nt" else
                  os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600))
        except FileExistsError:
            continue
        return path, os.fdopen(fd, "w+b")
    raise PQError("Unable to allocate an exclusive temporary file")


def _stamp(st):
    # On Windows fstat/lstat disagree about ctime (change time vs creation time).
    change_time = st.st_ctime_ns if os.name != "nt" else None
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, change_time, st.st_nlink


def _unchanged(path, expected):
    current = _check_path(path)
    _regular(current)
    if _stamp(current) != _stamp(expected):
        raise PQError("源文件在处理期间发生变化，已保留原件", "SOURCE_CHANGED")


def _sync_directory(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _publish(src, dst, replace=False):
    _check_path(src)
    existing = _check_path(dst, missing=True)
    if existing is not None:
        if not replace:
            raise FileExistsError("目标已存在，未覆盖：" + dst)
        _regular(existing)
    if os.name == "nt":
        import ctypes as c
        from ctypes import wintypes as w
        kernel = c.WinDLL("kernel32", use_last_error=True)
        kernel.MoveFileExW.argtypes = [w.LPCWSTR, w.LPCWSTR, w.DWORD]
        if not kernel.MoveFileExW(os.path.abspath(src), os.path.abspath(dst), 8 | (1 if replace else 0)):
            raise c.WinError(c.get_last_error())
    elif replace:
        os.replace(src, dst)
    else:
        os.link(src, dst, follow_symlinks=False)
        os.unlink(src)
    _sync_directory(os.path.dirname(dst) or ".")


def _rename_directory(src, dst):
    _check_path(src)
    if _check_path(dst, missing=True) is not None:
        raise FileExistsError("Destination directory exists")
    if os.name == "nt":
        _publish(src, dst)
        return
    import ctypes as c
    libc = c.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        fn = libc.renameat2
        fn.argtypes = [c.c_int, c.c_char_p, c.c_int, c.c_char_p, c.c_uint]
        result = fn(-100, os.fsencode(src), -100, os.fsencode(dst), 1)
    elif sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        fn = libc.renamex_np
        fn.argtypes = [c.c_char_p, c.c_char_p, c.c_uint]
        result = fn(os.fsencode(src), os.fsencode(dst), 4)
    else:
        raise PQError("Atomic non-overwriting directory rename is unavailable")
    if result != 0:
        raise OSError(c.get_errno(), "Directory rename failed", src)
    _sync_directory(os.path.dirname(dst) or ".")


_LOCK_STATE = threading.local()


@contextmanager
def _volume_lock(root):
    _check_path(root)
    key = os.path.normcase(os.path.abspath(root))
    active = getattr(_LOCK_STATE, "active", set())
    if key in active:
        yield
        return
    path = os.path.join(root, LOCK_NAME)
    st = _check_path(path, missing=True)
    if st is not None:
        _regular(st)
        if st.st_size > 1:
            raise PQError("Reserved lock filename is occupied", "VOLUME_BUSY")
    try:
        if os.name == "nt":
            try:
                fd = _windows_open(os.path.abspath(path), create=True, lock=True)
            except FileExistsError:
                fd = _windows_open(os.path.abspath(path), lock=True)
        else:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        f = os.fdopen(fd, "r+b", buffering=0)
    except OSError as e:
        raise PQError("Cannot open the volume lock", "VOLUME_BUSY") from e
    locked = False
    try:
        _regular(os.fstat(f.fileno()))
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as e:
            raise PQError("该卷正被另一实例使用，未执行写入", "VOLUME_BUSY") from e
        _LOCK_STATE.active = active | {key}
        yield
    finally:
        _LOCK_STATE.active = active
        if locked:
            if os.name == "nt":
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        f.close()


def _locked(method):
    @wraps(method)
    def wrapper(self, root, *args, **kwargs):
        with _volume_lock(root):
            return method(self, root, *args, **kwargs)
    return wrapper


class _HashIO:
    def __init__(self, source=None):
        self.source = source
        self.digest = hashlib.sha256()

    def read(self, n):
        data = self.source.read(n)
        self.digest.update(data)
        return data

    def write(self, data):
        self.digest.update(data)


def _remove_file(path):
    _regular(_check_path(path))
    os.remove(path)
    _sync_directory(os.path.dirname(path) or ".")


def _fsync_file(f):
    f.flush()
    os.fsync(f.fileno())


class BufferedSink:
    def __init__(self, f, limit=1 << 20):
        self.f = f
        self.limit = limit
        self.parts = []
        self.n = 0

    def write(self, b):
        self.parts.append(bytes(b))
        self.n += len(b)
        if self.n >= self.limit:
            self.flush()

    def flush(self):
        if self.n:
            self.f.write(b"".join(self.parts))
            self.parts = []
            self.n = 0


class VolumeFS:
    def __init__(self, pq):
        self.pq = pq

    # ---- small helpers ----------------------------------------------------------
    @staticmethod
    def list_entries(path):
        _check_path(path)
        out = []
        with os.scandir(path) as it:
            for e in it:
                if _is_link(e):
                    kind = "link"
                elif e.is_dir(follow_symlinks=False):
                    kind = "directory"
                elif e.is_file(follow_symlinks=False):
                    kind = "file"
                else:
                    kind = "other"
                out.append((e.name, kind))
        order = {"file": 0, "directory": 1, "link": 2, "other": 3}
        out.sort(key=lambda t: (order[t[1]], t[0]))
        return out

    @staticmethod
    def exists_kind(path):
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        if _is_reparse(st) or (stat.S_ISREG(st.st_mode) and st.st_nlink != 1):
            return "link"
        if stat.S_ISDIR(st.st_mode):
            return "directory"
        return "file"

    @staticmethod
    def read_file_bytes(path, limit=MAX_SINGLE_FILE_BYTES):
        with _read_regular(path) as f:
            if os.fstat(f.fileno()).st_size > limit:
                raise PQError("文件超过当前操作的大小上限；大文件请使用卷模式", "INPUT_LIMIT")
            data = f.read(limit + 1)
            if len(data) > limit:
                raise PQError("File exceeds the input limit", "INPUT_LIMIT")
            return data

    @staticmethod
    def write_file_bytes(path, data, replace=True):
        d = os.path.dirname(path) or "."
        existing = _check_path(path, missing=True)
        if existing is not None:
            _regular(existing)
        tmp, f = _new_temp(d)
        try:
            with f:
                f.write(data)
                _fsync_file(f)
            _publish(tmp, path, replace=replace)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise

    def probe_file(self, path):
        with _read_regular(path) as f:
            head = f.read(VOLUME_HDR_LEN)
            size = os.fstat(f.fileno()).st_size
        return {"size": size, "probe": self.pq.probe_header(head), "hasMagic": head.startswith(MAGIC)}

    def _is_ours(self, path, volume_id):
        try:
            p = self.probe_file(path)["probe"]
        except OSError:
            return False
        return bool(p["ok"] and p["volumeId"] is not None and volume_id is not None and bytes_equal(p["volumeId"], volume_id))

    # ---- volume header ---------------------------------------------------------------
    def read_header_file(self, path):
        # Preserve access/path errors; they do not mean that the header is missing.
        raw = self.read_file_bytes(path, MAX_JSON_BYTES)
        try:
            obj = strict_json(raw)
        except PQError as e:
            raise PQError("卷头文件 %s 不是有效 JSON（可用备份恢复）" % os.path.basename(path), e.code) from e
        self.pq.validate_volume_header(obj)
        return obj

    def read_volume_header(self, root):
        path = _volume_header_path(root)
        try:
            os.lstat(path)
        except FileNotFoundError:
            return None
        return self.read_header_file(path)

    def header_status(self, root):
        """('none' | 'ok' | 'invalid', header or None, error text or None) without raising."""
        try:
            header = self.read_volume_header(root)
            return ("ok", header, None) if header is not None else ("none", None, None)
        except Exception as e:
            return "invalid", None, str(e)

    def find_header_candidates(self, root):
        """Read only header-like files in this directory; never descend or write."""
        names = [name for name, kind in self.list_entries(root)
                 if not _is_volume_header_name(name)
                 and name.casefold().endswith((".pqvolume", ".pqvolume.txt", ".pqvolume.json"))]
        if len(names) > 32:
            raise PQError("目录内卷头候选超过 32 个，请用“载入卷头文件”明确选择", "INPUT_LIMIT")
        candidates = []
        for name in names:
            path = os.path.join(root, name)
            try:
                candidates.append({"path": path, "header": self.read_header_file(path), "error": None})
            except Exception as e:
                candidates.append({"path": path, "header": None, "error": str(e)})
        return candidates

    def _is_header_backup(self, root, name):
        """Recognized root-level recovery headers are metadata, not plaintext."""
        if not name.casefold().endswith((".pqvolume", ".pqvolume.txt", ".pqvolume.json")):
            return False
        try:
            self.read_header_file(os.path.join(root, name))
            return True
        except (OSError, PQError):
            return False

    def parent_header_hint(self, root):
        """Suggest the nearest ancestor with a canonical header; never change scope."""
        current = os.path.abspath(root)
        while True:
            parent = os.path.dirname(current)
            if parent == current:
                return None
            current = parent
            path = os.path.join(current, VOLUME_HEADER_NAME)
            try:
                os.lstat(path)
            except FileNotFoundError:
                continue
            except OSError:
                return None
            return path

    @_locked
    def write_volume_header(self, root, header, replace=True):
        self.pq.validate_volume_header(header)
        data = header_json(header).encode("utf-8")
        if len(data) > MAX_JSON_BYTES:
            raise PQError("Volume header exceeds the size limit", "INPUT_LIMIT")
        self.write_file_bytes(_volume_header_path(root), data, replace=replace)

    def can_start_new_volume(self, root):
        """Require a complete, readable plaintext tree before replacing a volume."""
        try:
            report = self.diagnose_tree(root)
            blocked = ("密文", "损坏", "无法", "残留", "目录清单", "链接", "跳过")
            if any(any(word in kind for word in blocked) for kind in report["counts"]):
                return False
            # Diagnostics reserve the legacy root header name. Its contents may
            # nevertheless be ciphertext renamed by another application.
            for name, kind in self.list_entries(root):
                if not _is_volume_header_name(name):
                    continue
                if kind != "file":
                    return False
                self.read_header_file(os.path.join(root, name))
            return True
        except (OSError, PQError):
            return False

    @_locked
    def save_encryption_header(self, root, header, destination, previous_header=None):
        """Save exactly the selected header; replace only a safely retired volume."""
        self.pq.validate_volume_header(header)
        data = header_json(header).encode("utf-8")
        if len(data) > MAX_JSON_BYTES:
            raise PQError("Volume header exceeds the size limit", "INPUT_LIMIT")
        destination = os.path.abspath(os.fsdecode(destination))
        name = os.path.basename(destination)
        if not _is_volume_header_name(name):
            _component(name)
        previous_id = None
        if previous_header is not None:
            previous_id = self.pq.validate_volume_header(previous_header)["volumeId"]
        stamp = _check_path(destination, missing=True)
        original = None
        if stamp is not None:
            _regular(stamp)
            original = self.read_file_bytes(destination, MAX_JSON_BYTES)
            existing = strict_json(original)
            existing_id = self.pq.validate_volume_header(existing)["volumeId"]
            _unchanged(destination, stamp)
            if previous_id is None or not bytes_equal(existing_id, previous_id):
                raise PQError("所选位置已有其它文件或其它卷的卷头，未覆盖；请选择新的保存位置", "OUTPUT_EXISTS")
        if previous_id is not None and not self.can_start_new_volume(root):
            raise PQError("目录仍有密文、残留清单或无法确认的文件，不能替换旧卷头", "VOLUME_NOT_EMPTY")
        if stamp is not None:
            _unchanged(destination, stamp)
            if self.read_file_bytes(destination, MAX_JSON_BYTES) != original:
                raise PQError("卷头在检查期间发生变化，未覆盖", "SOURCE_CHANGED")
            _unchanged(destination, stamp)
        self.write_file_bytes(destination, data, replace=stamp is not None)
        return destination

    # ---- hidden-name manifests -----------------------------------------------------------
    def _load_manifest(self, dirpath, dir_id, ctx):
        path = os.path.join(dirpath, DIR_MANIFEST_NAME)
        if not os.path.lexists(path):
            return None
        pt = self.pq.decrypt_volume_bytes(ctx["vmk"], ctx["volumeId"], self.read_file_bytes(path, MAX_MANIFEST_BYTES))
        try:
            m = strict_json(pt, MAX_MANIFEST_BYTES)
        except Exception:
            raise PQError("目录清单解密后不是有效 JSON")
        if not isinstance(m, dict) or m.get("v") != 1 or not isinstance(m.get("dir"), str) or not isinstance(m.get("entries"), dict):
            raise PQError("目录清单格式异常")
        if m["dir"] != dir_id:
            raise PQError("目录清单与所在目录不匹配（清单可能被移动 / 调换）")
        return _validate_manifest(m, dir_id)

    def _save_manifest(self, dirpath, dir_id, entries, ctx):
        _validate_manifest({"v": 1, "dir": dir_id, "entries": entries}, dir_id)
        pt = json.dumps({"v": 1, "dir": dir_id, "entries": entries}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if self.pq.volume_ciphertext_length(len(pt)) > MAX_MANIFEST_BYTES:
            raise PQError("Directory manifest exceeds the size limit", "INPUT_LIMIT")
        self.write_file_bytes(os.path.join(dirpath, DIR_MANIFEST_NAME), self.pq.encrypt_volume_bytes(ctx["vmk"], ctx["volumeId"], pt))

    @staticmethod
    def _new_id(taken):
        while True:
            i = hexs(random_bytes(ID_BYTES))
            if i not in taken:
                taken.add(i)
                return i

    # ---- scan (read-only) -------------------------------------------------------------------
    def scan_tree(self, root, volume_id=None, cancel=None, header_path=None):
        _check_path(root)
        header_key = os.path.normcase(os.path.abspath(header_path)) if header_path is not None else None
        st = {"files": 0, "bytes": 0, "dirs": 0, "encrypted": 0, "encryptedBytes": 0, "foreign": 0,
              "skippedDirs": [], "links": 0, "largest": 0, "tmpLeft": 0,
              "foreignVolumes": {}, "volumeIds": {}, "nestedHeaders": [],
              "singleMode": 0, "notContainer": 0, "unreadable": [], "damaged": []}

        def walk(dirpath, rel, is_root):
            _check_cancel(cancel)
            try:
                entries = self.list_entries(dirpath)
            except OSError as e:
                st["skippedDirs"].append(rel or "(根)")
                return
            for name, kind in entries:
                if name == LOCK_NAME:
                    continue
                full = os.path.join(dirpath, name)
                if header_key is not None and os.path.normcase(os.path.abspath(full)) == header_key:
                    continue
                if kind == "directory":
                    if is_root and name in SYSTEM_DIRS:
                        st["skippedDirs"].append(name)
                        continue
                    st["dirs"] += 1
                    walk(full, _join(rel, name), False)
                    continue
                if kind in ("link", "other"):
                    st["links"] += 1
                    continue
                if is_root and (_is_volume_header_name(name) or self._is_header_backup(dirpath, name)):
                    continue
                if not is_root and _is_volume_header_name(name):
                    st["nestedHeaders"].append(os.path.join(dirpath, name))
                if name == DIR_MANIFEST_NAME:
                    continue
                if name.startswith(TMP_PREFIX):
                    st["tmpLeft"] += 1
                    continue
                if name.endswith(ENC_EXT):
                    try:
                        info = self.probe_file(full)
                    except OSError as e:
                        st["unreadable"].append(_join(rel, name) + "（" + _errstr(e) + "）")
                        continue
                    size = info["size"]
                    p = info["probe"]
                    if p["ok"] and p["volumeId"] is not None:
                        full_id = hexs(p["volumeId"])
                        st["volumeIds"][full_id] = st["volumeIds"].get(full_id, 0) + 1
                    if p["ok"] and p["volumeId"] is not None and volume_id is not None and bytes_equal(p["volumeId"], volume_id):
                        st["encrypted"] += 1
                        st["encryptedBytes"] += size
                        continue
                    if p["ok"]:
                        st["foreign"] += 1
                        if p["volumeId"] is not None:
                            k = hexs(p["volumeId"])[:12]
                            st["foreignVolumes"][k] = st["foreignVolumes"].get(k, 0) + 1
                        elif p["version"] == VERSION and p["mode"] == MODE_VOLUME:
                            st["damaged"].append(_join(rel, name))
                        else:
                            st["singleMode"] += 1
                        continue
                    st["notContainer"] += 1
                else:
                    try:
                        size = os.path.getsize(full)
                    except OSError:
                        continue
                st["files"] += 1
                st["bytes"] += size
                if size > st["largest"]:
                    st["largest"] = size
        walk(root, "", True)
        try:
            st["free"] = shutil.disk_usage(root).free
        except OSError:
            st["free"] = None
        return st

    # ---- encrypt whole tree ---------------------------------------------------------------------
    @_locked
    def encrypt_tree(self, root, ctx, keep_originals=False, verify=True, on_event=None, cancel=None, header_path=None):
        header = self.read_header_file(header_path) if header_path is not None else self.read_volume_header(root)
        header_key = os.path.normcase(os.path.abspath(header_path)) if header_path is not None else None
        if (not header or not bytes_equal(b64decode(header["volume_id"]), ctx["volumeId"])
                or header["hide_names"] != ctx["hideNames"]):
            raise PQError("卷头已变化或与当前上下文不匹配，未开始加密", "VOLUME_CHANGED")
        keep = bool(keep_originals)
        verify = bool(verify) or not keep
        pq = self.pq
        res = {"files": 0, "bytes": 0, "skipped": 0, "foreign": 0, "reused": 0, "errors": [], "cancelled": False}

        def emit(ev):
            if on_event:
                on_event(ev)

        def progress(n):
            emit({"type": "progress", "bytes": n})

        def reuse_existing(src, out, rel_path):
            emit({"type": "verify-start", "path": rel_path})
            verified = _HashIO()
            # Keep the verified ciphertext open until any redundant plaintext is removed.
            with _read_regular(out) as encrypted:
                out_st = os.fstat(encrypted.fileno())
                try:
                    result = pq.decrypt_volume_stream(ctx["vmk"], ctx["volumeId"], ByteReader(encrypted),
                                                      verified, cancel, progress)
                except PQError as e:
                    if e.code == "ABORTED":
                        raise
                    raise PQError("已有目标未通过本卷密文认证，未覆盖，原文件已保留", "OUTPUT_EXISTS") from e
                with _read_regular(src) as fin:
                    src_st = os.fstat(fin.fileno())
                    source = _HashIO(fin)
                    size = 0
                    while True:
                        _check_cancel(cancel)
                        chunk = source.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        size += len(chunk)
                        progress(len(chunk))
                    _unchanged(src, src_st)
                    if size != src_st.st_size:
                        raise PQError("源文件在核对期间发生变化，已保留原件", "SOURCE_CHANGED")
                if result["bytesOut"] != size or not bytes_equal(verified.digest.digest(), source.digest.digest()):
                    raise PQError("同名密文与当前文件内容不同，未覆盖；请为新版本改名或先备份并移走旧密文", "OUTPUT_EXISTS")
                _check_cancel(cancel)
                _unchanged(out, out_st)
                _unchanged(src, src_st)
                if not keep:
                    _remove_file(src)
            return size

        def file_done(rel_path, size, reused=False):
            res["files"] += 1
            res["bytes"] += size
            if reused:
                res["reused"] += 1
            emit({"type": "file-done", "path": rel_path, "size": size})

        def encrypt_one(src_dir, name, dst_dir, out_name, rel_path):
            _component(name)
            _component(out_name)
            src = os.path.join(src_dir, name)
            out = os.path.join(dst_dir, out_name)
            size = os.path.getsize(src)
            emit({"type": "file-start", "path": rel_path, "size": size})
            ex = self.exists_kind(out)
            if ex is not None:
                if ex != "file":
                    raise PQError("输出名 %s 已被目录或链接占用，未覆盖" % out_name, "OUTPUT_EXISTS")
                size = reuse_existing(src, out, rel_path)
                file_done(rel_path, size, reused=True)
                return
            tmp, fout = _new_temp(dst_dir)
            ok = False
            try:
                with fout, _read_regular(src) as fin:
                    st = os.fstat(fin.fileno())
                    source = _HashIO(fin)
                    sink = BufferedSink(fout)
                    r = pq.encrypt_volume_stream(ctx["vmk"], ctx["volumeId"], source, sink, cancel, progress)
                    sink.flush()
                    _fsync_file(fout)
                    _unchanged(src, st)
                    if r["bytesIn"] != st.st_size:
                        raise PQError("Source size changed during encryption", "SOURCE_CHANGED")
                if verify:
                    emit({"type": "verify-start", "path": rel_path})
                    verified = _HashIO()
                    with _read_regular(tmp) as f2:
                        r2 = pq.decrypt_volume_stream(ctx["vmk"], ctx["volumeId"], ByteReader(f2), verified, cancel, progress)
                    if r2["bytesOut"] != r["bytesIn"] or not bytes_equal(verified.digest.digest(), source.digest.digest()):
                        raise PQError("校验：还原内容与原文件不符")
                _check_cancel(cancel)
                _unchanged(src, st)
                _publish(tmp, out)
                ok = True
                if st is not None:
                    try:
                        os.utime(out, ns=(st.st_atime_ns, st.st_mtime_ns))
                    except OSError:
                        pass
            finally:
                if not ok:
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
            if not keep:
                _unchanged(src, st)
                _remove_file(src)
            file_done(rel_path, r["bytesIn"])

        def walk(src_dir, dst_dir, dir_id, rel, is_root):
            _check_cancel(cancel)
            entries = self.list_entries(src_dir)
            if not ctx["hideNames"] and any(n == DIR_MANIFEST_NAME for n, _ in entries):
                res["errors"].append({"path": rel, "message": "卷头标志与目录清单不一致，未处理"})
                return
            same = os.path.normcase(os.path.abspath(src_dir)) == os.path.normcase(os.path.abspath(dst_dir))
            self._sweep_tmp(src_dir, rel, emit)
            manifest = None
            loaded_entries = None
            by_name = {}
            taken = set()
            if ctx["hideNames"]:
                try:
                    manifest = self._load_manifest(dst_dir, dir_id, ctx)
                except Exception as e:
                    res["errors"].append({"path": _join(rel, DIR_MANIFEST_NAME), "message": "目录清单无法读取，跳过该目录：" + str(e)})
                    emit({"type": "dir-skip", "path": rel or "(根)", "reason": str(e)})
                    return
                loaded_entries = manifest["entries"] if manifest is not None else None
                dst_names = entries if same else self.list_entries(dst_dir)
                present = {n for n, _ in dst_names}
                kept = {}
                for i, ent in ((manifest or {}).get("entries") or {}).items():
                    if i in present or (i + ENC_EXT) in present:
                        kept[i] = ent
                manifest = {"entries": kept}
                for i, ent in kept.items():
                    taken.add(i)
                    by_name[ent["t"] + ":" + ent["n"]] = i
                for n, _ in dst_names:
                    taken.add(n[:-len(ENC_EXT)] if n.endswith(ENC_EXT) else n)

            plain_files, plain_dirs, enc_dirs = [], [], []
            for name, kind in entries:
                if name == LOCK_NAME:
                    continue
                if header_key is not None and os.path.normcase(os.path.abspath(os.path.join(src_dir, name))) == header_key:
                    continue
                if kind == "directory":
                    if is_root and name in SYSTEM_DIRS:
                        emit({"type": "dir-skip", "path": name, "reason": "系统目录"})
                        continue
                    ent = manifest["entries"].get(name) if ctx["hideNames"] else None
                    if ent and ent.get("t") == "d":
                        enc_dirs.append(name)
                        continue
                    plain_dirs.append(name)
                    continue
                if kind in ("link", "other"):
                    emit({"type": "file-skip", "path": _join(rel, name), "reason": "符号链接 / 联接点 / 特殊文件，已跳过"})
                    continue
                if is_root and (_is_volume_header_name(name) or self._is_header_backup(src_dir, name)):
                    continue
                if name == DIR_MANIFEST_NAME or name.startswith(TMP_PREFIX):
                    continue
                if name.endswith(ENC_EXT):
                    try:
                        info = self.probe_file(os.path.join(src_dir, name))
                    except OSError as e:
                        res["errors"].append({"path": _join(rel, name), "message": str(e)})
                        continue
                    p = info["probe"]
                    if p["ok"] and p["volumeId"] is not None and bytes_equal(p["volumeId"], ctx["volumeId"]):
                        res["skipped"] += 1
                        continue
                    if p["ok"]:
                        res["foreign"] += 1
                        emit({"type": "file-skip", "path": _join(rel, name),
                              "reason": "已是本工具的加密文件（其它卷 / 单文件模式），未二次加密，原地保留" + ("（其所在目录名因此保留）" if ctx["hideNames"] and not same else "")})
                        continue
                plain_files.append(name)
            plain_files.sort(key=lambda n: 0 if n.endswith(ENC_EXT) else 1)

            id_of = {}
            if ctx["hideNames"]:
                for n in plain_files:
                    k = "f:" + n
                    i = by_name.get(k) or self._new_id(taken)
                    by_name[k] = i
                    manifest["entries"][i] = {"n": n, "t": "f"}
                    id_of[k] = i
                for n in plain_dirs:
                    k = "d:" + n
                    i = by_name.get(k) or self._new_id(taken)
                    by_name[k] = i
                    manifest["entries"][i] = {"n": n, "t": "d"}
                    id_of[k] = i
                try:
                    if loaded_entries != manifest["entries"]:
                        self._save_manifest(dst_dir, dir_id, manifest["entries"], ctx)
                except Exception as e:
                    res["errors"].append({"path": _join(rel, DIR_MANIFEST_NAME), "message": "目录清单写入失败，跳过该目录：" + str(e)})
                    return

            for n in plain_files:
                _check_cancel(cancel)
                rel_path = _join(rel, n)
                out_name = (id_of["f:" + n] + ENC_EXT) if ctx["hideNames"] else n + ENC_EXT
                try:
                    encrypt_one(src_dir, n, dst_dir, out_name, rel_path)
                except PQError as e:
                    if e.code == "ABORTED":
                        raise
                    res["errors"].append({"path": rel_path, "message": str(e)})
                    emit({"type": "file-error", "path": rel_path, "message": str(e)})
                except Exception as e:
                    res["errors"].append({"path": rel_path, "message": _errstr(e)})
                    emit({"type": "file-error", "path": rel_path, "message": _errstr(e)})
            for n in plain_dirs:
                _check_cancel(cancel)
                child_src = os.path.join(src_dir, n)
                child_dst, child_id = child_src, n
                if ctx["hideNames"]:
                    child_id = id_of["d:" + n]
                    child_dst = os.path.join(dst_dir, child_id)
                    try:
                        os.makedirs(child_dst, exist_ok=True)
                        _check_path(child_dst)
                    except OSError as e:
                        res["errors"].append({"path": _join(rel, n), "message": "无法创建目标目录：" + _errstr(e)})
                        continue
                try:
                    walk(child_src, child_dst, child_id, _join(rel, n), False)
                except PQError:
                    raise
                except Exception as e:
                    res["errors"].append({"path": _join(rel, n), "message": _errstr(e)})
                    continue
                if ctx["hideNames"] and not keep:
                    try:
                        os.rmdir(child_src)
                    except OSError:
                        pass
            for i in enc_dirs:
                _check_cancel(cancel)
                d = os.path.join(src_dir, i)
                if not os.path.isdir(d):
                    continue
                walk(d, d, i, _join(rel, manifest["entries"][i]["n"]), False)

        try:
            walk(root, root, "", "", True)
        except PQError as e:
            if e.code == "ABORTED":
                res["cancelled"] = True
            else:
                raise
        return res

    # ---- decrypt whole tree -----------------------------------------------------------------------
    def _snapshot_cleanup_headers(self, root, volume_id, header_paths=None):
        """Record only pre-existing, validated headers directly inside this root."""
        root = os.path.abspath(root)
        paths = [os.path.join(root, name) for name, kind in self.list_entries(root)
                 if kind == "file" and (_is_volume_header_name(name) or
                     name.casefold().endswith((".pqvolume", ".pqvolume.txt", ".pqvolume.json")))]
        if isinstance(header_paths, (str, bytes, os.PathLike)):
            header_paths = [header_paths]
        paths.extend(header_paths or [])
        snapshots, warnings, seen = [], [], set()
        for candidate in paths:
            path = os.path.abspath(os.fsdecode(candidate))
            key = os.path.normcase(path)
            if os.path.normcase(os.path.dirname(path)) != os.path.normcase(root) or key in seen:
                continue
            seen.add(key)
            try:
                with _read_regular(path) as source:
                    stamp = os.fstat(source.fileno())
                    if stamp.st_size > MAX_JSON_BYTES:
                        continue
                    raw = source.read(MAX_JSON_BYTES + 1)
                    if len(raw) > MAX_JSON_BYTES:
                        continue
                    _unchanged(path, stamp)
                try:
                    header = strict_json(raw)
                    self.pq.validate_volume_header(header)
                except PQError:
                    # Header-like names can also belong to ordinary files.
                    continue
                if bytes_equal(b64decode(header["volume_id"]), volume_id):
                    snapshots.append((path, stamp, raw))
            except FileNotFoundError:
                # Only files that exist before decryption are cleanup targets.
                continue
            except (OSError, PQError) as e:
                warnings.append({"path": os.path.basename(path), "message": "无法确认卷头快照，已保留卷头：" + _errstr(e)})
        return snapshots, warnings

    @_locked
    def decrypt_tree(self, root, ctx, keep_originals=False, on_event=None, cancel=None, remove_header=False, header_paths=None):
        keep = bool(keep_originals)
        pq = self.pq
        res = {"files": 0, "bytes": 0, "skipped": 0, "kept": 0, "errors": [], "warnings": [], "cancelled": False, "headerRemoved": False, "removedHeaders": []}

        def emit(ev):
            if on_event:
                on_event(ev)

        def progress(n):
            emit({"type": "progress", "bytes": n})

        def decrypt_one(src_dir, name, dst_dir, out_name, rel_path):
            _component(out_name)
            src = os.path.join(src_dir, name)
            out = os.path.join(dst_dir, out_name)
            size = os.path.getsize(src)
            emit({"type": "file-start", "path": rel_path, "size": size})
            if self.exists_kind(out) is not None:
                res["skipped"] += 1
                res["kept"] += 1
                emit({"type": "file-skip", "path": rel_path, "reason": "目标 %s 已存在，未覆盖（密文、清单与卷头保留；移走同名文件后再解密一次即可）" % out_name})
                return False
            tmp, fout = _new_temp(dst_dir)
            ok = False
            try:
                with fout, _read_regular(src) as fin:
                    st = os.fstat(fin.fileno())
                    sink = BufferedSink(fout)
                    pq.decrypt_volume_stream(ctx["vmk"], ctx["volumeId"], ByteReader(fin), sink, cancel, progress)
                    sink.flush()
                    _fsync_file(fout)
                    _unchanged(src, st)
                if self.exists_kind(out) is not None:
                    res["skipped"] += 1
                    res["kept"] += 1
                    emit({"type": "file-skip", "path": rel_path, "reason": "目标 %s 已存在，未覆盖（密文、清单与卷头保留）" % out_name})
                    return False
                _check_cancel(cancel)
                _unchanged(src, st)
                _publish(tmp, out)
                ok = True
                if st is not None:
                    try:
                        os.utime(out, ns=(st.st_atime_ns, st.st_mtime_ns))
                    except OSError:
                        pass
            finally:
                if not ok:
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
            if not keep:
                _unchanged(src, st)
                _remove_file(src)
            res["files"] += 1
            res["bytes"] += size
            emit({"type": "file-done", "path": rel_path, "size": size})
            return True

        def walk(src_dir, dst_dir, dir_id, rel, is_root):
            _check_cancel(cancel)
            entries = self.list_entries(src_dir)
            self._sweep_tmp(src_dir, rel, emit)
            manifest = None
            clean = not any(n.startswith(TMP_PREFIX) or k in ("link", "other") for n, k in entries)
            if not ctx["hideNames"] and any(n == DIR_MANIFEST_NAME for n, _ in entries):
                res["errors"].append({"path": rel, "message": "卷头标志与目录清单不一致，未处理"})
                return False
            if ctx["hideNames"]:
                try:
                    manifest = self._load_manifest(src_dir, dir_id, ctx)
                except Exception as e:
                    res["errors"].append({"path": _join(rel, DIR_MANIFEST_NAME), "message": str(e)})
                    return False
                if manifest is None and any(n.endswith(ENC_EXT) for n, _ in entries):
                    res["warnings"].append({"path": _join(rel, DIR_MANIFEST_NAME), "message": "目录清单缺失：该目录内的文件 / 子目录名无法恢复，已按 ID 命名还原"})
                    emit({"type": "file-warn", "path": _join(rel, DIR_MANIFEST_NAME), "message": "目录清单缺失，该目录内容按 ID 命名还原"})
                    clean = False
            ents = (manifest or {}).get("entries") or {}

            for name, kind in entries:
                if kind != "file":
                    continue
                _check_cancel(cancel)
                if is_root and _is_volume_header_name(name):
                    continue
                if name == DIR_MANIFEST_NAME or name.startswith(TMP_PREFIX):
                    continue
                if not name.endswith(ENC_EXT):
                    continue
                rel_path = _join(rel, name)
                try:
                    info = self.probe_file(os.path.join(src_dir, name))
                except OSError as e:
                    res["errors"].append({"path": rel_path, "message": _errstr(e)})
                    clean = False
                    continue
                p = info["probe"]
                if not (p["ok"] and p["volumeId"] is not None and bytes_equal(p["volumeId"], ctx["volumeId"])):
                    res["skipped"] += 1
                    emit({"type": "file-skip", "path": rel_path, "reason": "不属于本卷（其它卷 / 单文件模式），已跳过" if p["ok"] else "不是本工具的加密文件，已跳过"})
                    continue
                if ctx["hideNames"]:
                    i = name[:-len(ENC_EXT)]
                    ent = ents.get(i)
                    if ent and ent.get("t") == "f":
                        out_name = ent["n"]
                    else:
                        out_name = i
                        message = "清单中没有此文件的原名，已按 ID 命名还原"
                        if manifest is not None:
                            res["warnings"].append({"path": rel_path, "message": message})
                        emit({"type": "file-warn", "path": rel_path, "message": message})
                        clean = False
                else:
                    out_name = name[:-len(ENC_EXT)]
                try:
                    if not decrypt_one(src_dir, name, dst_dir, out_name, _join(rel, out_name) if ctx["hideNames"] else rel_path):
                        clean = False
                except PQError as e:
                    if e.code == "ABORTED":
                        raise
                    clean = False
                    res["errors"].append({"path": rel_path, "message": str(e)})
                    emit({"type": "file-error", "path": rel_path, "message": str(e)})
                except Exception as e:
                    clean = False
                    res["errors"].append({"path": rel_path, "message": _errstr(e)})
                    emit({"type": "file-error", "path": rel_path, "message": _errstr(e)})
            for name, kind in entries:
                if kind != "directory":
                    continue
                _check_cancel(cancel)
                if is_root and name in SYSTEM_DIRS:
                    continue
                child_src = os.path.join(src_dir, name)
                child_dst, child_rel = child_src, _join(rel, name)
                ent = ents.get(name) if ctx["hideNames"] else None
                if ent and ent.get("t") == "d":
                    out_dir = ent["n"]
                    if self.exists_kind(os.path.join(dst_dir, out_dir)) in ("file", "link"):
                        out_dir = "%s (目录, 原 ID %s)" % (ent["n"], name)
                        res["warnings"].append({"path": _join(rel, ent["n"]), "message": "同名文件已存在，目录改以“%s”还原" % out_dir})
                        emit({"type": "file-warn", "path": _join(rel, ent["n"]), "message": "同名文件已存在，目录改以“%s”还原" % out_dir})
                        clean = False
                    child_dst = os.path.join(dst_dir, out_dir)
                    child_rel = _join(rel, out_dir)
                    try:
                        os.makedirs(child_dst, exist_ok=True)
                        _check_path(child_dst)
                    except OSError as e:
                        res["errors"].append({"path": _join(rel, name), "message": "无法创建目标目录：" + _errstr(e)})
                        clean = False
                        continue
                try:
                    sub = walk(child_src, child_dst, name, child_rel, False)
                except PQError:
                    raise
                except Exception as e:
                    res["errors"].append({"path": _join(rel, name), "message": _errstr(e)})
                    clean = False
                    continue
                if not sub:
                    clean = False
                if sub and child_dst != child_src and not keep:
                    try:
                        os.rmdir(child_src)
                    except OSError:
                        pass
            if ctx["hideNames"] and manifest is not None and clean and not keep:
                try:
                    _remove_file(os.path.join(src_dir, DIR_MANIFEST_NAME))
                except OSError:
                    pass
            return clean

        try:
            _check_cancel(cancel)
            snapshots = []
            if remove_header and not keep:
                snapshots, warnings = self._snapshot_cleanup_headers(root, ctx["volumeId"], header_paths)
                res["warnings"].extend(warnings)
                for warning in warnings:
                    emit(dict(warning, type="file-warn"))
            clean = walk(root, root, "", "", True)
            _check_cancel(cancel)
            if clean and not keep and not res["errors"] and not res["warnings"] and not res["kept"] and remove_header:
                cleanup_path = "(根)"
                try:
                    diag = self.diagnose_tree(root, {"volume_id": b64encode(ctx["volumeId"])}, cancel=cancel)
                    remaining = any("本卷密文" in k or "损坏" in k or "无法" in k or "残留" in k or "目录清单" in k
                                    or "链接 / 特殊文件" in k for k in diag["counts"])
                    # Diagnostics reserve the canonical header name. Probe it
                    # separately in case ciphertext was renamed to that name.
                    for name, kind in self.list_entries(root):
                        if kind == "file" and _is_volume_header_name(name):
                            probe = self.probe_file(os.path.join(root, name))["probe"]
                            if (probe["ok"] and probe["version"] == VERSION and probe["mode"] == MODE_VOLUME
                                    and (probe["volumeId"] is None or bytes_equal(probe["volumeId"], ctx["volumeId"]))):
                                remaining = True
                    if not remaining:
                        # Validate the entire set before removing any header. A
                        # replaced/edited header must not disappear during cleanup.
                        for path, stamp, raw in snapshots:
                            cleanup_path = os.path.basename(path)
                            _check_cancel(cancel)
                            _unchanged(path, stamp)
                            if self.read_file_bytes(path, MAX_JSON_BYTES) != raw:
                                raise PQError("卷头在解密期间发生变化，已保留卷头", "SOURCE_CHANGED")
                            _unchanged(path, stamp)
                        for path, stamp, raw in snapshots:
                            cleanup_path = os.path.basename(path)
                            _check_cancel(cancel)
                            _unchanged(path, stamp)
                            _remove_file(path)
                            res["removedHeaders"].append(path)
                            res["headerRemoved"] = True
                except (OSError, PQError) as e:
                    if isinstance(e, PQError) and e.code == "ABORTED":
                        raise
                    warning = {"path": cleanup_path,
                               "message": "解密后卷头清理未完成：" + _errstr(e)}
                    res["warnings"].append(warning)
                    emit(dict(warning, type="file-warn"))
        except PQError as e:
            if e.code == "ABORTED":
                res["cancelled"] = True
            else:
                raise
        return res

    # ---- diagnostics: classify every file (any extension) by content ---------------------------------
    def diagnose_tree(self, root, header=None, limit=400, cancel=None):
        vid = None
        try:
            vid = b64decode(header["volume_id"]) if header else None
        except Exception:
            vid = None
        lines = []
        counts = {}
        misnamed = []

        def add(kind, text):
            counts[kind] = counts.get(kind, 0) + 1
            if len(lines) < limit:
                lines.append("[%s] %s" % (kind, text))

        def walk(dirpath, rel, is_root):
            _check_cancel(cancel)
            try:
                entries = self.list_entries(dirpath)
            except OSError as e:
                add("目录无法列出", (rel or "(根)") + "：" + _errstr(e))
                return
            for name, kind in entries:
                if name == LOCK_NAME:
                    continue
                full = os.path.join(dirpath, name)
                rp = _join(rel, name)
                if kind == "directory":
                    if is_root and name in SYSTEM_DIRS:
                        add("系统目录（跳过）", rp)
                        continue
                    walk(full, rp, False)
                    continue
                if kind != "file":
                    add("链接 / 特殊文件（跳过）", rp)
                    continue
                if is_root and _is_volume_header_name(name):
                    continue
                try:
                    size = os.path.getsize(full)
                except OSError as e:
                    add("无法读取", rp + "：" + _errstr(e))
                    continue
                if name == DIR_MANIFEST_NAME:
                    add("目录清单", "%s（%d B）" % (rp, size))
                    continue
                if name.startswith(TMP_PREFIX):
                    add("残留临时文件", rp)
                    continue
                try:
                    info = self.probe_file(full)
                    p = info["probe"]
                except OSError as e:
                    add("无法读取", rp + "：" + _errstr(e))
                    continue
                is_pqfc = name.endswith(ENC_EXT)
                if not p["ok"]:
                    category = "损坏（头部不完整）" if info["hasMagic"] else "普通文件" if not is_pqfc else "普通文件（只是名字以 .pqfc 结尾）"
                    add(category, "%s（%d B）" % (rp, size))
                    continue
                if p["version"] == VERSION and p["mode"] == MODE_VOLUME:
                    if p["volumeId"] is None:
                        add("损坏（头部不完整）", "%s（%d B）" % (rp, size))
                    elif vid is not None and bytes_equal(p["volumeId"], vid):
                        if is_pqfc:
                            add("本卷密文", "%s（%d B）" % (rp, size))
                        else:
                            add("本卷密文但扩展名不是 .pqfc", "%s（%d B）" % (rp, size))
                            misnamed.append(rp)
                    else:
                        add("其它卷密文" + ("" if is_pqfc else "（扩展名不是 .pqfc）"), "%s（%d B）卷 ID %s…" % (rp, size, hexs(p["volumeId"])[:12]))
                else:
                    add("单文件模式密文（v%d 模式 %d）" % (p["version"], p["mode"]), "%s（%d B）" % (rp, size))
        walk(root, "", True)
        return {"lines": lines, "counts": counts, "misnamed": misnamed, "truncated": sum(counts.values()) > limit}

    @_locked
    def fix_extensions(self, root, rel_paths):
        done = []
        errors = []
        for rp in rel_paths:
            try:
                if not isinstance(rp, str):
                    raise PQError("Invalid relative path", "UNSAFE_PATH")
                parts = rp.split("/")
                for part in parts:
                    _component(part)
                src = os.path.join(root, *parts)
                dst = src + ENC_EXT
                _component(parts[-1] + ENC_EXT)
                if os.path.exists(dst):
                    raise PQError("目标已存在：" + rp + ENC_EXT)
                _regular(_check_path(src))
                _publish(src, dst)
                done.append(rp)
            except Exception as e:
                errors.append({"path": rp, "message": _errstr(e)})
        return {"renamed": done, "errors": errors}

    # ---- rename-only conversion between visible and hidden-name layouts --------------------------
    # Ciphertext never depends on file names, so hiding / unhiding is pure renaming plus manifests.
    # Hiding writes hide_names=true to the header first; unhiding writes hide_names=false last:
    # either way an interrupted conversion still decrypts (with "named by ID" warnings).
    @_locked
    def convert_names(self, root, header, ctx, hide, on_event=None, cancel=None, header_path=None):
        res = {"files": 0, "dirs": 0, "errors": [], "warnings": [], "cancelled": False, "completed": False}
        if header_path is not None:
            root_key = os.path.normcase(os.path.abspath(root))
            parent_key = os.path.normcase(os.path.dirname(os.path.abspath(header_path)))
            if parent_key != root_key and parent_key.startswith(root_key.rstrip(os.sep) + os.sep):
                raise PQError("卷头位于待改名的子目录，请先把它移到根目录或卷外并重新载入，再切换文件名显示方式。", "HEADER_IN_SUBDIRECTORY")

        def emit(ev):
            if on_event:
                on_event(ev)
        def persist():
            if header_path is None:
                self.write_volume_header(root, header)
            else:
                existing = self.read_header_file(header_path)
                if existing["volume_id"] != header["volume_id"]:
                    raise PQError("卷头已变化，未更新", "VOLUME_CHANGED")
                self.write_file_bytes(header_path, header_json(header).encode("utf-8"))
        if bool(header.get("hide_names")) == bool(hide):
            raise PQError("卷已经是%s状态" % ("隐藏文件名" if hide else "显示文件名"))
        try:
            if hide:
                header["hide_names"] = True
                persist()
                self._hide_walk(root, "", "", ctx, res, emit, cancel)
            else:
                plan = []
                conflicts = []
                self._unhide_plan(root, "", "", ctx, res, emit, plan, conflicts, cancel)
                if res["errors"] or res["warnings"]:
                    return res
                if conflicts:
                    raise PQError("有 %d 处名字冲突，未做任何改动：%s%s" % (
                        len(conflicts), "；".join(conflicts[:5]), "…" if len(conflicts) > 5 else ""))
                for op in plan:
                    _check_cancel(cancel)
                    op()
                    if res["errors"]:
                        return res
                if not res["errors"]:
                    header["hide_names"] = False
                    persist()
            res["completed"] = not res["errors"]
        except PQError as e:
            if e.code == "ABORTED":
                res["cancelled"] = True
            else:
                raise
        return res

    def _hide_walk(self, dirpath, dir_id, rel, ctx, res, emit, cancel):
        _check_cancel(cancel)
        entries = self.list_entries(dirpath)
        present = {n for n, _ in entries}
        try:
            manifest = self._load_manifest(dirpath, dir_id, ctx)
        except Exception as e:
            res["errors"].append({"path": _join(rel, DIR_MANIFEST_NAME), "message": "目录清单无法读取，跳过该目录：" + str(e)})
            emit({"type": "dir-skip", "path": rel or "(根)", "reason": str(e)})
            return
        kept = {i: ent for i, ent in ((manifest or {}).get("entries") or {}).items() if i in present or (i + ENC_EXT) in present}
        by_name = {ent["t"] + ":" + ent["n"]: i for i, ent in kept.items()}
        taken = set(kept)
        for n, _ in entries:
            taken.add(n[:-len(ENC_EXT)] if n.endswith(ENC_EXT) else n)
        files, dirs = [], []
        for name, kind in entries:
            if name == LOCK_NAME:
                continue
            if kind == "directory":
                if dir_id == "" and rel == "" and name in SYSTEM_DIRS:
                    continue
                if name in kept and kept[name].get("t") == "d":
                    continue
                dirs.append(name)
            elif kind == "file" and name.endswith(ENC_EXT) and name[:-len(ENC_EXT)] not in kept:
                if self._is_ours(os.path.join(dirpath, name), ctx["volumeId"]):
                    files.append(name)
        entries_out = dict(kept)
        id_of = {}
        for n in files:
            base = n[:-len(ENC_EXT)]
            i = by_name.get("f:" + base) or self._new_id(taken)
            entries_out[i] = {"n": base, "t": "f"}
            id_of["f:" + n] = i
        for n in dirs:
            i = by_name.get("d:" + n) or self._new_id(taken)
            entries_out[i] = {"n": n, "t": "d"}
            id_of["d:" + n] = i
        try:
            self._save_manifest(dirpath, dir_id, entries_out, ctx)
        except Exception as e:
            res["errors"].append({"path": _join(rel, DIR_MANIFEST_NAME), "message": "目录清单写入失败，跳过该目录：" + _errstr(e)})
            return
        for n in files:
            _check_cancel(cancel)
            try:
                _publish(os.path.join(dirpath, n), os.path.join(dirpath, id_of["f:" + n] + ENC_EXT))
                res["files"] += 1
            except OSError as e:
                res["errors"].append({"path": _join(rel, n), "message": _errstr(e)})
                emit({"type": "file-error", "path": _join(rel, n), "message": _errstr(e)})
        for n in dirs:
            _check_cancel(cancel)
            i = id_of["d:" + n]
            self._hide_walk(os.path.join(dirpath, n), i, _join(rel, n), ctx, res, emit, cancel)
            try:
                _rename_directory(os.path.join(dirpath, n), os.path.join(dirpath, i))
                res["dirs"] += 1
            except OSError as e:
                res["errors"].append({"path": _join(rel, n), "message": _errstr(e)})
                emit({"type": "file-error", "path": _join(rel, n), "message": _errstr(e)})
        for i in [i for i, ent in kept.items() if ent.get("t") == "d" and i in present]:
            _check_cancel(cancel)
            self._hide_walk(os.path.join(dirpath, i), i, _join(rel, kept[i]["n"]), ctx, res, emit, cancel)

    def _unhide_plan(self, dirpath, dir_id, rel, ctx, res, emit, plan, conflicts, cancel):
        _check_cancel(cancel)
        entries = self.list_entries(dirpath)
        present = {n for n, _ in entries}
        try:
            manifest = self._load_manifest(dirpath, dir_id, ctx)
        except Exception as e:
            res["errors"].append({"path": _join(rel, DIR_MANIFEST_NAME), "message": str(e)})
            return
        ents = (manifest or {}).get("entries") or {}
        if manifest is None:
            if any(n.endswith(ENC_EXT) for n in present):
                res["warnings"].append({"path": _join(rel, DIR_MANIFEST_NAME), "message": "目录清单缺失：该目录内的名字无法恢复，保持 ID 名"})
                emit({"type": "file-warn", "path": _join(rel, DIR_MANIFEST_NAME), "message": "目录清单缺失，该目录内保持 ID 名"})
            return
        targets = set()

        def taken(name):
            return name in present or name in targets
        for name, kind in entries:
            if kind == "file" and name.endswith(ENC_EXT):
                i = name[:-len(ENC_EXT)]
                ent = ents.get(i)
                if not ent or ent.get("t") != "f":
                    if self._is_ours(os.path.join(dirpath, name), ctx["volumeId"]):
                        res["warnings"].append({"path": _join(rel, name), "message": "清单中没有此文件的原名，保持 ID 名"})
                    continue
                target = ent["n"] + ENC_EXT
                if taken(target):
                    conflicts.append(_join(rel, target))
                    continue
                targets.add(target)
                src, dst, rp = os.path.join(dirpath, name), os.path.join(dirpath, target), _join(rel, name)

                def op(src=src, dst=dst, rp=rp):
                    try:
                        _publish(src, dst)
                        res["files"] += 1
                    except OSError as e:
                        res["errors"].append({"path": rp, "message": _errstr(e)})
                        emit({"type": "file-error", "path": rp, "message": _errstr(e)})
                plan.append(op)
        for name, kind in entries:
            if kind != "directory":
                continue
            ent = ents.get(name)
            if not ent or ent.get("t") != "d":
                continue
            self._unhide_plan(os.path.join(dirpath, name), name, _join(rel, ent["n"]), ctx, res, emit, plan, conflicts, cancel)
            target = ent["n"]
            if taken(target):
                conflicts.append(_join(rel, target))
                continue
            targets.add(target)
            src, dst, rp = os.path.join(dirpath, name), os.path.join(dirpath, target), _join(rel, name)

            def dop(src=src, dst=dst, rp=rp):
                try:
                    _rename_directory(src, dst)
                    res["dirs"] += 1
                except OSError as e:
                    res["errors"].append({"path": rp, "message": _errstr(e)})
                    emit({"type": "file-error", "path": rp, "message": _errstr(e)})
            plan.append(dop)
        mpath = os.path.join(dirpath, DIR_MANIFEST_NAME)

        def mop(mpath=mpath, rp=_join(rel, DIR_MANIFEST_NAME)):
            try:
                _remove_file(mpath)
            except OSError as e:
                res["errors"].append({"path": rp, "message": _errstr(e)})
        plan.append(mop)

    @staticmethod
    def _sweep_tmp(dirpath, rel, emit):
        try:
            names = os.listdir(dirpath)
        except OSError:
            return
        for n in names:
            if n.startswith(TMP_PREFIX):
                emit({"type": "file-warn", "path": _join(rel, n), "message": "发现残留临时文件，未自动删除；请先确认是否需要恢复"})


def _errstr(e):
    if isinstance(e, PermissionError):
        return "没有权限或文件正被占用：" + (e.strerror or str(e))
    if isinstance(e, OSError) and e.strerror:
        return e.strerror + ("（%s）" % e.filename if e.filename else "")
    return str(e) or e.__class__.__name__


def header_json(header):
    return json.dumps(header, indent=2, ensure_ascii=False)


def vol_id_short(header):
    try:
        return hexs(b64decode(header["volume_id"]))[:12]
    except Exception:
        return "?"


# ---------------------------------------------------------------------------
# GUI (tkinter). tkinter is imported lazily so the crypto core and the test suite
# work without a display; the UI smoke test injects a fake tkinter here.
# ---------------------------------------------------------------------------
tk = ttk = filedialog = messagebox = None


def _load_tk():
    global tk, ttk, filedialog, messagebox
    import tkinter as _tk
    from tkinter import ttk as _ttk, filedialog as _fd, messagebox as _mb
    tk, ttk, filedialog, messagebox = _tk, _ttk, _fd, _mb


def _ui_font(size, weight="normal"):
    try:
        from tkinter import font as _tkfont
        return (_tkfont.nametofont("TkDefaultFont").actual("family"), size, weight)
    except Exception:
        return ("Helvetica", size, weight)


def _mono_font(size):
    try:
        from tkinter import font as _tkfont
        return (_tkfont.nametofont("TkFixedFont").actual("family"), size)
    except Exception:
        return ("Courier", size)


def fmt_size(n):
    n = float(n or 0)
    if n < 1024:
        return "%d B" % int(n)
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        n /= 1024.0
        if n < 1024 or unit == "TiB":
            return "%.1f %s" % (n, unit)
    return "%.1f TiB" % n


def fmt_rate(bps):
    return fmt_size(bps) + "/s" if bps > 0 else "—"


def fmt_dur(s):
    s = int(max(0, s))
    if s < 60:
        return "%d 秒" % s
    if s < 3600:
        return "%d 分 %02d 秒" % (s // 60, s % 60)
    return "%d 时 %02d 分" % (s // 3600, (s % 3600) // 60)


def fmt_date(iso):
    try:
        d = datetime.strptime(str(iso)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).astimezone()
        return d.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(iso or "—")


def slot_summary(header):
    pw = sum(1 for s in header["slots"] if s.get("type") == SLOT_PASSWORD)
    pks = [s for s in header["slots"] if s.get("type") == SLOT_PUBKEY]
    parts = []
    if pw:
        parts.append("口令 ×%d" % pw)
    if pks:
        parts.append("公钥 ×%d（指纹 %s）" % (len(pks), " / ".join(s.get("fingerprint") or "?" for s in pks)))
    return "、".join(parts) or "无"


def read_json_file(path):
    raw = VolumeFS.read_file_bytes(path, MAX_JSON_BYTES)
    try:
        return strict_json(raw)
    except Exception:
        raise PQError("文件不是有效 JSON：" + os.path.basename(path))


def write_text_file(path, text):
    VolumeFS.write_file_bytes(path, text.encode("utf-8"))


class ScrollFrame:
    """Vertical scrollable container; .inner is the frame to put content in."""

    def __init__(self, parent):
        self.outer = ttk.Frame(parent)
        self.canvas = tk.Canvas(self.outer, highlightthickness=0, borderwidth=0)
        self.vsb = ttk.Scrollbar(self.outer, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas)
        self.win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self.win, width=e.width))
        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _bind_wheel(self, _e=None):
        self.canvas.bind_all("<MouseWheel>", self._wheel)
        self.canvas.bind_all("<Button-4>", lambda e: self.canvas.yview_scroll(-3, "units"))
        self.canvas.bind_all("<Button-5>", lambda e: self.canvas.yview_scroll(3, "units"))

    def _unbind_wheel(self, _e=None):
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.canvas.unbind_all(seq)

    def _wheel(self, e):
        try:
            self.canvas.yview_scroll(int(-e.delta / 120) * 3, "units")
        except Exception:
            pass


class PasswordEntry:
    """Entry with a show/hide toggle and an optional strength label."""

    def __init__(self, parent, var, width=34, meter=False):
        self.var = var
        self.frame = ttk.Frame(parent)
        self.entry = ttk.Entry(self.frame, textvariable=var, show="•", width=width)
        self.entry.pack(side="left")
        self.show = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.frame, text="显示", variable=self.show, command=self._toggle).pack(side="left", padx=(6, 0))
        self.meter = None
        if meter:
            self.meter = ttk.Label(self.frame, text="口令强度：—", foreground="#666")
            self.meter.pack(side="left", padx=(12, 0))
            var.trace_add("write", lambda *a: self._update_meter())

    def _toggle(self):
        self.entry.configure(show="" if self.show.get() else "•")

    def _update_meter(self):
        r = password_strength(self.var.get())
        if r["blocked"]:
            txt = "口令强度：不可用（%s）" % r["reason"]
            color = "#b02a2a"
        else:
            txt = "口令强度：%s（约 %d bit）" % (r["label"], r["bits"])
            color = ["#b02a2a", "#c76a1a", "#8a7a1a", "#2a7a3a", "#1f6f3f"][r["score"]]
        if r["warnings"]:
            txt += "；" + "；".join(r["warnings"][:2])
        self.meter.configure(text=txt, foreground=color)


class UnlockBox:
    """Password / private-key chooser; snapshot() runs on the UI thread, unlock() on the worker."""

    def __init__(self, app, parent, title="解锁方式", pw_label="卷口令"):
        self.app = app
        self.mode = tk.StringVar(value="pw")
        self.pw = tk.StringVar()
        self.key_pw = tk.StringVar()
        self.key_obj = None
        self.key_raw = None
        self.key_wrapped = False
        self.key_name = ""
        f = self.frame = ttk.LabelFrame(parent, text=title, padding=(10, 6))
        f.columnconfigure(1, weight=1)
        rb = ttk.Frame(f)
        rb.grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Radiobutton(rb, text="口令", variable=self.mode, value="pw", command=self._refresh).pack(side="left")
        ttk.Radiobutton(rb, text="私钥 (.key)", variable=self.mode, value="key", command=self._refresh).pack(side="left", padx=(12, 0))
        self.pw_row = ttk.Frame(f)
        self.pw_row.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Label(self.pw_row, text=pw_label).pack(side="left", padx=(0, 8))
        self.pw_entry = PasswordEntry(self.pw_row, self.pw)
        self.pw_entry.frame.pack(side="left")
        self.key_row = ttk.Frame(f)
        self.key_row.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Button(self.key_row, text="选择 .key 私钥…", command=self.pick_key).pack(side="left")
        self.key_label = ttk.Label(self.key_row, text="未载入私钥", foreground="#666")
        self.key_label.pack(side="left", padx=(8, 0))
        self.key_pw_row = ttk.Frame(f)
        self.key_pw_row.grid(row=3, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Label(self.key_pw_row, text="私钥口令（此私钥已加密）").pack(side="left", padx=(0, 8))
        self.key_pw_entry = PasswordEntry(self.key_pw_row, self.key_pw)
        self.key_pw_entry.frame.pack(side="left")
        self._refresh()

    def _refresh(self):
        pw = self.mode.get() == "pw"
        if pw:
            self.pw_row.grid()
            self.key_row.grid_remove()
            self.key_pw_row.grid_remove()
        else:
            self.pw_row.grid_remove()
            self.key_row.grid()
            if self.key_wrapped:
                self.key_pw_row.grid()
            else:
                self.key_pw_row.grid_remove()

    def select(self, mode):
        self.mode.set(mode)
        self._refresh()

    def adapt(self, header):
        has_pw = any(s.get("type") == SLOT_PASSWORD for s in header["slots"])
        has_pk = any(s.get("type") == SLOT_PUBKEY for s in header["slots"])
        if not has_pw and has_pk:
            self.select("key")
        elif has_pw and not has_pk:
            self.select("pw")

    def pick_key(self):
        path = filedialog.askopenfilename(title="选择 .key 私钥文件", filetypes=[("私钥文件", "*.key"), ("所有文件", "*.*")])
        if path:
            self.load_key(path)

    def load_key(self, path):
        try:
            self.app.ensure_ready()
            pq = self.app.pq
            obj = read_json_file(path)
            name = os.path.basename(path)
            if pq.is_wrapped_key(obj):
                self.key_raw, self.key_wrapped, self.key_obj = obj, True, None
                self.key_name = name
                self.key_label.configure(text=name + " 🔒（将在解锁时用口令解封）")
                self.app.log("已载入【受口令保护】的私钥 %s，将在解锁卷时用 Argon2id 解封。" % name)
                kp = obj.get("kdf_params") or {}
                warn = kdf_cost_exceeds_default(kp.get("t"), kp.get("m"), kp.get("p"))
                if warn:
                    self.app.log("注意：私钥容器：" + warn, "w")
            elif isinstance(obj, dict) and obj.get("x25519_priv") and obj.get("mlkem_secret"):
                pq.validate_key_obj(obj)
                self.key_obj, self.key_raw, self.key_wrapped = obj, None, False
                self.key_name = name
                fp = pq.fingerprint(b64decode(obj["x25519_pub"]), b64decode(obj["mlkem_pub"]))
                self.key_label.configure(text=name + " ✓  指纹 " + fp)
                self.app.log("已载入私钥（明文）%s，指纹 %s" % (name, fp))
            else:
                raise PQError("这不是有效的 .key 私钥文件")
            self.select("key")
        except Exception as e:
            self.key_obj = self.key_raw = None
            self.key_wrapped = False
            self.key_label.configure(text="未载入私钥")
            self._refresh()
            self.app.fail(e)

    def snapshot(self, header):
        """Collect inputs (UI thread). Raises PQError when something is missing."""
        if self.mode.get() == "pw":
            pw = self.pw.get()
            if not pw:
                raise PQError("请输入卷口令")
            for i, s in enumerate(header["slots"]):
                if s.get("type") == SLOT_PASSWORD:
                    p = s.get("kdf_params") or {}
                    self.app.confirm_kdf_cost(p.get("t"), p.get("m"), p.get("p"), "解锁卷（口令槽 #%d）" % (i + 1))
            return {"mode": "pw", "password": pw}
        if self.key_wrapped:
            kpw = self.key_pw.get()
            if not kpw:
                raise PQError("请输入解锁私钥的口令")
            kp = self.key_raw.get("kdf_params") or {}
            self.app.confirm_kdf_cost(kp.get("t"), kp.get("m"), kp.get("p"), "解锁私钥")
            return {"mode": "key", "wrapped": self.key_raw, "key_pw": kpw}
        if not self.key_obj:
            raise PQError("请先载入你的 .key 私钥")
        return {"mode": "key", "key_obj": self.key_obj}

    def snapshot_plain(self, want=None):
        """Header-less variant for single-file mode: want is 'pw', 'key' or None (use the radio)."""
        mode = want or self.mode.get()
        if mode == "pw":
            pw = self.pw.get()
            if not pw:
                raise PQError("请输入口令")
            return {"mode": "pw", "password": pw}
        if self.key_wrapped:
            kpw = self.key_pw.get()
            if not kpw:
                raise PQError("请输入解锁私钥的口令")
            kp = self.key_raw.get("kdf_params") or {}
            self.app.confirm_kdf_cost(kp.get("t"), kp.get("m"), kp.get("p"), "解锁私钥")
            return {"mode": "key", "wrapped": self.key_raw, "key_pw": kpw}
        if not self.key_obj:
            raise PQError("请先载入你的 .key 私钥")
        return {"mode": "key", "key_obj": self.key_obj}

    def resolve(self, spec):
        """Worker thread: returns (password, key_obj) for pq.decrypt / signing."""
        if spec["mode"] == "pw":
            return spec["password"], None
        obj = spec.get("key_obj")
        if spec.get("wrapped"):
            self.app.wlog("用 Argon2id 解锁私钥…")
            obj = self.app.try_password_variants(spec["key_pw"], lambda v: self.app.pq.unwrap_secret_key(spec["wrapped"], v))
        return None, obj

    def unlock(self, spec, header):
        """Worker thread: returns pq.unlock_volume result."""
        pq = self.app.pq
        if spec["mode"] == "pw":
            self.app.wlog("Argon2id 派生 → 核对密钥承诺 → 解封卷主密钥（口令槽）…")
            return self.app.try_password_variants(spec["password"], lambda v: pq.unlock_volume(header, password=v))
        obj = spec.get("key_obj")
        if spec.get("wrapped"):
            self.app.wlog("用 Argon2id 解锁私钥…")
            obj = self.app.try_password_variants(spec["key_pw"], lambda v: pq.unwrap_secret_key(spec["wrapped"], v))
        self.app.wlog("解封 ML-KEM + X25519 → 组合器派生 → 核对密钥承诺 → 解封卷主密钥（公钥槽）…")
        return pq.unlock_volume(header, key_obj=obj)

    def clear(self):
        self.key_obj = self.key_raw = None
        self.key_wrapped = False
        self.key_name = ""
        self.pw.set("")
        self.key_pw.set("")
        self.key_label.configure(text="未载入私钥")
        self._refresh()


class ProgressBox:
    def __init__(self, app, parent, cancel_hint):
        self.app = app
        f = self.frame = ttk.Frame(parent)
        self.bar = ttk.Progressbar(f, orient="horizontal", mode="determinate", maximum=1000)
        self.bar.pack(fill="x")
        self.stat = ttk.Label(f, text="准备中…")
        self.stat.pack(anchor="w", pady=(3, 0))
        self.cur = ttk.Label(f, text="—", foreground="#666")
        self.cur.pack(anchor="w")
        self.cancel_btn = ttk.Button(f, text="■ 取消（" + cancel_hint + "）", command=self.cancel)
        self.cancel_btn.pack(anchor="w", pady=(4, 0))
        self.cancel_ev = None
        self.total = self.done = self.files = self.total_files = self.errors = 0
        self.t0 = 0.0
        self.cur_path = "—"
        self.phase = ""
        self.active = False

    def start(self, total_bytes, total_files):
        self.cancel_ev = threading.Event()
        self.total, self.total_files = int(total_bytes or 0), int(total_files or 0)
        self.done = self.files = self.errors = 0
        self.t0 = time.time()
        self.cur_path, self.phase = "—", ""
        self.active = True
        self.frame.grid()
        self.cancel_btn.configure(state="normal")
        self.render(True)
        return self.cancel_ev

    def cancel(self):
        if self.cancel_ev is not None and not self.cancel_ev.is_set():
            self.cancel_ev.set()
            self.cancel_btn.configure(state="disabled")
            self.cur.configure(text="正在取消：等待当前文件块处理完毕…")
            self.app.log("已请求取消。", "w")

    def on_event(self, ev):
        """Called from the worker thread."""
        t = ev["type"]
        if t == "progress":
            self.done += ev["bytes"]
        elif t == "file-start":
            self.cur_path, self.phase = ev["path"], ""
        elif t == "verify-start":
            self.phase = "校验"
        elif t == "file-done":
            self.files += 1
        elif t == "file-error":
            self.errors += 1
            self.app.wlog("失败：%s：%s" % (ev["path"], ev["message"]), "er")
        elif t == "file-skip":
            self.app.wlog("跳过：%s：%s" % (ev["path"], ev["reason"]), "w")
        elif t == "file-warn":
            self.app.wlog("警告：%s：%s" % (ev["path"], ev["message"]), "w")
        elif t == "dir-skip":
            self.app.wlog("跳过目录：%s（%s）" % (ev["path"], ev["reason"]), "w")

    def render(self, force=False):
        if not self.active and not force:
            return
        pct = min(100.0, self.done / self.total * 100.0) if self.total > 0 else 0.0
        self.bar.configure(value=pct * 10)
        el = time.time() - self.t0
        speed = self.done / el if el > 0 else 0
        eta = max(0, self.total - self.done) / speed if speed > 0 else 0
        txt = "%.1f%%   %d / %d 文件 · %s / %s · %s · 剩余约 %s · 已用 %s" % (
            pct, self.files, self.total_files, fmt_size(self.done), fmt_size(self.total), fmt_rate(speed), fmt_dur(eta), fmt_dur(el))
        if self.errors:
            txt += " · %d 个错误" % self.errors
        self.stat.configure(text=txt)
        self.cur.configure(text=("[%s] " % self.phase if self.phase else "") + self.cur_path)

    def finish(self, label, force_full):
        if force_full:
            self.done = self.total
        self.active = False
        self.render(True)
        self.cancel_btn.configure(state="disabled")
        self.cur.configure(text=label)

    @property
    def elapsed(self):
        return time.time() - self.t0


class App:
    def __init__(self, root):
        import queue
        self.root = root
        self.q = queue.Queue()
        self.pq = None
        self.vfs = None
        self.ready = False
        self.selftest_failure = None
        self.busy = False
        self.log_count = 0
        self.last_keys = None
        self.enc_dir = self.enc_header = self.enc_scan = self.enc_pub = self.enc_last_header = None
        self.dec_dir = self.dec_header = self.dec_scan = None
        self.dec_override = None
        self.dec_header_source = None
        # Explicit choices survive rescans; automatic choices are reconsidered.
        self.dec_header_explicit = False
        self.header_locations = {}
        self.header_choices = set()
        self.enc_header_source = None
        self.enc_previous_header = None
        self.mg_dir = self.mg_header = self.mg_vmk = self.mg_pub = None
        self.mg_header_source = None
        self.sf_in = self.sf_probe = self.sf_plain = self.sf_pub = None
        self.progress_boxes = []
        self._build()
        self.log("%s 桌面版 %s 已启动（卷格式 pqdisk-volume-v1 · 文件格式 v2 卷模式）。所有加解密都在本机进行。" % (APP_NAME, APP_VERSION))
        self.root.after(120, self._poll)
        self._start_selftest()

    # ---- infrastructure ---------------------------------------------------------------
    LOG_FILE = None
    DIAG_FILE = None

    def _file_log(self, text):
        if not self.LOG_FILE:
            return
        try:
            old = VolumeFS.read_file_bytes(self.LOG_FILE, 1024 * 1024) if os.path.lexists(self.LOG_FILE) else b""
            line = (time.strftime("%Y-%m-%d %H:%M:%S ") + text.rstrip("\n") + "\n").encode("utf-8")
            VolumeFS.write_file_bytes(self.LOG_FILE, (old + line)[-(1024 * 1024):])
        except Exception:
            pass

    def log(self, msg, cls="i"):
        self._file_log(("[%s] " % cls) + msg)
        ts = time.strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", "[%s] " % ts, "ts")
        self.log_text.insert("end", msg + "\n", cls)
        self.log_count += 1
        if self.log_count > 400:
            self.log_text.delete("1.0", "2.0")
            self.log_count -= 1
        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def wlog(self, msg, cls="i"):
        self.q.put(("log", msg, cls))

    def fail(self, e):
        self.log("错误：" + (str(e) or e.__class__.__name__), "er")

    def _poll(self):
        try:
            while True:
                item = self.q.get_nowait()
                kind = item[0]
                if kind == "log":
                    self.log(item[1], item[2])
                elif kind == "done":
                    _, cb, result, err = item
                    try:
                        cb(result, err)
                    except Exception as e:
                        self.fail(e)
                elif kind == "ask":
                    _, fn, evt, box = item
                    try:
                        box[0] = fn()
                    except Exception as e:
                        box[1] = e
                    finally:
                        evt.set()
        except Exception:
            pass
        for pb in self.progress_boxes:
            if pb.active:
                pb.render()
        self.root.after(120, self._poll)

    def run_worker(self, fn, on_done):
        def target():
            try:
                r = fn()
                self.q.put(("done", on_done, r, None))
            except BaseException as e:
                import traceback
                if not isinstance(e, PQError):
                    self._file_log("worker exception:\n" + traceback.format_exc())
                self.q.put(("done", on_done, None, e))
        threading.Thread(target=target, daemon=True).start()

    def _tk_exception(self, exc, val, tb):
        import traceback
        text = "".join(traceback.format_exception(exc, val, tb))
        self._file_log("tk callback exception:\n" + text)
        try:
            self.log("界面内部错误：%s" % val, "er")
        except Exception:
            pass

    def ask_main(self, fn):
        """Run fn on the UI thread and wait for its result (callable from a worker)."""
        if threading.current_thread() is threading.main_thread():
            return fn()
        evt = threading.Event()
        box = [None, None]
        self.q.put(("ask", fn, evt, box))
        evt.wait()
        if box[1] is not None:
            raise box[1]
        return box[0]

    def ensure_ready(self):
        if self.selftest_failure:
            raise PQError("启动自检未通过，已停用密钥生成 / 加密 / 解密：" + str(self.selftest_failure))
        if not self.ready:
            raise PQError("启动自检尚未完成，请稍候。")

    def _start_selftest(self):
        def work():
            if not HAVE_CRYPTOGRAPHY:
                raise PQError("缺少 cryptography 库。请先执行：pip install cryptography  （%s）" % CRYPTOGRAPHY_IMPORT_ERROR)
            name, _ = _argon2_backend()
            pq = PQCrypto()
            t = time.time()
            pq.self_test(SELFTEST_ARGON)
            return pq, name, time.time() - t

        def done(r, err):
            if err is not None:
                self.selftest_failure = err
                self.chips.configure(text="自检：未通过", foreground="#b02a2a")
                self.banner.configure(text="⚠ 启动自检未通过，已永久禁用密钥生成 / 加密 / 解密以防产出不安全文件：" + str(err))
                self.banner.grid()
                self.log("⚠ 启动自检未通过，已永久禁用加解密：" + str(err), "er")
                self._refresh_buttons()
                return
            self.pq, backend, dt = r
            self.vfs = VolumeFS(self.pq)
            self.ready = True
            self.chips.configure(text="自检通过 · AES-256-GCM / SHA-512 / X25519 / Argon2id：%s · ML-KEM-1024 / ML-DSA-87：pqcrypto 原生后端" % backend, foreground="#1f6f3f")
            self.log("启动自检通过（%.1f 秒）：单文件 / 卷模式加解密流水线、密钥槽、流式往返、ML-KEM-1024 / ML-DSA-87 参数集、篡改 / 错误口令拒绝均正常。" % dt, "ok")
            self._refresh_buttons()
        self.chips.configure(text="自检进行中…")
        self.run_worker(work, done)

    def _refresh_buttons(self):
        ok = self.ready and not self.selftest_failure and not self.busy
        self.gen_btn.configure(state="normal" if ok else "disabled")
        self.enc_btn.configure(state="normal" if ok and self.enc_scan is not None else "disabled")
        self.dec_btn.configure(state="normal" if ok and self.dec_header is not None else "disabled")
        self.mg_unlock_btn.configure(state="normal" if ok and self.mg_header is not None and self.mg_vmk is None else "disabled")
        for b in (self.mg_addpw_btn, self.mg_addpk_btn, self.mg_write_btn):
            b.configure(state="normal" if ok and self.mg_vmk is not None else "disabled")
        self.mg_conv_btn.configure(state="normal" if ok and self.mg_vmk is not None and self.mg_dir else "disabled")
        if self.mg_header:
            self.mg_conv_btn.configure(text="切换为显示文件名（当前：隐藏）" if self.mg_header["hide_names"] else "切换为隐藏文件名（当前：显示）")
        for b in (self.enc_pick_btn, self.enc_scan_btn, self.enc_load_btn, self.dec_pick_btn, self.dec_scan_btn, self.dec_diag_btn, self.dec_load_btn, self.mg_pick_btn, self.mg_load_btn):
            b.configure(state="disabled" if self.busy else "normal")
        self.sf_dec_btn.configure(state="normal" if ok and self.sf_in is not None else "disabled")
        self.sf_enc_btn.configure(state="normal" if ok and self.sf_plain is not None else "disabled")

    def set_busy(self, busy):
        self.busy = busy
        self._refresh_buttons()

    # ---- password helpers (UI thread) ---------------------------------------------------------
    def gate_password(self, pw, purpose):
        r = password_strength(pw)
        if r["blocked"]:
            raise PQError(purpose + "：口令不可用：" + r["reason"])
        if r["score"] <= 1:
            msg = ("%s：口令强度“%s”（约 %d bit）。\n口令槽的安全性完全取决于口令本身，弱口令可被离线穷举。\n" % (purpose, r["label"], r["bits"]))
            if r["warnings"]:
                msg += "提示：" + "；".join(r["warnings"]) + "\n"
            msg += "\n仍要用这个口令继续吗？"
            if not messagebox.askyesno("口令过弱", msg):
                raise PQError(purpose + "：已取消（口令过弱）。")
            self.log("警告：你选择了强度为“%s”的口令继续。" % r["label"], "w")
        for h in password_hints(pw):
            self.log("提示：" + h, "w")
        return normalize_password(pw)

    def confirm_kdf_cost(self, t, m, p, what):
        msg = kdf_cost_exceeds_default(t, m, p)
        if not msg:
            return
        self.log("注意：%s：%s" % (what, msg), "w")
        if not messagebox.askyesno("口令派生参数偏高", what + "\n\n" + msg + "\n\n仍要继续吗？"):
            raise PQError("已取消：未执行高成本的口令派生。")

    def try_password_variants(self, pw, fn):
        nfc = normalize_password(pw)
        try:
            return fn(nfc)
        except PQError as e:
            if e.code != "BAD_PASSWORD" or nfc == pw:
                raise
            self.wlog("按 NFC 规范化的口令未匹配，改用原始字节重试一次…", "w")
            return fn(pw)

    # ---- file dialogs ----------------------------------------------------------------------------
    def pick_directory(self, title):
        path = filedialog.askdirectory(title=title, mustexist=True)
        if not path:
            return None
        return os.path.normpath(path)

    def save_header_dialog(self, header, why=""):
        name = "pqdisk-%s.pqvolume" % vol_id_short(header)
        path = filedialog.asksaveasfilename(title="保存卷头备份" + ("（%s）" % why if why else ""), initialfile=name,
                                            defaultextension=".pqvolume", filetypes=[("卷头备份", "*.pqvolume"), ("所有文件", "*.*")])
        if not path:
            self.log("未保存卷头备份。卷头 .pqvolume 丢失 = 全卷无法解密，请务必另存一份。", "w")
            return None
        write_text_file(path, header_json(header))
        self.log("卷头备份已保存：" + path, "ok")
        return path

    def load_header_file(self, path):
        return self.vfs.read_header_file(path)

    def load_pub_file(self, path):
        obj = read_json_file(path)
        self.pq.validate_pub(obj)
        fp = self.pq.fingerprint(b64decode(obj["x25519_pub"]), b64decode(obj["mlkem_pub"]))
        return obj, fp

    # ---- layout ------------------------------------------------------------------------------------
    def _section(self, parent, row, title=None, padding=(10, 6)):
        f = ttk.LabelFrame(parent, text=title, padding=padding) if title else ttk.Frame(parent, padding=padding)
        f.grid(row=row, column=0, sticky="ew", padx=8, pady=4)
        f.columnconfigure(0, weight=1)
        return f

    def _wrapped(self, parent, text, color=None, **kw):
        lbl = ttk.Label(parent, text=text, wraplength=860, justify="left")
        if color:
            lbl.configure(foreground=color)
        lbl.pack(anchor="w", fill="x", **kw)
        return lbl

    def _build(self):
        root = self.root
        root.title("pqdiskcrypt · 抗量子硬盘加密工具（桌面版）")
        root.geometry("1020x780")
        root.minsize(880, 620)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)
        top = ttk.Frame(root, padding=(10, 8, 10, 2))
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(0, weight=1)
        ttk.Label(top, text="pqdiskcrypt", font=_ui_font(16, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(top, text="Post-Quantum Disk Encryption · 桌面版（不需要浏览器，数据不出本机）", foreground="#666").grid(row=1, column=0, sticky="w")
        self.chips = ttk.Label(top, text="", foreground="#666")
        self.chips.grid(row=2, column=0, sticky="w", pady=(2, 0))
        self.banner = ttk.Label(top, text="", foreground="#b02a2a", wraplength=960, justify="left")
        self.banner.grid(row=3, column=0, sticky="w", pady=(2, 0))
        self.banner.grid_remove()

        paned = ttk.PanedWindow(root, orient="vertical")
        paned.grid(row=1, column=0, sticky="nsew")
        nb = self.nb = ttk.Notebook(paned)
        tabs = {}
        for key, title in (("keys", "密钥"), ("enc", "加密硬盘"), ("dec", "解密硬盘"), ("mg", "卷管理"), ("single", "单文件")):
            sf = ScrollFrame(nb)
            sf.inner.columnconfigure(0, weight=1)
            nb.add(sf.outer, text="  " + title + "  ")
            tabs[key] = sf.inner
        paned.add(nb, weight=4)
        logf = ttk.Frame(paned, padding=(8, 4))
        logf.columnconfigure(0, weight=1)
        logf.rowconfigure(1, weight=1)
        head = ttk.Frame(logf)
        head.grid(row=0, column=0, sticky="ew")
        ttk.Label(head, text="运行日志", font=_ui_font(10, "bold")).pack(side="left")
        ttk.Button(head, text="⌫ 清除敏感状态并重置", command=self.on_clear).pack(side="right")
        self.log_text = tk.Text(logf, height=8, wrap="word", state="disabled", font=_mono_font(9))
        sb = ttk.Scrollbar(logf, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)
        self.log_text.grid(row=1, column=0, sticky="nsew")
        sb.grid(row=1, column=1, sticky="ns")
        for tag, color in (("ts", "#888"), ("i", "#222"), ("ok", "#1f6f3f"), ("w", "#a05a00"), ("er", "#b02a2a")):
            self.log_text.tag_configure(tag, foreground=color)
        paned.add(logf, weight=1)

        self._build_keys(tabs["keys"])
        self._build_enc(tabs["enc"])
        self._build_dec(tabs["dec"])
        self._build_mg(tabs["mg"])
        self._build_single(tabs["single"])
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.report_callback_exception = self._tk_exception
        self._refresh_buttons()

    # ---- tab: keys ------------------------------------------------------------------------------
    def _build_keys(self, p):
        s = self._section(p, 0, "生成身份密钥对（可选）")
        self._wrapped(s, "用口令即可加密硬盘；若想用公钥保护（加密时只需 .pub，解密必须有 .key，适合把私钥放在别处保管、或让别人为你加密），先在这里生成 X25519 + ML-KEM-1024 混合密钥对（附带 ML-DSA-87 签名身份）。公钥 (.pub) 可公开；私钥 (.key) 务必自己保密，默认会用口令加密后再落盘。")
        row = ttk.Frame(s)
        row.pack(anchor="w", pady=(6, 0))
        self.gen_btn = ttk.Button(row, text="⚿ 生成密钥对", command=self.on_gen)
        self.gen_btn.pack(side="left")
        self.fp_label = ttk.Label(s, text="公钥指纹：—（卷头里会记录此指纹，解密时据此提示需要哪把私钥）")
        self.fp_label.pack(anchor="w", pady=(6, 0))
        self.sfp_label = ttk.Label(s, text="签名指纹：—（签名身份；硬盘加密不使用）")
        self.sfp_label.pack(anchor="w")

        s = self._section(p, 1, "▣ 公钥 key.pub：加密硬盘时选它作为密钥槽，可放心公开")
        row = ttk.Frame(s)
        row.pack(anchor="w")
        self.save_pub_btn = ttk.Button(row, text="保存 .pub…", command=self.on_save_pub, state="disabled")
        self.save_pub_btn.pack(side="left")
        self.pub_peek = tk.Text(s, height=5, wrap="none", state="disabled", font=_mono_font(8))
        self.pub_peek.pack(fill="x", pady=(6, 0))

        s = self._section(p, 2, "▲ 私钥 key.key：解锁卷的钥匙，绝不分享，妥善备份")
        self.key_prot = tk.StringVar(value="pw")
        row = ttk.Frame(s)
        row.pack(anchor="w")
        ttk.Label(row, text="落盘保护：").pack(side="left")
        ttk.Radiobutton(row, text="口令加密（推荐）", variable=self.key_prot, value="pw", command=self._keys_refresh).pack(side="left")
        ttk.Radiobutton(row, text="明文导出", variable=self.key_prot, value="raw", command=self._keys_refresh).pack(side="left", padx=(10, 0))
        prot = ttk.Frame(s)
        prot.pack(anchor="w", fill="x", pady=(4, 0))
        prot.columnconfigure(0, weight=1)
        self.key_pw_box = ttk.Frame(prot)
        self.key_pw_box.grid(row=0, column=0, sticky="ew")
        self.key_pw = tk.StringVar()
        self.key_pw2 = tk.StringVar()
        r1 = ttk.Frame(self.key_pw_box)
        r1.pack(anchor="w")
        ttk.Label(r1, text="私钥口令", width=12).pack(side="left")
        PasswordEntry(r1, self.key_pw, meter=True).frame.pack(side="left")
        r2 = ttk.Frame(self.key_pw_box)
        r2.pack(anchor="w", pady=(3, 0))
        ttk.Label(r2, text="再输一次", width=12).pack(side="left")
        PasswordEntry(r2, self.key_pw2).frame.pack(side="left")
        self.key_raw_warn = ttk.Label(prot, text="警告：明文私钥文件未经任何加密，任何拿到它的人都能解锁用此公钥保护的全部硬盘。仅在你能确保存储介质本身安全时使用。", wraplength=860, justify="left", foreground="#b02a2a")
        self.key_raw_warn.grid(row=1, column=0, sticky="ew")
        row = ttk.Frame(s)
        row.pack(anchor="w", pady=(6, 0))
        self.save_key_btn = ttk.Button(row, text="保存 .key…", command=self.on_save_key, state="disabled")
        self.save_key_btn.pack(side="left")
        self.key_peek = tk.Text(s, height=5, wrap="none", state="disabled", font=_mono_font(8))
        self.key_peek.pack(fill="x", pady=(6, 0))
        self._wrapped(s, "提醒：私钥一旦丢失，只用它保护的卷将无法恢复（建议同时给卷加一个口令槽作为后备）；私钥一旦泄露，相关卷即不再安全。Python 无法可靠地从内存抹除密钥，敏感场景请用完即退出程序。", "#666", pady=(6, 0))
        self._keys_refresh()

    def _keys_refresh(self):
        if self.key_prot.get() == "pw":
            self.key_pw_box.grid()
            self.key_raw_warn.grid_remove()
        else:
            self.key_pw_box.grid_remove()
            self.key_raw_warn.grid()

    def _set_text(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    @staticmethod
    def redacted_key_preview(key_obj):
        secret = ("x25519_priv", "mlkem_secret", "mldsa_secret")
        view = {}
        for k, v in key_obj.items():
            view[k] = ("<%s · %d 字节 · 已隐藏，不在界面上显示>" % (k, len(b64decode(v)))) if k in secret else v
        return json.dumps(view, indent=2, ensure_ascii=False)

    def on_gen(self):
        try:
            self.ensure_ready()
        except Exception as e:
            self.fail(e)
            return
        self.set_busy(True)
        self.log("生成 X25519 + ML-KEM-1024 + ML-DSA-87 密钥对…")

        def done(kp, err):
            self.set_busy(False)
            if err is not None:
                self.fail(err)
                return
            self.last_keys = kp
            self.fp_label.configure(text="公钥指纹：" + kp["fingerprint"] + "（卷头里会记录此指纹，解密时据此提示需要哪把私钥）")
            self.sfp_label.configure(text="签名指纹：" + (kp["signerFingerprint"] or "—") + "（签名身份；硬盘加密不使用）")
            self._set_text(self.pub_peek, json.dumps(kp["pub"], indent=2, ensure_ascii=False))
            self._set_text(self.key_peek, self.redacted_key_preview(kp["key"]))
            self.save_pub_btn.configure(state="normal")
            self.save_key_btn.configure(state="normal")
            self.log("密钥对已生成。公钥指纹 " + kp["fingerprint"], "ok")
            self.log("私钥内容不会显示在界面上；请立即保存 .key 并妥善备份。")
        self.run_worker(lambda: self.pq.generate_keypair(), done)

    def on_save_pub(self):
        if not self.last_keys:
            return
        path = filedialog.asksaveasfilename(title="保存公钥", initialfile="key.pub", defaultextension=".pub", filetypes=[("公钥文件", "*.pub"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            write_text_file(path, json.dumps(self.last_keys["pub"], indent=2, ensure_ascii=False))
            self.log("已保存公钥：" + path, "ok")
        except Exception as e:
            self.fail(e)

    def on_save_key(self):
        if not self.last_keys:
            return
        try:
            if self.key_prot.get() == "pw":
                pw, pw2 = self.key_pw.get(), self.key_pw2.get()
                if not pw:
                    raise PQError("请先设置用于保护私钥的口令")
                if pw != pw2:
                    raise PQError("两次口令不一致")
                pw_n = self.gate_password(pw, "私钥口令")
                self.ensure_ready()
                path = filedialog.asksaveasfilename(title="保存私钥（口令保护）", initialfile="key.key", defaultextension=".key", filetypes=[("私钥文件", "*.key"), ("所有文件", "*.*")])
                if not path:
                    return
                self.set_busy(True)
                self.log("用 Argon2id + AES-256-GCM（含密钥承诺）加密私钥（%d MiB / t=%d / p=%d），稍候…" % (ARGON_MEM_KIB // 1024, ARGON_TIME, ARGON_PAR))
                keys = self.last_keys

                def done(cont, err):
                    self.set_busy(False)
                    if err is not None:
                        self.fail(err)
                        return
                    try:
                        write_text_file(path, json.dumps(cont, indent=2, ensure_ascii=False))
                        self.log("已保存【受口令保护】的私钥：%s（解锁卷时需要此口令）" % path, "ok")
                    except Exception as e:
                        self.fail(e)
                self.run_worker(lambda: self.pq.wrap_secret_key(keys["key"], pw_n), done)
            else:
                if not messagebox.askyesno("明文导出私钥", "你正在导出【未加密】的明文私钥。任何拿到该文件的人都能解锁用此公钥保护的全部硬盘。\n确定要以明文导出吗？"):
                    raise PQError("已取消明文导出。")
                path = filedialog.asksaveasfilename(title="保存私钥（明文）", initialfile="key.key", defaultextension=".key", filetypes=[("私钥文件", "*.key"), ("所有文件", "*.*")])
                if not path:
                    return
                write_text_file(path, json.dumps(self.last_keys["key"], indent=2, ensure_ascii=False))
                self.log("已保存【明文】私钥 %s（未加密，务必妥善保管）" % path, "w")
        except Exception as e:
            self.fail(e)

    # ---- tab: encrypt ----------------------------------------------------------------------------
    def _build_enc(self, p):
        s = self._section(p, 0)
        self._wrapped(s, "选择一块移动硬盘、U 盘的根目录或任意文件夹。首次加密前请手动选择卷头保存位置；保存成功后才逐文件加密。已有可用卷头时继续使用，解密后也保留它。程序不会额外生成 .pqvolume。")
        s = self._section(p, 1, "① 目标")
        row = ttk.Frame(s)
        row.pack(anchor="w", fill="x")
        self.enc_path = tk.StringVar()
        ttk.Entry(row, textvariable=self.enc_path, width=60).pack(side="left", fill="x", expand=True)
        self.enc_pick_btn = ttk.Button(row, text="📁 浏览…", command=lambda: self.on_pick("enc"))
        self.enc_pick_btn.pack(side="left", padx=(6, 0))
        self.enc_scan_btn = ttk.Button(row, text="扫描", command=lambda: self.on_scan("enc"))
        self.enc_scan_btn.pack(side="left", padx=(6, 0))
        self.enc_load_btn = ttk.Button(row, text="载入卷头…", command=self.on_enc_load_header)
        self.enc_load_btn.pack(side="left", padx=(6, 0))
        self.enc_dir_info = self._wrapped(s, "未选择。可直接选择盘符根目录（如 E:\\）或任意文件夹。", "#666", pady=(4, 0))
        self.enc_scan_info = self._wrapped(s, "", pady=(2, 0))

        s = self.enc_new_box = self._section(p, 2, "② 解锁方式（新卷的密钥槽）")
        self.enc_slot_mode = tk.StringVar(value="pw")
        row = ttk.Frame(s)
        row.pack(anchor="w")
        for text, val in (("口令", "pw"), ("抗量子公钥 (.pub)", "pk"), ("口令 + 公钥", "both")):
            ttk.Radiobutton(row, text=text, variable=self.enc_slot_mode, value=val, command=self._enc_refresh).pack(side="left", padx=(0, 10))
        slots = ttk.Frame(s)
        slots.pack(anchor="w", fill="x")
        slots.columnconfigure(0, weight=1)
        self.enc_pw_box = ttk.Frame(slots)
        self.enc_pw_box.grid(row=0, column=0, sticky="ew", pady=(4, 0))
        self.enc_pw = tk.StringVar()
        self.enc_pw2 = tk.StringVar()
        r1 = ttk.Frame(self.enc_pw_box)
        r1.pack(anchor="w")
        ttk.Label(r1, text="卷口令", width=12).pack(side="left")
        PasswordEntry(r1, self.enc_pw, meter=True).frame.pack(side="left")
        r2 = ttk.Frame(self.enc_pw_box)
        r2.pack(anchor="w", pady=(3, 0))
        ttk.Label(r2, text="再输一次", width=12).pack(side="left")
        PasswordEntry(r2, self.enc_pw2).frame.pack(side="left")
        self.enc_pk_box = ttk.Frame(slots)
        self.enc_pk_box.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        ttk.Button(self.enc_pk_box, text="选择 .pub 公钥…", command=lambda: self.on_pick_pub("enc")).pack(side="left")
        self.enc_pub_label = ttk.Label(self.enc_pk_box, text="未载入公钥（只有对应的 .key 私钥能解锁此卷）", foreground="#666")
        self.enc_pub_label.pack(side="left", padx=(8, 0))

        s = self.enc_exist_box = self._section(p, 3, "② 此目录已经是一个加密卷")
        self.enc_exist_info = self._wrapped(s, "本次会把其中尚未加密的新文件并入该卷；需要先用卷现有的口令或私钥解锁。")
        self.enc_unlock = UnlockBox(self, s, "用卷现有的口令 / 私钥解锁")
        self.enc_unlock.frame.pack(fill="x", pady=(4, 0))
        self.enc_exist_box.grid_remove()

        s = self._section(p, 4, "③ 选项")
        self.enc_hide = tk.BooleanVar(value=False)
        self.enc_verify = tk.BooleanVar(value=True)
        self.enc_keep = tk.BooleanVar(value=False)
        self.enc_recreate = tk.BooleanVar(value=False)
        ttk.Checkbutton(s, text="重新创建卷并更换口令 / 密钥（仅全部解密后可用；替换原卷头）", variable=self.enc_recreate,
                        command=lambda: self.on_scan("enc")).pack(anchor="w")
        self.enc_hide_cb = ttk.Checkbutton(s, text="隐藏文件名与目录结构（文件与目录改成随机 ID，原名存于各目录的加密清单；加密后可在“卷管理”页切换）", variable=self.enc_hide)
        self.enc_hide_cb.pack(anchor="w")
        ttk.Checkbutton(s, text="删除原文件前重新读取密文并完整校验认证标签（推荐；耗时约翻倍）", variable=self.enc_verify).pack(anchor="w")
        ttk.Checkbutton(s, text="保留原文件，只生成加密副本（试运行；硬盘上将同时存在明文与密文）", variable=self.enc_keep).pack(anchor="w")
        row = ttk.Frame(s)
        row.pack(anchor="w", pady=(4, 0))
        ttk.Label(row, text="卷名称（可选，明文存于卷头）").pack(side="left", padx=(0, 8))
        self.enc_label = tk.StringVar()
        ttk.Entry(row, textvariable=self.enc_label, width=30).pack(side="left")

        s = self._section(p, 5)
        row = ttk.Frame(s)
        row.pack(anchor="w")
        self.enc_btn = ttk.Button(row, text="🔒 加密整个目录", command=self.on_enc_start)
        self.enc_btn.pack(side="left")
        self.enc_dl_btn = ttk.Button(row, text="⬇ 再次保存卷头备份 (.pqvolume)…", command=lambda: self.enc_last_header and self.save_header_dialog(self.enc_last_header))
        self.enc_dl_btn.pack(side="left", padx=(10, 0))
        self.enc_dl_btn.pack_forget()
        pf = ttk.Frame(s)
        pf.pack(fill="x", pady=(6, 0))
        pf.columnconfigure(0, weight=1)
        self.enc_prog = ProgressBox(self, pf, "已完成的文件保持加密，正在处理的文件保留原样")
        self.enc_prog.frame.grid(row=0, column=0, sticky="ew")
        self.enc_prog.frame.grid_remove()
        self.progress_boxes.append(self.enc_prog)
        self.enc_done = self._wrapped(s, "", pady=(6, 0))

        s = self._section(p, 6)
        self._wrapped(s, "请务必知悉：这是文件级加密（不是 BitLocker / VeraCrypt 那样的全盘加密），不能加密系统盘或正在被占用的文件；被删除的原文件仍可能被数据恢复工具找回；加密过程中硬盘需有至少一个最大文件大小的可用空间；卷头 .pqvolume 丢失或损坏 = 全卷无法解密，新建卷时请务必另存一份备份。", "#666")
        ttk.Button(s, text="详细说明…", command=self.show_notes).pack(anchor="w", pady=(4, 0))
        self._enc_refresh()

    def _enc_refresh(self):
        m = self.enc_slot_mode.get()
        if m == "pk":
            self.enc_pw_box.grid_remove()
        else:
            self.enc_pw_box.grid()
        if m == "pw":
            self.enc_pk_box.grid_remove()
        else:
            self.enc_pk_box.grid()

    def show_notes(self):
        messagebox.showinfo("请务必知悉", (
            "① 这是文件级加密，不是 BitLocker / VeraCrypt 那样的扇区级全盘加密，不能加密系统盘或正在被其它程序占用的文件；文件大小、数量、修改时间等元数据仍可见（隐藏文件名模式只遮住名字）。\n\n"
            "② 被删除的原文件在磁盘上仍可能被数据恢复工具找回。若这块硬盘之前长期存放过明文，请对整盘做安全擦除或改用全盘加密，最稳妥的做法是先加密再把文件放进硬盘。\n\n"
            "③ 加密过程中硬盘需有至少一个最大文件大小的可用空间。\n\n"
            "④ 桌面版会保留文件的修改时间（浏览器版做不到）。\n\n"
            "⑤ 卷头丢失或损坏 = 全卷无法解密。首次加密时手动选择保存位置，保存成功后才开始加密；请妥善备份。\n\n"
            "⑥ 删除密钥槽不会更换卷主密钥。持有旧卷头和旧口令 / 私钥的人仍能解密本卷，包括之后新增的文件；彻底撤销访问需要新建卷并重新加密全部数据。多个槽是任选其一，不是双因素认证。\n\n"
            "⑦ 后量子运算使用 pqcrypto / PQClean 原生实现，但整套应用仍未经独立审计。口令槽取决于口令强度，操作系统被攻陷时无法保护已解锁数据。"))

    def on_pick(self, which):
        if self.busy:
            return
        path = self.pick_directory({"enc": "选择要加密的硬盘 / 文件夹", "dec": "选择加密卷所在目录", "mg": "选择加密卷所在目录"}[which])
        if not path:
            return
        getattr(self, which + "_path").set(path)
        if which == "enc":
            self.enc_done.configure(text="")
            self.enc_dl_btn.pack_forget()
            self.enc_prog.frame.grid_remove()
        elif which == "dec":
            self.dec_done.configure(text="")
            self.dec_prog.frame.grid_remove()
            self.dec_override = None
            self.dec_header_source = None
            self.dec_header_explicit = False
        self.on_scan(which)

    def on_scan(self, which, on_ready=None):
        if self.busy:
            return
        path = getattr(self, which + "_path").get().strip().strip('"')
        if not path:
            self.fail(PQError("请先选择或输入目录路径"))
            return
        path = os.path.abspath(os.path.normpath(path))
        if not os.path.isdir(path):
            self.fail(PQError("目录不存在或不可访问：" + path))
            return
        if which == "mg":
            self.mg_open_dir(path)
            return
        try:
            self.ensure_ready()
        except Exception as e:
            self.fail(e)
            return
        if which == "enc":
            self.enc_dir, self.enc_header, self.enc_scan = path, None, None
            self.enc_dir_info.configure(text=path + " · 扫描中…")
        else:
            # Compare before assigning: the old code compared path to itself.
            if not self.dec_dir or os.path.normcase(self.dec_dir) != os.path.normcase(path):
                self.dec_override = None
                self.dec_header_source = None
                self.dec_header_explicit = False
            self.dec_dir, self.dec_header, self.dec_scan = path, None, None
            self.dec_dir_info.configure(text=path + " · 扫描中…")
        self.log("已选择目录 %s，扫描中…" % path)
        self.set_busy(True)
        vfs = self.vfs
        override = self.dec_override if which == "dec" and self.dec_header_explicit else None
        source = self.dec_header_source if override is not None else None
        remembered = self.header_locations.get(os.path.normcase(path))
        explicit_enc = which == "enc" and remembered and os.path.normcase(path) in self.header_choices

        def work():
            status, header, herr = vfs.header_status(path)
            use = header
            selected_source = source
            source_error = None
            if override is not None:
                try:
                    use = vfs.read_header_file(source) if source else override
                except (OSError, PQError) as e:
                    use, selected_source, source_error = header, None, str(e)
            if which == "enc" and remembered:
                try:
                    use = vfs.read_header_file(remembered)
                    selected_source = remembered
                except (OSError, PQError) as e:
                    use, selected_source, source_error = header, None, str(e)
            vid = b64decode(use["volume_id"]) if use else None
            st = vfs.scan_tree(path, volume_id=vid, header_path=selected_source)
            candidates, hints = [], []
            try:
                candidates = vfs.find_header_candidates(path)
            except Exception as e:
                hints.append(str(e))
            if header is not None:
                candidates.insert(0, {"path": _volume_header_path(path), "header": header, "error": None})
            if remembered and not any(os.path.normcase(c["path"]) == os.path.normcase(remembered) for c in candidates):
                try:
                    candidates.append({"path": remembered, "header": vfs.read_header_file(remembered), "error": None})
                except (OSError, PQError) as e:
                    candidates.append({"path": remembered, "header": None, "error": str(e)})
            matches = [c for c in candidates if c["header"] is not None
                       and (not st["volumeIds"] or hexs(b64decode(c["header"]["volume_id"])) in st["volumeIds"])]
            if (override is None or source_error) and not (explicit_enc and not source_error):
                if len(matches) == 1:
                    use, selected_source = matches[0]["header"], matches[0]["path"]
                    st = vfs.scan_tree(path, volume_id=b64decode(use["volume_id"]), header_path=selected_source)
                    if header is not None and os.path.normcase(selected_source) == os.path.normcase(_volume_header_path(path)):
                        selected_source = None
                elif len(matches) >= 2:
                    use = header = None
                    st = vfs.scan_tree(path)
                    hints.append("发现 %d 份可用卷头，请选择本次使用的卷头文件。" % len(matches))
                elif candidates:
                    hints.append("未找到匹配卷头，请载入对应文件；卷头需与密文的完整卷 ID 一致。")
                for c in candidates:
                    if c["error"]:
                        hints.append(os.path.basename(c["path"]) + "：" + c["error"])
            parent = vfs.parent_header_hint(path)
            if parent:
                hints.append("上级目录存在卷头：%s。若选中了卷内子目录，请改选该卷头所在的根目录。" % parent)
            if st["nestedHeaders"]:
                hints.append("子目录中存在卷头：%s。请改选相应卷头所在的根目录。" % "、".join(st["nestedHeaders"][:8]))
            st["headerBlocksEncryption"] = bool(st["volumeIds"] or st["unreadable"] or st["damaged"] or parent or st["nestedHeaders"] or len(matches) >= 2)
            st["matchingHeaders"] = matches
            st["headerHint"] = "\n".join(hints)
            st["headerCandidates"] = candidates
            st["headerSource"] = selected_source or (_volume_header_path(path) if use is not None else None)
            st["sourceError"] = source_error
            if which == "enc":
                st["canRenew"] = not st["encrypted"] and vfs.can_start_new_volume(path)
            return status, header, herr, st, use, selected_source

        def done(r, err):
            self.set_busy(False)
            if err is not None:
                self.fail(err)
                getattr(self, which + "_dir_info").configure(text="扫描失败：" + str(err))
                return
            status, header, herr, st, use, selected_source = r
            if status == "invalid":
                self.log("目录 %s 的卷头 %s 无法读取或已损坏：%s。可在解密页载入卷头备份。" % (path, VOLUME_HEADER_NAME, herr), "er")
            for u in st["unreadable"]:
                self.log("无法读取：" + u, "w")
            for d in st["damaged"]:
                self.log("头部不完整（已损坏）：" + d, "w")
            if which == "enc":
                self.enc_header_source = st["headerSource"]
                self._enc_after_scan(path, use, st, "ok" if use is not None else status, herr)
            else:
                chosen = use if selected_source is not None else None
                self.dec_override, self.dec_header_source = chosen, selected_source
                if st.get("sourceError"):
                    self.dec_header_explicit = False
                if chosen is not None and override is None:
                    self.log("已识别匹配卷头：%s。本次从该文件读取，未改写目录中的卷头。" % selected_source, "ok")
                self._dec_after_scan(path, header, st, status, herr, chosen)
            if use is not None and st["headerSource"]:
                self.header_locations[os.path.normcase(path)] = st["headerSource"]
            if on_ready is not None and (status != "invalid" or use is not None or which == "dec"):
                on_ready()
        self.run_worker(work, done)

    @staticmethod
    def foreign_text(st):
        parts = []
        fv = st.get("foreignVolumes") or {}
        if fv:
            parts.append("%d 个属于其它卷（卷 ID %s）" % (sum(fv.values()), "、".join("%s… ×%d" % (k, n) for k, n in sorted(fv.items()))))
        if st.get("singleMode"):
            parts.append("%d 个是单文件模式的 .pqfc（请用 pqfilecrypt 解密）" % st["singleMode"])
        if st.get("damaged"):
            parts.append("%d 个头部不完整（已损坏）" % len(st["damaged"]))
        return "，".join(parts)

    def describe_scan(self, st, for_encrypt):
        if for_encrypt:
            txt = "将加密 %d 个文件，共 %s（最大单文件 %s，%d 个目录）" % (st["files"], fmt_size(st["bytes"]), fmt_size(st["largest"]), st["dirs"])
            if st["encrypted"]:
                txt += "；已属于本卷 %d 个（%s）将跳过" % (st["encrypted"], fmt_size(st["encryptedBytes"]))
            if st["foreign"]:
                txt += "；另有 %d 个 .pqfc 不属于本卷，将跳过（不二次加密）：%s（若你选中的是某个加密卷的子目录，请改选它的根目录）" % (st["foreign"], self.foreign_text(st))
        else:
            txt = "找到 %d 个本卷加密文件，共 %s" % (st["encrypted"], fmt_size(st["encryptedBytes"]))
            if st["files"]:
                txt += "；%d 个未加密文件将保持原样" % st["files"]
            if st["foreign"]:
                txt += "；另有 %d 个 .pqfc 不属于本卷，本次不会解密：%s" % (st["foreign"], self.foreign_text(st))
                if st.get("foreignVolumes"):
                    txt += "。要解密它们，请点“载入卷头备份”选择对应卷的 pqdisk-<卷 ID>.pqvolume"
        if st.get("notContainer"):
            txt += "；%d 个只是名字以 .pqfc 结尾的普通文件" % st["notContainer"]
        if st.get("unreadable"):
            txt += "；%d 个 .pqfc 无法读取（被占用 / 无权限，见日志）" % len(st["unreadable"])
        if st.get("links"):
            txt += "；%d 个符号链接 / 特殊文件将跳过" % st["links"]
        if st["skippedDirs"]:
            txt += "；跳过系统目录：" + "、".join(st["skippedDirs"])
        if st.get("free") is not None:
            txt += "；可用空间 " + fmt_size(st["free"])
        return txt

    def _enc_after_scan(self, path, header, st, status="ok", herr=None):
        self.enc_previous_header = header
        if header and self.enc_recreate.get():
            if not st.get("canRenew"):
                self.enc_scan = None
                self.enc_dir_info.configure(text=path + " · 尚有密文或未完成的内容，不能更换卷")
                self.enc_scan_info.configure(text="请先完整解密，再重新创建卷。原卷头保持不变。")
                self._refresh_buttons()
                return
            header = None
        self.enc_header, self.enc_scan = header, st
        self.enc_scan_info.configure(text=self.describe_scan(st, True))
        if status == "invalid":
            self.enc_scan = None
            self.enc_new_box.grid_remove()
            self.enc_exist_box.grid_remove()
            self.enc_dir_info.configure(text=path + " · 卷头 .pqvolume 已损坏，已停用加密以免造成两个卷混在一起")
            self.enc_scan_info.configure(text="卷头损坏：%s。请载入可用的卷头文件后重试。" % herr)
            self._refresh_buttons()
            return
        if header is None and st.get("headerHint") and st.get("headerBlocksEncryption", True):
            self.enc_scan = None
            self.enc_new_box.grid_remove()
            self.enc_exist_box.grid_remove()
            self.enc_dir_info.configure(text=path + " · 请先确认已有卷头的位置")
            self.enc_scan_info.configure(text=st["headerHint"] + "\n请点击“载入卷头…”选择本卷卷头。")
            self.log(st["headerHint"], "w")
            self._refresh_buttons()
            return
        if header:
            self.enc_new_box.grid_remove()
            self.enc_exist_box.grid()
            self.enc_hide.set(header["hide_names"])
            self.enc_hide_cb.configure(state="disabled")
            self.enc_exist_info.configure(text="卷 %s%s · 密钥槽：%s · 隐藏文件名：%s（可在“卷管理”页切换）。本次会把其中尚未加密的新文件并入该卷；需要先用卷现有的口令或私钥解锁。" % (
                vol_id_short(header), "“%s”" % header["label"] if header.get("label") else "", slot_summary(header), "是" if header["hide_names"] else "否"))
            self.enc_unlock.adapt(header)
            self.enc_dir_info.configure(text=path + " · 已是加密卷 " + vol_id_short(header))
            self.log("该目录已是加密卷 %s，尚未加密的新文件：%d 个。" % (vol_id_short(header), st["files"]))
        else:
            self.enc_exist_box.grid_remove()
            self.enc_new_box.grid()
            self.enc_hide_cb.configure(state="normal")
            self.enc_dir_info.configure(text=path + " · 新卷")
            self.log("扫描完成：待加密 %d 个文件，共 %s。" % (st["files"], fmt_size(st["bytes"])))
            if self.enc_previous_header:
                self.log("本次将创建新卷，并在原保存位置更新卷头。")
        self._refresh_buttons()

    def on_enc_load_header(self, path=None):
        if self.busy:
            return
        try:
            self.ensure_ready()
            root = self.enc_path.get().strip().strip('"')
            if not root or not os.path.isdir(root):
                raise PQError("请先选择要加密的目录")
            root = os.path.abspath(os.path.normpath(root))
            if path is None:
                path = filedialog.askopenfilename(title="载入本目录的卷头", initialdir=root,
                    filetypes=[("卷头文件", "*.pqvolume *.pqvolume.txt *.pqvolume.json"), ("所有文件", "*.*")])
            if not path:
                return
            self.load_header_file(path)
            self.header_locations[os.path.normcase(root)] = os.path.abspath(path)
            self.header_choices.add(os.path.normcase(root))
            self.on_scan("enc")
        except Exception as e:
            self.fail(e)

    def on_pick_pub(self, which):
        path = filedialog.askopenfilename(title="选择 .pub 公钥文件", filetypes=[("公钥文件", "*.pub"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            self.ensure_ready()
            obj, fp = self.load_pub_file(path)
            name = os.path.basename(path)
            if which == "enc":
                self.enc_pub = obj
                self.enc_pub_label.configure(text=name + " ✓  指纹 " + fp)
                self.log("已载入公钥 %s，指纹 %s（请确认这就是你自己 / 预期收件人的公钥）" % (name, fp))
            else:
                self.mg_pub = obj
                self.mg_pub_label.configure(text=name + " ✓  指纹 " + fp)
                self.log("已载入公钥 %s，指纹 %s" % (name, fp))
        except Exception as e:
            if which == "enc":
                self.enc_pub = None
                self.enc_pub_label.configure(text="未载入公钥")
            else:
                self.mg_pub = None
                self.mg_pub_label.configure(text="未载入公钥")
            self.fail(e)

    def on_enc_start(self, fresh_scan=False):
        if self.busy:
            return
        if not fresh_scan:
            self.enc_done.configure(text="")
            self.on_scan("enc", on_ready=lambda: self.on_enc_start(fresh_scan=True))
            return
        try:
            self.ensure_ready()
            if not self.enc_dir or self.enc_scan is None:
                raise PQError("请先选择要加密的硬盘 / 文件夹")
            st, header, path = self.enc_scan, self.enc_header, self.enc_dir
            if st["files"] == 0 and header and st["encrypted"] and not st.get("unreadable"):
                summary = "本卷现有密文将跳过，扫描未发现新增明文，无需重复加密。"
                self.enc_done.configure(text=summary)
                self.log(summary, "ok")
                return
            keep = self.enc_keep.get()
            verify = self.enc_verify.get() or not keep
            if verify:
                self.enc_verify.set(True)
            hide = header["hide_names"] if header else self.enc_hide.get()
            label = (self.enc_label.get() or "").strip()
            mode = self.enc_slot_mode.get()
            want_pw = not header and mode in ("pw", "both")
            want_pk = not header and mode in ("pk", "both")
            pw_n = None
            if want_pw:
                pw, pw2 = self.enc_pw.get(), self.enc_pw2.get()
                if not pw:
                    raise PQError("卷口令不能为空")
                if pw != pw2:
                    raise PQError("两次口令不一致")
                pw_n = self.gate_password(pw, "卷口令")
            if want_pk and not self.enc_pub:
                raise PQError("请先载入 .pub 公钥")
            if st["files"] == 0:
                raise PQError("该目录里没有需要加密的文件" + ("（全部已属于本卷）" if header else "") + "。")
            spec = self.enc_unlock.snapshot(header) if header else None
            how = "用卷现有密钥槽解锁后加入" if header else ("口令槽" if want_pw else "") + (" + " if want_pw and want_pk else "") + ("公钥槽" if want_pk else "")
            msg = "即将加密目录「%s」：\n· %d 个文件，共 %s（最大单文件 %s）\n· 解锁方式：%s\n· 隐藏文件名与目录结构：%s；写入后校验：%s；删除原文件：%s\n" % (
                path, st["files"], fmt_size(st["bytes"]), fmt_size(st["largest"]), how, "是" if hide else "否", "是" if verify else "否", "否（保留）" if keep else "是")
            if st["foreign"]:
                msg += "· 注意：目录里有 %d 个 .pqfc 不属于本卷，将跳过（不二次加密）：%s。\n" % (st["foreign"], self.foreign_text(st))
                if not header and st.get("foreignVolumes"):
                    msg += "· 你将在这里新建一个卷；上述其它卷的密文只能用它们各自的卷头备份解密。若这些密文原本就是这个目录的，请先用备份恢复卷头而不是新建卷。\n"
            if st.get("free") is not None and st["free"] < st["largest"] + 1024 * 1024:
                msg += "· 警告：可用空间（%s）小于最大单文件（%s），大文件可能加密失败。\n" % (fmt_size(st["free"]), fmt_size(st["largest"]))
            if not header:
                msg += ("· 新卷头将替换之前选择的卷头文件。\n" if self.enc_previous_header else
                        "· 请手动选择卷头保存位置；保存成功后才开始加密，取消保存则不处理文件。\n")
            msg += "· 被删除的原文件仍可能被数据恢复工具找回（见说明）。\n\n确定开始？"
            if not messagebox.askyesno("确认加密", msg):
                raise PQError("已取消。")
        except Exception as e:
            self.fail(e)
            return
        self.set_busy(True)
        self.enc_done.configure(text="")
        self.enc_dl_btn.pack_forget()
        cancel = self.enc_prog.start(st["bytes"] * (2 if verify else 1), st["files"])
        pq, vfs, pub, unlock = self.pq, self.vfs, self.enc_pub, self.enc_unlock
        header_source = self.enc_header_source
        previous_header = self.enc_previous_header if not header else None

        def work():
            if header:
                u = unlock.unlock(spec, header)
                vmk, vid, hdr = u["vmk"], u["volumeId"], header
                self.wlog("卷已解锁（密钥槽 #%d）。" % (u["slotIndex"] + 1), "ok")
            else:
                vol = pq.new_volume(hide_names=hide, label=label)
                hdr, vmk, vid = vol["header"], vol["vmk"], vol["volumeId"]
                if want_pw:
                    self.wlog("Argon2id 派生口令槽（%d MiB / t=%d / p=%d），稍候…" % (ARGON_MEM_KIB // 1024, ARGON_TIME, ARGON_PAR))
                    pq.add_password_slot(hdr, vmk, pw_n)
                if want_pk:
                    self.wlog("混合 KEM：X25519 + ML-KEM-1024 → 公钥槽…")
                    pq.add_pubkey_slot(hdr, vmk, pub)
                target = header_source if previous_header is not None else self.ask_main(lambda: filedialog.asksaveasfilename(
                    title="选择卷头保存位置（保存成功后开始加密）", initialfile="pqdisk-%s.pqvolume" % vol_id_short(hdr),
                    defaultextension=".pqvolume", filetypes=[("卷头文件", "*.pqvolume"), ("所有文件", "*.*")]))
                if not target:
                    wipe(vmk)
                    raise PQError("已取消保存卷头，未开始加密。", "ABORTED")
                target = os.path.abspath(target)
                try:
                    with _volume_lock(path):
                        _check_cancel(cancel)
                        if previous_header is not None:
                            if not vfs.can_start_new_volume(path):
                                raise PQError("目录仍有密文或未完成的内容，不能替换卷头", "VOLUME_CHANGED")
                            current = vfs.read_header_file(target)
                            if current != previous_header:
                                raise PQError("原卷头已变化，未替换，请重新扫描", "VOLUME_CHANGED")
                        elif os.path.lexists(target):
                            raise PQError("所选文件已存在，未覆盖。请选择新文件名；要替换本卷卷头，请先载入它并勾选重新创建卷。", "OUTPUT_EXISTS")
                        if os.path.basename(target) in (DIR_MANIFEST_NAME, LOCK_NAME) or os.path.basename(target).startswith(TMP_PREFIX):
                            raise PQError("此文件名保留给卷内部数据，请选择其它卷头文件名")
                        vfs.save_encryption_header(path, hdr, target, previous_header=previous_header)
                        def remember_header():
                            self.header_locations[os.path.normcase(path)] = target
                            self.header_choices.add(os.path.normcase(path))
                            self.enc_header_source = target
                            self.enc_last_header = hdr
                            self.enc_recreate.set(False)
                            if self.dec_dir and os.path.normcase(self.dec_dir) == os.path.normcase(path):
                                self.dec_override = None
                                self.dec_header_source = None
                                self.dec_header_explicit = False
                        self.ask_main(remember_header)
                        self.wlog("卷 %s 的卷头已保存：%s。" % (vol_id_short(hdr), target), "ok")
                        return encrypt_with_header(vmk, vid, hdr, target)
                finally:
                    wipe(vmk)
            return encrypt_with_header(vmk, vid, hdr, header_source)

        def encrypt_with_header(vmk, vid, hdr, source):
            self.wlog("开始逐文件流式加密（AES-256-GCM，64 KiB 分块，逐文件独立密钥）%s%s%s…" % ("，隐藏文件名" if hide else "", "，写入后校验" if verify else "", "，保留原文件" if keep else ""))
            try:
                res = vfs.encrypt_tree(path, {"vmk": vmk, "volumeId": vid, "hideNames": hide}, keep_originals=keep, verify=verify, on_event=self.enc_prog.on_event, cancel=cancel, header_path=source)
            finally:
                wipe(vmk)
            return res, hdr

        def done(r, err):
            self.set_busy(False)
            if err is not None:
                self.enc_prog.finish("失败：" + str(err), False)
                self.fail(err)
                return
            res, hdr = r
            self.enc_last_header = hdr
            el = self.enc_prog.elapsed
            summary = ("已取消：" if res["cancelled"] else "完成：") + "加密 %d 个文件（%s）" % (res["files"], fmt_size(res["bytes"]))
            if res["reused"]:
                summary += "，其中 %d 个复用已认证且内容一致的密文" % res["reused"]
            if res["skipped"]:
                summary += "，跳过已加密 %d 个" % res["skipped"]
            if res["foreign"]:
                summary += "，跳过其它卷 / 单文件模式 %d 个" % res["foreign"]
            if res["errors"]:
                summary += "，失败 %d 个" % len(res["errors"])
            summary += "，用时 %s" % fmt_dur(el) + ("（约 %s）" % fmt_rate(res["bytes"] / el) if el > 0 else "")
            self.enc_prog.finish(summary, not res["cancelled"] and not res["errors"])
            self.log(summary, "w" if res["errors"] or res["cancelled"] else "ok")
            extra = " 失败的文件仍以明文保留在原位，修正问题（占用 / 权限 / 空间）后再运行一次即可。" if res["errors"] else ""
            self.enc_done.configure(text=summary + extra + " 卷头：" + (self.enc_header_source or "已保存"))
            self.enc_dl_btn.pack(side="left", padx=(10, 0))
            self.enc_path.set(path)
            self.on_scan("enc")
        self.run_worker(work, done)

    # ---- tab: decrypt ----------------------------------------------------------------------------
    def _build_dec(self, p):
        s = self._section(p, 0)
        self._wrapped(s, "选择加密时的根目录，并载入之前手动保存的卷头。工具会逐个解密 .pqfc、还原原文件名与目录结构；解密完成后保留卷头。")
        s = self._section(p, 1, "① 目标")
        row = ttk.Frame(s)
        row.pack(anchor="w", fill="x")
        self.dec_path = tk.StringVar()
        ttk.Entry(row, textvariable=self.dec_path, width=60).pack(side="left", fill="x", expand=True)
        self.dec_pick_btn = ttk.Button(row, text="📁 浏览…", command=lambda: self.on_pick("dec"))
        self.dec_pick_btn.pack(side="left", padx=(6, 0))
        self.dec_scan_btn = ttk.Button(row, text="扫描", command=lambda: self.on_scan("dec"))
        self.dec_scan_btn.pack(side="left", padx=(6, 0))
        self.dec_diag_btn = ttk.Button(row, text="诊断报告", command=self.on_diagnose)
        self.dec_diag_btn.pack(side="left", padx=(6, 0))
        self.dec_load_btn = ttk.Button(s, text="载入卷头文件 / 备份…", command=self.on_dec_load_header)
        self.dec_load_btn.pack(anchor="w", pady=(4, 0))
        self.dec_dir_info = self._wrapped(s, "未选择。解不开时点“诊断报告”：会逐个检查目录里每个文件的内容并写出报告，把报告发给开发者即可定位问题。", "#666", pady=(4, 0))
        self.dec_vol_info = self._wrapped(s, "", pady=(2, 0))
        self.dec_nohdr = ttk.Frame(s)
        self.dec_nohdr.pack(anchor="w", fill="x", pady=(4, 0))
        self.dec_nohdr_label = ttk.Label(self.dec_nohdr, wraplength=860, justify="left", foreground="#a05a00")
        self.dec_nohdr_label.pack(anchor="w")
        self.dec_nohdr.pack_forget()
        self.dec_scan_info = self._wrapped(s, "", pady=(2, 0))

        s = self._section(p, 2)
        self.dec_unlock = UnlockBox(self, s, "② 解锁")
        self.dec_unlock.frame.pack(fill="x")

        s = self._section(p, 3, "③ 选项")
        self.dec_keep = tk.BooleanVar(value=False)
        ttk.Checkbutton(s, text="保留密文文件与卷头（只还原出明文副本；同名文件已存在时不覆盖）", variable=self.dec_keep).pack(anchor="w")

        s = self._section(p, 4)
        self.dec_btn = ttk.Button(s, text="🔓 解密整个目录", command=self.on_dec_start)
        self.dec_btn.pack(anchor="w")
        pf = ttk.Frame(s)
        pf.pack(fill="x", pady=(6, 0))
        pf.columnconfigure(0, weight=1)
        self.dec_prog = ProgressBox(self, pf, "已还原的文件保留，正在处理的密文保持原样")
        self.dec_prog.frame.grid(row=0, column=0, sticky="ew")
        self.dec_prog.frame.grid_remove()
        self.progress_boxes.append(self.dec_prog)
        self.dec_done = self._wrapped(s, "", pady=(6, 0))

    def _dec_after_scan(self, path, header, st, status="ok", herr=None, override=None):
        use = override or header
        self.dec_header, self.dec_scan = use, st
        matches = st.get("matchingHeaders", [])
        if len(matches) >= 2:
            self.dec_load_btn.configure(text="选择卷头…")
            self.dec_load_btn.pack(anchor="w", pady=(4, 0))
        elif use is None or st.get("foreignVolumes") or status == "invalid":
            self.dec_load_btn.configure(text="载入卷头文件 / 备份…")
            self.dec_load_btn.pack(anchor="w", pady=(4, 0))
        else:
            self.dec_load_btn.pack_forget()
        if not use:
            self.dec_nohdr.pack(anchor="w", fill="x", pady=(4, 0), before=self.dec_scan_info)
            self.dec_nohdr_label.configure(text=("卷头无法读取或已损坏，请查看具体错误；可载入对应备份。" if status == "invalid" else
                "尚未选定可用卷头。可点击上方“载入卷头文件 / 备份”，直接选择你已有的卷头文件。"))
            self.dec_vol_info.configure(text="")
            hint = st.get("headerHint", "")
            if st.get("foreignVolumes"):
                hint += "\n目录里有 %s；请载入对应的卷头备份（pqdisk-<卷 ID>.pqvolume）。" % self.foreign_text(st)
            self.dec_scan_info.configure(text=hint)
            self.dec_dir_info.configure(text=path + (" · 卷头无法读取或已损坏：%s" % herr if status == "invalid" else
                                                   " · 发现卷头位置，请选择" if hint.strip() and st.get("headerHint") else " · 未找到卷头"))
            self.log(("卷头 %s 无法读取或已损坏（%s）。" % (VOLUME_HEADER_NAME, herr) if status == "invalid" else
                      st.get("headerHint") or "未在 %s 找到卷头 %s。" % (path, VOLUME_HEADER_NAME)) + "可载入卷头备份。", "w")
            self._refresh_buttons()
            return
        self.dec_nohdr.pack_forget()
        self.dec_vol_info.configure(text=self.vol_info_text(use) + ("\n卷头来源：%s（本次使用，未写回目录）" % self.dec_header_source if override else ""))
        self.dec_scan_info.configure(text=self.describe_scan(st, False))
        self.dec_unlock.adapt(use)
        self.dec_dir_info.configure(text=path + " · 加密卷 " + vol_id_short(use) + ("（来自备份）" if override else ""))
        self.log("卷 %s：本卷加密文件 %d 个（%s）。密钥槽：%s" % (vol_id_short(use), st["encrypted"], fmt_size(st["encryptedBytes"]), slot_summary(use)))
        if st["encrypted"] == 0 and st.get("foreignVolumes"):
            self.log("注意：目录里没有属于卷 %s 的密文，但有 %s。请载入那个卷的卷头备份。" % (vol_id_short(use), self.foreign_text(st)), "w")
        self._refresh_buttons()

    def vol_info_text(self, header):
        return "卷 %s%s · 创建于 %s · 隐藏文件名：%s · 密钥槽：%s" % (
            vol_id_short(header), " · 名称“%s”" % header["label"] if header.get("label") else "", fmt_date(header.get("created")),
            "是" if header["hide_names"] else "否", slot_summary(header))

    def on_dec_load_header(self, path=None):
        if self.busy:
            return
        try:
            self.ensure_ready()
            selected = self.dec_path.get().strip().strip('"')
            if not selected:
                raise PQError("请先选择加密卷所在目录")
            selected = os.path.abspath(os.path.normpath(selected))
            if not self.dec_dir or os.path.normcase(selected) != os.path.normcase(self.dec_dir) or self.dec_scan is None:
                self.on_scan("dec", on_ready=lambda: self.on_dec_load_header(path))
                return
            if not self.dec_dir:
                raise PQError("请先选择加密卷所在目录")
            if path is None:
                matches = self.dec_scan.get("matchingHeaders", [])
                if len(matches) == 1 and not self.dec_scan.get("foreignVolumes") and self.dec_header is None:
                    path = matches[0]["path"]
                else:
                    path = filedialog.askopenfilename(title="选择卷头" if len(matches) >= 2 else "载入卷头文件 / 备份", initialdir=self.dec_dir,
                        filetypes=[("卷头文件", "*.pqvolume *.pqvolume.txt *.pqvolume.json"), ("所有文件", "*.*")])
            if not path:
                return
            h = self.load_header_file(path)
            self.dec_override = h
            self.dec_header_source = os.path.abspath(path)
            self.dec_header_explicit = True
            self.header_locations[os.path.normcase(self.dec_dir)] = self.dec_header_source
            self.header_choices.add(os.path.normcase(self.dec_dir))
            self.log("已载入卷头 %s（卷 %s）；解密后保留该文件。" % (path, vol_id_short(h)), "ok")
            self.on_scan("dec")
        except Exception as e:
            self.fail(e)

    def on_dec_start(self, fresh_scan=False):
        if self.busy:
            return
        if not fresh_scan:
            self.on_scan("dec", on_ready=lambda: self.on_dec_start(fresh_scan=True))
            return
        try:
            self.ensure_ready()
            if not self.dec_dir or not self.dec_header or self.dec_scan is None:
                raise PQError("请先选择含卷头的加密卷目录")
            path, header, st = self.dec_dir, self.dec_header, self.dec_scan
            keep = self.dec_keep.get()
            if st["encrypted"] == 0:
                if st.get("foreignVolumes"):
                    raise PQError("该目录里没有属于卷 %s 的加密文件，但有 %s。请点“载入卷头备份”选择那个卷的 pqdisk-<卷 ID>.pqvolume 后再解密。" % (vol_id_short(header), self.foreign_text(st)))
                if st.get("singleMode"):
                    raise PQError("该目录里的 %d 个 .pqfc 是单文件模式的密文，不属于任何卷：请到“单文件”页逐个解密。" % st["singleMode"])
                if st.get("damaged"):
                    raise PQError("该目录里的 .pqfc 头部不完整（已损坏），无法解密：%s" % "、".join(st["damaged"][:5]))
                if st.get("unreadable"):
                    raise PQError("该目录里的 .pqfc 无法读取（被占用 / 无权限，见日志），没有可解密的文件。")
                raise PQError("该目录里没有属于本卷的加密文件（若有文件被改过名，点“诊断报告”按内容查找）。")
            spec = self.dec_unlock.snapshot(header)
            header_paths = [self.dec_header_source] if self.dec_header_source else []
            action_text = ("保留密文与卷头" if keep else
                           "删除密文；保留卷头，之后再次加密可继续使用")
            if not messagebox.askyesno("确认解密", "即将解密目录「%s」：\n· %d 个加密文件，共 %s\n· 还原后%s\n· 同名明文已存在的文件不会被覆盖\n\n确定开始？" % (
                    path, st["encrypted"], fmt_size(st["encryptedBytes"]), action_text)):
                raise PQError("已取消。")
        except Exception as e:
            self.fail(e)
            return
        self.set_busy(True)
        self.dec_done.configure(text="")
        cancel = self.dec_prog.start(st["encryptedBytes"], st["encrypted"])
        vfs, unlock = self.vfs, self.dec_unlock

        def work():
            u = unlock.unlock(spec, header)
            self.wlog("卷已解锁（密钥槽 #%d）。" % (u["slotIndex"] + 1), "ok")
            self.wlog("开始逐文件流式解密…")
            try:
                return vfs.decrypt_tree(path, {"vmk": u["vmk"], "volumeId": u["volumeId"], "hideNames": header["hide_names"]}, keep_originals=keep, on_event=self.dec_prog.on_event, cancel=cancel, remove_header=False, header_paths=header_paths)
            finally:
                wipe(u["vmk"])

        def done(res, err):
            self.set_busy(False)
            if err is not None:
                self.dec_prog.finish("失败：" + str(err), False)
                self.fail(err)
                return
            el = self.dec_prog.elapsed
            summary = ("已取消：" if res["cancelled"] else "完成：") + "还原 %d 个文件（%s）" % (res["files"], fmt_size(res["bytes"]))
            if res["skipped"]:
                summary += "，跳过 %d 个" % res["skipped"]
            if res["warnings"]:
                summary += "，警告 %d 个" % len(res["warnings"])
            if res["errors"]:
                summary += "，失败 %d 个" % len(res["errors"])
            summary += "，用时 %s" % fmt_dur(el) + ("（约 %s）" % fmt_rate(res["bytes"] / el) if el > 0 else "")
            summary += "；卷头保留"
            self.dec_prog.finish(summary, not res["cancelled"] and not res["errors"])
            self.log(summary, "w" if res["errors"] or res["cancelled"] else "ok")
            if self.dec_override is not None and st.get("foreign") and not res["cancelled"] and not res["errors"] and not res.get("kept"):
                self.dec_override = None
                self.dec_header_source = None
                self.dec_header_explicit = False
                self.log("所选卷头对应的文件已处理完毕，重新扫描目录。")
            extra = " 失败的密文原样保留、卷头也保留，修正问题后再运行一次即可。" if res["errors"] else ""
            if res.get("kept"):
                extra += " %d 个文件因同名文件已存在而未还原：它们的密文、目录清单和卷头都已保留，移走同名文件后再解密一次即可。" % res["kept"]
            if res["warnings"]:
                extra += " 有警告（例如目录清单缺失导致按 ID 命名），卷头已保留，请检查日志。"
            self.dec_done.configure(text=summary + extra)
            self.on_scan("dec")
        self.run_worker(work, done)

    # ---- tab: volume management ---------------------------------------------------------------------
    def _build_mg(self, p):
        s = self._section(p, 0)
        self._wrapped(s, "卷主密钥被每个密钥槽各自包裹，因此更换口令、追加公钥、吊销某把钥匙都只需改写卷头，无需重新加密整块硬盘。任何改动都会更新之前选择的卷头文件，改完请重新保存备份。")
        s = self._section(p, 1, "① 卷")
        row = ttk.Frame(s)
        row.pack(anchor="w", fill="x")
        self.mg_path = tk.StringVar()
        ttk.Entry(row, textvariable=self.mg_path, width=60).pack(side="left", fill="x", expand=True)
        self.mg_pick_btn = ttk.Button(row, text="📁 浏览…", command=lambda: self.on_pick("mg"))
        self.mg_pick_btn.pack(side="left", padx=(6, 0))
        self.mg_scan_btn = ttk.Button(row, text="读取卷头", command=lambda: self.on_scan("mg"))
        self.mg_scan_btn.pack(side="left", padx=(6, 0))
        self.mg_load_btn = ttk.Button(row, text="载入卷头备份…", command=self.on_mg_load_header)
        self.mg_load_btn.pack(side="left", padx=(6, 0))
        self.mg_dir_info = self._wrapped(s, "未选择。也可以只载入卷头备份文件来查看 / 改写它，再写回硬盘。", "#666", pady=(4, 0))
        self.mg_vol_info = self._wrapped(s, "", pady=(2, 0))
        self.mg_slots = ttk.Frame(s)
        self.mg_slots.pack(anchor="w", fill="x", pady=(4, 0))

        s = self._section(p, 2)
        self.mg_unlock = UnlockBox(self, s, "② 用现有口令 / 私钥解锁")
        self.mg_unlock.frame.pack(fill="x")
        self.mg_unlock_btn = ttk.Button(s, text="🔑 解锁卷", command=self.on_mg_unlock)
        self.mg_unlock_btn.pack(anchor="w", pady=(6, 0))

        s = self._section(p, 3, "③ 追加口令槽")
        self.mg_new_pw = tk.StringVar()
        self.mg_new_pw2 = tk.StringVar()
        r1 = ttk.Frame(s)
        r1.pack(anchor="w")
        ttk.Label(r1, text="新口令", width=12).pack(side="left")
        PasswordEntry(r1, self.mg_new_pw, meter=True).frame.pack(side="left")
        r2 = ttk.Frame(s)
        r2.pack(anchor="w", pady=(3, 0))
        ttk.Label(r2, text="再输一次", width=12).pack(side="left")
        PasswordEntry(r2, self.mg_new_pw2).frame.pack(side="left")
        self.mg_addpw_btn = ttk.Button(s, text="＋ 追加口令槽", command=self.on_mg_add_pw)
        self.mg_addpw_btn.pack(anchor="w", pady=(6, 0))

        s = self._section(p, 4, "④ 追加公钥槽")
        row = ttk.Frame(s)
        row.pack(anchor="w")
        ttk.Button(row, text="选择 .pub 公钥…", command=lambda: self.on_pick_pub("mg")).pack(side="left")
        self.mg_pub_label = ttk.Label(row, text="未载入公钥（对应的 .key 私钥将能解锁此卷）", foreground="#666")
        self.mg_pub_label.pack(side="left", padx=(8, 0))
        self.mg_addpk_btn = ttk.Button(s, text="＋ 追加公钥槽", command=self.on_mg_add_pk)
        self.mg_addpk_btn.pack(anchor="w", pady=(6, 0))

        s = self._section(p, 5, "⑤ 卷头")
        row = ttk.Frame(s)
        row.pack(anchor="w")
        self.mg_dl_btn = ttk.Button(row, text="⬇ 保存卷头备份…", command=lambda: self.mg_header and self.save_header_dialog(self.mg_header))
        self.mg_dl_btn.pack(side="left")
        self.mg_write_btn = ttk.Button(row, text="⬆ 更新所选卷头文件", command=self.on_mg_write)
        self.mg_write_btn.pack(side="left", padx=(8, 0))
        self._wrapped(s, "删除密钥槽只移除当前卷头中的入口，不会轮换卷主密钥。持有旧卷头和旧凭据的人仍能解密本卷，包括之后新增的文件；彻底撤销访问需要新建卷并重新加密。至少保留一个可用槽。", "#666", pady=(6, 0))

        s = self._section(p, 6, "⑥ 隐藏文件名（加密后也可以切换）")
        self._wrapped(s, "密文内容不依赖文件名，所以“隐藏 / 显示文件名”只是改名并增删目录清单，不重新加密、不动任何密文，几秒即可完成。需要先选择卷所在目录并解锁。")
        self.mg_conv_btn = ttk.Button(s, text="切换隐藏文件名", command=self.on_mg_convert)
        self.mg_conv_btn.pack(anchor="w", pady=(6, 0))

    def mg_open_dir(self, path):
        try:
            self.ensure_ready()
            self.mg_dir = path
            self.mg_set_header(None, "")
            self.mg_dir_info.configure(text=path + " · 读取卷头…")
            source = self.header_locations.get(os.path.normcase(os.path.abspath(path)))
            h = self.vfs.read_header_file(source) if source else self.vfs.read_volume_header(path)
            if h is None:
                available = [c for c in self.vfs.find_header_candidates(path) if c["header"] is not None]
                if len(available) == 1:
                    h, source = available[0]["header"], available[0]["path"]
            if h is not None:
                self.header_locations[os.path.normcase(os.path.abspath(path))] = source or _volume_header_path(path)
            if not h:
                candidates = self.vfs.find_header_candidates(path)
                parent = self.vfs.parent_header_hint(path)
                hint = ("发现卷头候选：" + "、".join(os.path.basename(c["path"]) for c in candidates)
                        if candidates else "上级目录存在卷头：" + parent if parent else "未找到卷头 .pqvolume")
                self.mg_dir_info.configure(text=path + " · " + hint + "；可载入对应卷头后解锁并写回")
                self.log(hint, "w")
                return
            self.mg_set_header(h, "硬盘 " + path, source or _volume_header_path(path))
            self.mg_dir_info.configure(text=path + " · 加密卷 " + vol_id_short(h))
        except Exception as e:
            self.mg_dir_info.configure(text=path + " · 卷头读取失败：" + str(e))
            self.fail(e)

    def on_mg_load_header(self):
        try:
            self.ensure_ready()
            path = filedialog.askopenfilename(title="载入卷头备份", filetypes=[("卷头备份", "*.pqvolume"), ("所有文件", "*.*")])
            if not path:
                return
            h = self.load_header_file(path)
            self.mg_set_header(h, "备份文件 " + os.path.basename(path), os.path.abspath(path))
            if self.mg_dir:
                self.header_locations[os.path.normcase(os.path.abspath(self.mg_dir))] = os.path.abspath(path)
        except Exception as e:
            self.fail(e)

    def mg_set_header(self, h, source, header_path=None):
        if self.mg_vmk is not None:
            wipe(self.mg_vmk)
        self.mg_vmk = None
        self.mg_header = h
        self.mg_header_source = header_path
        self.mg_render()
        if h:
            self.log("已载入卷头（%s）：卷 %s · 密钥槽：%s" % (source, vol_id_short(h), slot_summary(h)))

    def mg_render(self):
        for w in self.mg_slots.winfo_children():
            w.destroy()
        if not self.mg_header:
            self.mg_vol_info.configure(text="")
            self._refresh_buttons()
            return
        self.mg_vol_info.configure(text=self.vol_info_text(self.mg_header) + ("（已解锁）" if self.mg_vmk is not None else ""))
        for i, s in enumerate(self.mg_header["slots"]):
            row = ttk.Frame(self.mg_slots)
            row.pack(anchor="w", fill="x", pady=1)
            if s.get("type") == SLOT_PASSWORD:
                p = s.get("kdf_params") or {}
                txt = "#%d 口令槽 · Argon2id %s / t=%s / p=%s · 创建于 %s" % (i + 1, fmt_kib(p.get("m")), p.get("t"), p.get("p"), fmt_date(s.get("created")))
            else:
                txt = "#%d 公钥槽 · %s · 指纹 %s · 创建于 %s" % (i + 1, s.get("alg") or "X25519+ML-KEM-1024", s.get("fingerprint") or "?", fmt_date(s.get("created")))
            ttk.Label(row, text=txt).pack(side="left")
            b = ttk.Button(row, text="删除", command=lambda i=i: self.on_mg_remove_slot(i))
            b.pack(side="left", padx=(8, 0))
            if self.mg_vmk is None or len(self.mg_header["slots"]) <= 1 or self.busy:
                b.configure(state="disabled")
        self.mg_unlock.adapt(self.mg_header)
        self._refresh_buttons()

    def mg_persist(self, what):
        if self.mg_dir:
            path = self.mg_header_source
            if not path:
                raise PQError("请先载入要更新的卷头文件")
            current = self.vfs.read_header_file(path)
            if current["volume_id"] != self.mg_header["volume_id"]:
                raise PQError("卷头已变化，未更新，请重新载入")
            with _volume_lock(self.mg_dir):
                self.vfs.write_file_bytes(path, header_json(self.mg_header).encode("utf-8"))
            self.log("%s：卷头已更新到 %s。" % (what, path), "ok")
        else:
            self.log("%s：当前只在内存中修改了卷头备份，请保存并写回硬盘。" % what, "w")
            self.save_header_dialog(self.mg_header, what)
        self.mg_render()

    def on_mg_unlock(self):
        if self.busy:
            return
        try:
            self.ensure_ready()
            if not self.mg_header:
                raise PQError("请先选择加密卷目录或载入卷头备份")
            spec = self.mg_unlock.snapshot(self.mg_header)
        except Exception as e:
            self.fail(e)
            return
        self.set_busy(True)
        header, unlock = self.mg_header, self.mg_unlock

        def done(u, err):
            self.set_busy(False)
            if err is not None:
                self.fail(err)
                return
            self.mg_vmk = u["vmk"]
            self.log("卷 %s 已解锁（密钥槽 #%d），可以增删密钥槽。" % (vol_id_short(header), u["slotIndex"] + 1), "ok")
            self.mg_render()
        self.run_worker(lambda: unlock.unlock(spec, header), done)

    def on_mg_add_pw(self):
        if self.busy:
            return
        try:
            self.ensure_ready()
            if self.mg_vmk is None:
                raise PQError("请先解锁卷")
            pw, pw2 = self.mg_new_pw.get(), self.mg_new_pw2.get()
            if not pw:
                raise PQError("新口令不能为空")
            if pw != pw2:
                raise PQError("两次口令不一致")
            pw_n = self.gate_password(pw, "新卷口令")
        except Exception as e:
            self.fail(e)
            return
        self.set_busy(True)
        self.log("Argon2id 派生新口令槽，稍候…")
        header, vmk = self.mg_header, self.mg_vmk

        def done(_r, err):
            self.set_busy(False)
            if err is not None:
                self.fail(err)
                return
            self.mg_new_pw.set("")
            self.mg_new_pw2.set("")
            try:
                self.mg_persist("已追加口令槽 #%d" % len(header["slots"]))
            except Exception as e:
                self.fail(e)
        self.run_worker(lambda: self.pq.add_password_slot(header, vmk, pw_n), done)

    def on_mg_add_pk(self):
        if self.busy:
            return
        try:
            self.ensure_ready()
            if self.mg_vmk is None:
                raise PQError("请先解锁卷")
            if not self.mg_pub:
                raise PQError("请先载入 .pub 公钥")
        except Exception as e:
            self.fail(e)
            return
        self.set_busy(True)
        header, vmk, pub = self.mg_header, self.mg_vmk, self.mg_pub

        def done(_r, err):
            self.set_busy(False)
            if err is not None:
                self.fail(err)
                return
            try:
                self.mg_persist("已追加公钥槽 #%d" % len(header["slots"]))
            except Exception as e:
                self.fail(e)
        self.run_worker(lambda: self.pq.add_pubkey_slot(header, vmk, pub), done)

    def on_mg_remove_slot(self, i):
        if self.busy:
            return
        try:
            if self.mg_vmk is None:
                raise PQError("请先解锁卷")
            s = self.mg_header["slots"][i]
            what = "口令槽 #%d" % (i + 1) if s.get("type") == SLOT_PASSWORD else "公钥槽 #%d（指纹 %s）" % (i + 1, s.get("fingerprint"))
            if not messagebox.askyesno("删除密钥槽", "确定删除 %s 吗？\n这只会移除当前卷头中的入口，不会轮换主密钥。持有旧卷头或主密钥的人仍能读取本卷及以后新增的文件。彻底撤销访问需新建卷并重新加密。\n请确认仍持有其余槽的口令或私钥。" % what):
                raise PQError("已取消。")
            self.pq.remove_slot(self.mg_header, i)
            self.mg_persist("已删除 " + what)
        except Exception as e:
            self.fail(e)

    def on_mg_convert(self):
        if self.busy:
            return
        try:
            self.ensure_ready()
            if not self.mg_header:
                raise PQError("请先选择加密卷目录")
            if not self.mg_dir:
                raise PQError("切换隐藏文件名需要先选择卷所在目录（只载入卷头备份无法改名）")
            if self.mg_vmk is None:
                raise PQError("请先解锁卷")
            hide = not self.mg_header["hide_names"]
            what = "隐藏文件名与目录结构（文件与目录改成随机 ID，原名存入各目录的加密清单）" if hide else "显示文件名与目录结构（把随机 ID 改回原名，并删除目录清单）"
            if not messagebox.askyesno("切换隐藏文件名", "将对目录「%s」执行：%s。\n只改名、不重新加密；卷头会随之更新，改完请重新保存备份。\n\n确定继续？" % (self.mg_dir, what)):
                raise PQError("已取消。")
        except Exception as e:
            self.fail(e)
            return
        self.set_busy(True)
        path, header, vmk, vfs = self.mg_dir, self.mg_header, self.mg_vmk, self.vfs
        header_source = self.mg_header_source
        vid = b64decode(header["volume_id"])

        def on_event(ev):
            t = ev["type"]
            if t == "file-error":
                self.wlog("失败：%s：%s" % (ev["path"], ev["message"]), "er")
            elif t == "file-warn":
                self.wlog("警告：%s：%s" % (ev["path"], ev["message"]), "w")
            elif t == "dir-skip":
                self.wlog("跳过目录：%s（%s）" % (ev["path"], ev["reason"]), "w")

        def work():
            self.wlog("开始%s…" % ("隐藏文件名" if hide else "显示文件名"))
            return vfs.convert_names(path, header, {"vmk": vmk, "volumeId": vid, "hideNames": header["hide_names"]}, hide, on_event=on_event, header_path=header_source)

        def done(res, err):
            self.set_busy(False)
            if err is not None:
                self.fail(err)
                try:
                    self.mg_header = (self.vfs.read_header_file(header_source) if header_source else self.vfs.read_volume_header(path)) or self.mg_header
                except Exception:
                    pass
                self.mg_render()
                return
            summary = "%s：改名 %d 个文件、%d 个目录" % ("已隐藏文件名" if hide else "已显示文件名", res["files"], res["dirs"])
            if res["warnings"]:
                summary += "，警告 %d 个" % len(res["warnings"])
            if res["errors"]:
                summary += "，失败 %d 个（卷头保持原状态，仍可正常解密；处理后可再试一次）" % len(res["errors"])
            self.log(summary, "w" if res["errors"] or res["warnings"] else "ok")
            try:
                self.mg_header = (self.vfs.read_header_file(header_source) if header_source else self.vfs.read_volume_header(path)) or self.mg_header
            except Exception as e:
                self.fail(e)
            self.mg_render()
        self.run_worker(work, done)

    def on_mg_write(self):
        try:
            if not self.mg_header:
                raise PQError("没有可写回的卷头")
            if not self.mg_dir:
                raise PQError("请先选择要写入的目录")
            if self.mg_vmk is None:
                raise PQError("请先用口令 / 私钥解锁，证明这份卷头能解开再写回")
            if not messagebox.askyesno("更新卷头", "将把卷 %s 的卷头更新到之前选择的文件。继续？" % vol_id_short(self.mg_header)):
                raise PQError("已取消。")
            self.mg_persist("手动更新")
        except Exception as e:
            self.fail(e)

    # ---- diagnostics --------------------------------------------------------------------------------
    def on_diagnose(self):
        if self.busy:
            return
        path = (self.dec_path.get() or "").strip().strip('"')
        try:
            self.ensure_ready()
            if not path or not os.path.isdir(os.path.normpath(path)):
                raise PQError("请先在上方选择目录")
        except Exception as e:
            self.fail(e)
            return
        path = os.path.normpath(path)
        rpath = self.DIAG_FILE or filedialog.asksaveasfilename(
            title="导出诊断报告（包含文件名和路径）", initialfile="pqdiskcrypt-diag.txt", defaultextension=".txt")
        if not rpath:
            return
        self.set_busy(True)
        self.log("生成诊断报告：逐个检查 %s 里每个文件的内容…" % path)
        vfs = self.vfs
        diagnostic_header = self.dec_header if self.dec_dir and os.path.normcase(os.path.abspath(path)) == os.path.normcase(self.dec_dir) else None

        def work():
            status, header, herr = vfs.header_status(path)
            header = diagnostic_header or header
            d = vfs.diagnose_tree(path, header)
            try:
                import platform
                sysinfo = "%s / Python %s" % (platform.platform(), platform.python_version())
            except Exception:
                sysinfo = sys.platform
            try:
                import cryptography
                cver = cryptography.__version__
            except Exception:
                cver = "?"
            out = ["%s %s 诊断报告 %s" % (APP_NAME, APP_VERSION, time.strftime("%Y-%m-%d %H:%M:%S")),
                   "系统：%s；cryptography %s；Argon2id 后端：%s" % (sysinfo, cver, argon2_backend_name()),
                   "目录：%s" % path]
            if status == "ok":
                out.append("卷头：正常 · 卷 %s · 隐藏文件名 %s · 密钥槽 %s · 创建于 %s" % (vol_id_short(header), header["hide_names"], slot_summary(header), header.get("created")))
            elif status == "invalid":
                out.append("卷头：已损坏（%s）" % herr)
            else:
                out.append("标准卷头 .pqvolume：未找到")
                try:
                    for c in vfs.find_header_candidates(path):
                        out.append("卷头候选：%s · %s" % (c["path"],
                                   "卷 " + vol_id_short(c["header"]) if c["header"] else "无法载入：" + c["error"]))
                    parent = vfs.parent_header_hint(path)
                    if parent:
                        out.append("上级目录卷头：" + parent)
                except Exception as e:
                    out.append("查找卷头候选失败：" + str(e))
            out.append("统计：" + "；".join("%s %d" % (k, v) for k, v in sorted(d["counts"].items())))
            out.extend(d["lines"])
            if d["truncated"]:
                out.append("（清单过长，只列出前 %d 项）" % len(d["lines"]))
            report = "\n".join(out)
            write_text_file(rpath, report + "\n")
            return report, rpath, d

        def done(r, err):
            self.set_busy(False)
            if err is not None:
                self.fail(err)
                return
            report, rpath, d = r
            for line in report.split("\n"):
                self.log(line, "i")
            self.log("诊断报告已写入 %s。报告包含文件名与路径，请审阅后再分享。" % rpath, "ok")
            if d["misnamed"]:
                if messagebox.askyesno("发现被改名的密文", "有 %d 个文件的内容是本卷密文，但文件名没有 .pqfc 后缀（可能被改过名），例如：\n%s\n\n要给它们补上 .pqfc 后缀以便解密吗？" % (
                        len(d["misnamed"]), "\n".join(d["misnamed"][:5]))):
                    r2 = self.vfs.fix_extensions(path, d["misnamed"])
                    self.log("已补上 .pqfc 后缀：%d 个；失败 %d 个" % (len(r2["renamed"]), len(r2["errors"])), "ok" if not r2["errors"] else "w")
                    for e in r2["errors"]:
                        self.log("失败：%s：%s" % (e["path"], e["message"]), "er")
                    self.on_scan("dec")
                    return
            messagebox.showinfo("诊断报告", "报告已写入：\n%s\n\n包含文件名、路径、大小和分类，不含口令或密钥。请审阅并删除敏感信息后再分享。" % rpath)
        self.run_worker(work, done)

    # ---- tab: single file ---------------------------------------------------------------------------
    def _build_single(self, p):
        s = self._section(p, 0)
        self._wrapped(s, "单个文件的加密 / 解密（pqfilecrypt 格式 v2：口令模式、混合公钥模式、混合公钥 + 发件人签名）。文件会一次性读入内存，适合单个文件；整块硬盘请用“加密硬盘”。")
        s = self._section(p, 1, "解密单个 .pqfc 文件")
        row = ttk.Frame(s)
        row.pack(anchor="w", fill="x")
        self.sf_pick_btn = ttk.Button(row, text="选择 .pqfc 文件…", command=self.on_sf_pick)
        self.sf_pick_btn.pack(side="left")
        self.sf_info = ttk.Label(row, text="未选择", foreground="#666")
        self.sf_info.pack(side="left", padx=(8, 0))
        self.sf_unlock = UnlockBox(self, s, "解锁方式（按文件模式自动选择）", pw_label="文件口令")
        self.sf_unlock.frame.pack(fill="x", pady=(6, 0))
        self.sf_dec_btn = ttk.Button(s, text="🔓 解密并另存…", command=self.on_sf_decrypt)
        self.sf_dec_btn.pack(anchor="w", pady=(6, 0))
        self.sf_dec_done = self._wrapped(s, "", pady=(4, 0))

        s = self._section(p, 2, "加密单个文件")
        row = ttk.Frame(s)
        row.pack(anchor="w", fill="x")
        ttk.Button(row, text="选择要加密的文件…", command=self.on_sf_pick_plain).pack(side="left")
        self.sf_plain_info = ttk.Label(row, text="未选择", foreground="#666")
        self.sf_plain_info.pack(side="left", padx=(8, 0))
        self.sf_mode = tk.StringVar(value="pw")
        row = ttk.Frame(s)
        row.pack(anchor="w", pady=(6, 0))
        for text, val in (("口令", "pw"), ("收件人公钥 (.pub)", "pk"), ("收件人公钥 + 我的签名 (.key)", "signed")):
            ttk.Radiobutton(row, text=text, variable=self.sf_mode, value=val, command=self._sf_refresh).pack(side="left", padx=(0, 10))
        box = ttk.Frame(s)
        box.pack(anchor="w", fill="x")
        box.columnconfigure(0, weight=1)
        self.sf_pw_box = ttk.Frame(box)
        self.sf_pw_box.grid(row=0, column=0, sticky="ew", pady=(4, 0))
        self.sf_pw = tk.StringVar()
        self.sf_pw2 = tk.StringVar()
        r1 = ttk.Frame(self.sf_pw_box)
        r1.pack(anchor="w")
        ttk.Label(r1, text="口令", width=12).pack(side="left")
        PasswordEntry(r1, self.sf_pw, meter=True).frame.pack(side="left")
        r2 = ttk.Frame(self.sf_pw_box)
        r2.pack(anchor="w", pady=(3, 0))
        ttk.Label(r2, text="再输一次", width=12).pack(side="left")
        PasswordEntry(r2, self.sf_pw2).frame.pack(side="left")
        self.sf_pk_box = ttk.Frame(box)
        self.sf_pk_box.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        ttk.Button(self.sf_pk_box, text="选择收件人 .pub…", command=self.on_sf_pick_pub).pack(side="left")
        self.sf_pub_label = ttk.Label(self.sf_pk_box, text="未载入公钥", foreground="#666")
        self.sf_pub_label.pack(side="left", padx=(8, 0))
        self.sf_sign_box = ttk.Frame(box)
        self.sf_sign_box.grid(row=2, column=0, sticky="ew", pady=(4, 0))
        self.sf_signer = UnlockBox(self, self.sf_sign_box, "我的签名私钥 (.key)")
        self.sf_signer.select("key")
        self.sf_signer.frame.pack(fill="x")
        self.sf_enc_btn = ttk.Button(s, text="🔒 加密并另存…", command=self.on_sf_encrypt)
        self.sf_enc_btn.pack(anchor="w", pady=(6, 0))
        self.sf_enc_done = self._wrapped(s, "", pady=(4, 0))
        self._sf_refresh()

    def _sf_refresh(self):
        m = self.sf_mode.get()
        if m == "pw":
            self.sf_pw_box.grid()
        else:
            self.sf_pw_box.grid_remove()
        if m == "pw":
            self.sf_pk_box.grid_remove()
        else:
            self.sf_pk_box.grid()
        if m == "signed":
            self.sf_sign_box.grid()
        else:
            self.sf_sign_box.grid_remove()

    @staticmethod
    def mode_name(mode):
        return {MODE_HYBRID: "混合公钥模式（需要收件人 .key）", MODE_PASSWORD: "口令模式", MODE_HYBRID_SIGNED: "混合公钥 + 发件人签名（需要收件人 .key）", MODE_VOLUME: "卷模式（属于某个加密卷，请用“解密硬盘”）"}.get(mode, "未知模式 %s" % mode)

    def on_sf_pick(self):
        if self.busy:
            return
        path = filedialog.askopenfilename(title="选择 .pqfc 文件", filetypes=[("加密文件", "*.pqfc"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            self.ensure_ready()
            p = self.vfs.probe_file(path)
            pr = p["probe"]
            if not pr["ok"]:
                raise PQError("这不是本工具的加密文件（魔数不匹配）：" + os.path.basename(path))
            if pr["version"] != VERSION:
                raise PQError("不支持的文件版本 %d（仅支持格式 v2）" % pr["version"])
            self.sf_in, self.sf_probe = path, pr
            self.sf_info.configure(text="%s（%s）· %s" % (os.path.basename(path), fmt_size(p["size"]), self.mode_name(pr["mode"])))
            self.sf_dec_done.configure(text="")
            if pr["mode"] == MODE_PASSWORD:
                self.sf_unlock.select("pw")
            elif pr["mode"] in (MODE_HYBRID, MODE_HYBRID_SIGNED):
                self.sf_unlock.select("key")
            self.log("已选择 %s：%s" % (os.path.basename(path), self.mode_name(pr["mode"])))
        except Exception as e:
            self.sf_in = self.sf_probe = None
            self.sf_info.configure(text="未选择")
            self.fail(e)
        self._refresh_buttons()

    def on_sf_decrypt(self):
        if self.busy:
            return
        try:
            self.ensure_ready()
            if not self.sf_in:
                raise PQError("请先选择 .pqfc 文件")
            mode = self.sf_probe["mode"]
            if mode == MODE_VOLUME:
                raise PQError("这是卷模式文件，请在“解密硬盘”页选择它所在的目录解密。")
            spec = self.sf_unlock.snapshot_plain("pw" if mode == MODE_PASSWORD else "key")
            if mode == MODE_PASSWORD:
                with _read_regular(self.sf_in) as source:
                    hdr = self.pq.parse_header(source.read(64))
                self.confirm_kdf_cost(hdr["timeCost"], hdr["memKiB"], hdr["parallelism"], "解密 " + os.path.basename(self.sf_in))
            base = os.path.basename(self.sf_in)
            out = filedialog.asksaveasfilename(title="解密后另存为", initialfile=base[:-len(ENC_EXT)] if base.endswith(ENC_EXT) else base + ".decrypted", initialdir=os.path.dirname(self.sf_in))
            if not out:
                return
            if os.path.lexists(out):
                raise PQError("目标已存在，未覆盖。请选择新文件名。", "OUTPUT_EXISTS")
        except Exception as e:
            self.fail(e)
            return
        self.set_busy(True)
        src, pq, unlock = self.sf_in, self.pq, self.sf_unlock

        def work():
            data = self.vfs.read_file_bytes(src, MAX_SINGLE_FILE_BYTES + 1024 * 1024)
            pw, key = unlock.resolve(spec)
            if pw is not None:
                self.wlog("Argon2id 派生 → 核对密钥承诺 → 逐块认证解密…")
                return self.try_password_variants(pw, lambda v: pq.decrypt(data, password=v))
            self.wlog("解封 ML-KEM + X25519 → 组合器派生 → 核对密钥承诺 → 逐块认证解密…")
            return pq.decrypt(data, key_obj=key)

        def done(r, err):
            self.set_busy(False)
            if err is not None:
                self.fail(err)
                return
            try:
                VolumeFS.write_file_bytes(out, r["plaintext"], replace=False)
            except Exception as e:
                self.fail(e)
                return
            msg = "已解密并保存：%s（%s）" % (out, fmt_size(len(r["plaintext"])))
            if r.get("signed"):
                msg += "；发件人签名验证通过，签名指纹 %s（请与发件人核对）" % r["signerFingerprint"]
            self.sf_dec_done.configure(text=msg)
            self.log(msg, "ok")
        self.run_worker(work, done)

    def on_sf_pick_plain(self):
        if self.busy:
            return
        path = filedialog.askopenfilename(title="选择要加密的文件")
        if not path:
            return
        try:
            size = os.path.getsize(path)
        except OSError as e:
            self.fail(e)
            return
        self.sf_plain = path
        self.sf_plain_info.configure(text="%s（%s）" % (os.path.basename(path), fmt_size(size)))
        self.sf_enc_done.configure(text="")
        self._refresh_buttons()

    def on_sf_pick_pub(self):
        path = filedialog.askopenfilename(title="选择收件人 .pub 公钥", filetypes=[("公钥文件", "*.pub"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            self.ensure_ready()
            obj, fp = self.load_pub_file(path)
            self.sf_pub = obj
            self.sf_pub_label.configure(text=os.path.basename(path) + " ✓  指纹 " + fp)
            self.log("已载入收件人公钥 %s，指纹 %s" % (os.path.basename(path), fp))
        except Exception as e:
            self.sf_pub = None
            self.sf_pub_label.configure(text="未载入公钥")
            self.fail(e)

    def on_sf_encrypt(self):
        if self.busy:
            return
        try:
            self.ensure_ready()
            if not self.sf_plain:
                raise PQError("请先选择要加密的文件")
            mode = self.sf_mode.get()
            pw_n = None
            signer_spec = None
            if mode == "pw":
                pw, pw2 = self.sf_pw.get(), self.sf_pw2.get()
                if not pw:
                    raise PQError("口令不能为空")
                if pw != pw2:
                    raise PQError("两次口令不一致")
                pw_n = self.gate_password(pw, "文件口令")
            else:
                if not self.sf_pub:
                    raise PQError("请先载入收件人 .pub 公钥")
                if mode == "signed":
                    signer_spec = self.sf_signer.snapshot_plain("key")
            out = filedialog.asksaveasfilename(title="加密后另存为", initialfile=os.path.basename(self.sf_plain) + ENC_EXT, initialdir=os.path.dirname(self.sf_plain), defaultextension=ENC_EXT)
            if not out:
                return
            if os.path.lexists(out):
                raise PQError("目标已存在，未覆盖。请选择新文件名。", "OUTPUT_EXISTS")
        except Exception as e:
            self.fail(e)
            return
        self.set_busy(True)
        src, pq, pub, signer = self.sf_plain, self.pq, self.sf_pub, self.sf_signer

        def work():
            data = self.vfs.read_file_bytes(src)
            if mode == "pw":
                self.wlog("Argon2id 派生（%d MiB / t=%d / p=%d）→ 逐块认证加密…" % (ARGON_MEM_KIB // 1024, ARGON_TIME, ARGON_PAR))
                return pq.encrypt_password(pw_n, data)
            if mode == "signed":
                _pw, key = signer.resolve(signer_spec)
                self.wlog("ML-DSA-87 签名 → 混合 KEM 加密…")
                return pq.encrypt_hybrid_signed(pub, data, key)
            self.wlog("混合 KEM：X25519 + ML-KEM-1024 → 逐块认证加密…")
            return pq.encrypt_hybrid(pub, data)

        def done(ct, err):
            self.set_busy(False)
            if err is not None:
                self.fail(err)
                return
            try:
                VolumeFS.write_file_bytes(out, ct, replace=False)
            except Exception as e:
                self.fail(e)
                return
            msg = "已加密并保存：%s（%s）" % (out, fmt_size(len(ct)))
            self.sf_enc_done.configure(text=msg)
            self.log(msg, "ok")
        self.run_worker(work, done)

    # ---- clear / close ------------------------------------------------------------------------------
    def on_clear(self):
        if self.busy:
            self.fail(PQError("正在处理中，完成或取消后再清除。"))
            return
        for v in (self.key_pw, self.key_pw2, self.enc_pw, self.enc_pw2, self.mg_new_pw, self.mg_new_pw2, self.enc_label, self.enc_path, self.dec_path, self.mg_path):
            v.set("")
        for w in (self.pub_peek, self.key_peek):
            self._set_text(w, "")
        if self.mg_vmk is not None:
            wipe(self.mg_vmk)
        self.last_keys = self.enc_pub = self.mg_pub = None
        self.enc_dir = self.enc_header = self.enc_scan = self.enc_last_header = None
        self.dec_dir = self.dec_header = self.dec_scan = None
        self.dec_override = None
        self.dec_header_source = None
        self.dec_header_explicit = False
        self.header_locations.clear()
        self.header_choices.clear()
        self.enc_recreate.set(False)
        self.enc_header_source = self.enc_previous_header = None
        self.mg_dir = self.mg_header = self.mg_vmk = None
        self.mg_header_source = None
        self.sf_in = self.sf_probe = self.sf_plain = self.sf_pub = None
        for v in (self.sf_pw, self.sf_pw2):
            v.set("")
        self.sf_info.configure(text="未选择")
        self.sf_plain_info.configure(text="未选择")
        self.sf_pub_label.configure(text="未载入公钥")
        self.sf_dec_done.configure(text="")
        self.sf_enc_done.configure(text="")
        for u in (self.enc_unlock, self.dec_unlock, self.mg_unlock, self.sf_unlock, self.sf_signer):
            u.clear()
        self.sf_signer.select("key")
        self.fp_label.configure(text="公钥指纹：—")
        self.sfp_label.configure(text="签名指纹：—")
        self.save_pub_btn.configure(state="disabled")
        self.save_key_btn.configure(state="disabled")
        self.enc_pub_label.configure(text="未载入公钥（只有对应的 .key 私钥能解锁此卷）")
        self.mg_pub_label.configure(text="未载入公钥（对应的 .key 私钥将能解锁此卷）")
        self.enc_dir_info.configure(text="未选择。")
        self.enc_scan_info.configure(text="")
        self.enc_done.configure(text="")
        self.enc_dl_btn.pack_forget()
        self.enc_prog.frame.grid_remove()
        self.enc_exist_box.grid_remove()
        self.enc_new_box.grid()
        self.enc_hide_cb.configure(state="normal")
        self.dec_dir_info.configure(text="未选择。")
        self.dec_vol_info.configure(text="")
        self.dec_scan_info.configure(text="")
        self.dec_done.configure(text="")
        self.dec_nohdr.pack_forget()
        self.dec_prog.frame.grid_remove()
        self.mg_dir_info.configure(text="未选择。")
        self.mg_render()
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.log_count = 0
        self.log("已清除敏感状态并重置界面（Python 无法保证彻底抹除内存，敏感场景请直接退出程序）。", "ok")

    def on_close(self):
        if self.busy and not messagebox.askyesno("正在处理", "有任务正在进行。现在退出会中止当前文件的处理（已完成的文件不受影响）。确定退出？"):
            return
        if self.mg_vmk is not None:
            wipe(self.mg_vmk)
        self.root.destroy()


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def run_selftest_cli():
    print("%s %s 自检…" % (APP_NAME, APP_VERSION))
    if not HAVE_CRYPTOGRAPHY:
        print("缺少 cryptography 库：pip install cryptography")
        return 2
    t = time.time()
    try:
        backend = _argon2_backend()[0]
        PQCrypto().self_test(SELFTEST_ARGON)
    except Exception as e:
        print("自检未通过：%s" % e)
        return 1
    print("自检通过（%.1f 秒；Argon2id 后端：%s；ML-KEM-1024 / ML-DSA-87：pqcrypto / PQClean 原生实现）。" % (time.time() - t, backend))
    return 0


def run_gui():
    _load_tk()
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    try:
        ttk.Style().theme_use({"win32": "vista", "darwin": "aqua"}.get(sys.platform, "clam"))
    except Exception:
        pass
    App(root)
    root.mainloop()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--selftest" in argv:
        return run_selftest_cli()
    if "--version" in argv:
        print(APP_NAME, APP_VERSION)
        return 0
    if "-h" in argv or "--help" in argv:
        print(__doc__)
        return 0
    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("缺少 tkinter：Windows / macOS 官方 Python 自带；Linux 请安装 python3-tk（例如 sudo apt install python3-tk）。")
        return 2
    run_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main())
