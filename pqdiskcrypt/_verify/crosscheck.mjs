// Cross-check oracle: verifies artifacts produced by pqdiskcrypt.py with the frozen original
// JS implementation (noble + hash-wasm + pqcore.js). Invoked by test_pqdiskcrypt.py:
//   node _verify/crosscheck.mjs <artifacts.json>
import { webcrypto, randomBytes as nodeRandom } from "node:crypto";
import fs from "node:fs";

const here = new URL(".", import.meta.url);
const P = (rel) => new URL(rel, here).href;
const { createPQCrypto } = await import(P("./legacy-js/pqcore.js"));
const noble = await import(P("./legacy-js/vendor/@noble__post-quantum@0.5.4__ml-kem.js"));
const nobleDsa = await import(P("./legacy-js/vendor/@noble__post-quantum@0.5.4__ml-dsa.js"));
const hw = await import(P("./legacy-js/vendor/hash-wasm@4.12.0.js"));
const kem = noble.ml_kem1024, dsa = nobleDsa.ml_dsa87;
const mlkem = { keygen: () => kem.keygen(), encapsulate: (pk) => kem.encapsulate(pk), decapsulate: (ct, sk) => kem.decapsulate(ct, sk) };
const mldsa = { keygen: () => dsa.keygen(), sign: (m, sk) => dsa.sign(m, sk), verify: (s, m, pk) => dsa.verify(s, m, pk), getPublicKey: (sk) => dsa.getPublicKey(sk), get lengths() { return dsa.lengths; } };
const argon2id = async ({ password, salt, iterations, memorySizeKiB, parallelism, hashLen }) =>
  hw.argon2id({ password, salt, iterations, parallelism, memorySize: memorySizeKiB, hashLength: hashLen, outputType: "binary" });
const pq = createPQCrypto({ subtle: webcrypto.subtle, randomBytes: (n) => new Uint8Array(nodeRandom(n)), mlkem, argon2id, mldsa });

const A = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const b = (s) => new Uint8Array(Buffer.from(s, "base64"));
const eq = (x, y) => x.length === y.length && x.every((v, i) => v === y[i]);
let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ✓", n)) : (fail++, console.log("  ✗ FAIL:", n)); };

// ML-KEM / ML-DSA primitives produced by Python
for (const v of A.mlkem) {
  const ss = kem.decapsulate(b(v.ct), b(v.sk));
  ok("JS 解封 Python 的 ML-KEM 密文 → 共享密钥一致", eq(ss, b(v.ss)));
  const enc = kem.encapsulate(b(v.pk));
  ok("JS 用 Python 公钥封装（长度合法）", enc.cipherText.length === 1568);
}
for (const v of A.mldsa) {
  ok("JS 验证 Python 的 ML-DSA-87 签名", dsa.verify(b(v.sig), b(v.msg), b(v.pk)) === true);
  ok("JS 拒绝篡改后的 Python 签名", dsa.verify(b(v.sig_bad), b(v.msg), b(v.pk)) === false);
  const sig = dsa.sign(b(v.msg), b(v.sk));
  ok("JS 用 Python 私钥签名可自验", dsa.verify(sig, b(v.msg), b(v.pk)) === true);
}

// pqcore artifacts
const kp = A.keypair;
for (const [k, ct] of Object.entries(A.hybrid)) { const r = await pq.decrypt(b(ct), { keyObj: kp.key }); ok(`JS 解开 Python 混合模式文件 ${k}`, eq(r.plaintext, b(A.payloads[k])) && r.signed === false); }
for (const [k, ct] of Object.entries(A.hybrid_signed)) { const r = await pq.decrypt(b(ct), { keyObj: kp.key }); ok(`JS 解开并验签 Python 签名模式文件 ${k}`, eq(r.plaintext, b(A.payloads[k])) && r.signed === true && r.signerFingerprint === A.signer.signerFingerprint); }
for (const [k, ct] of Object.entries(A.password.files)) { const r = await pq.decrypt(b(ct), { password: A.password.password }); ok(`JS 解开 Python 口令模式文件 ${k}`, eq(r.plaintext, b(A.payloads[k]))); }
{ const u = await pq.unwrapSecretKey(A.wrapped_key.container, A.wrapped_key.passphrase); ok("JS 解封 Python 加密的私钥容器", u.mlkem_secret === kp.key.mlkem_secret && u.mldsa_secret === kp.key.mldsa_secret); }
{
  const h = A.volume.header;
  pq.validateVolumeHeader(h);
  const u1 = await pq.unlockVolume(h, { password: A.volume.password });
  ok("JS 用口令解锁 Python 建的卷（口令槽）", eq(u1.vmk, b(A.volume.vmk)));
  const u2 = await pq.unlockVolume(h, { keyObj: kp.key });
  ok("JS 用私钥解锁 Python 建的卷（公钥槽）", eq(u2.vmk, b(A.volume.vmk)));
  let rej = false; try { await pq.unlockVolume(h, { password: "wrong" }); } catch { rej = true; }
  ok("JS 拒绝错误口令", rej);
  const vid = pq.b64decode(h.volume_id);
  for (const [k, ct] of Object.entries(A.volume.files)) ok(`JS 解开 Python 卷文件 ${k}`, eq(await pq.decryptVolumeBytes(u1.vmk, vid, b(ct)), b(A.payloads[k])));
  const m = JSON.parse(new TextDecoder().decode(await pq.decryptVolumeBytes(u1.vmk, vid, b(A.volume.manifest_enc))));
  ok("JS 解开 Python 目录清单", JSON.stringify(m) === JSON.stringify(A.volume.manifest_plain));
}
console.log(`\n交叉验证（JS 读 Python 产物）：${pass} 通过，${fail} 失败`);
process.exit(fail ? 1 : 0);
