// Generates _verify/vectors.json from the frozen JS implementation (noble + pqcore.js).
// Run: node _verify/gen-vectors.mjs
import { webcrypto, randomBytes as nodeRandom, createHash } from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

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
const randomBytes = (n) => new Uint8Array(nodeRandom(n));
const pq = createPQCrypto({ subtle: webcrypto.subtle, randomBytes, mlkem, argon2id, mldsa });

const b64 = (u8) => Buffer.from(u8).toString("base64");
const det = (label, n) => { // deterministic pseudo-random bytes for reproducible seeds
  const out = new Uint8Array(n);
  for (let i = 0, k = 0; i < n; k++) { const h = createHash("sha256").update(label + ":" + k).digest(); for (let j = 0; j < 32 && i < n; j++) out[i++] = h[j]; }
  return out;
};
const SMALL = { timeCost: 1, memKiB: 8, parallelism: 1 };
const V = { note: "Cross-implementation vectors produced by the original JS implementation (noble 0.5.4 + hash-wasm 4.12 + pqcore.js)" };

// ML-KEM-1024
V.mlkem1024 = [];
for (let i = 0; i < 3; i++) {
  const seed = det("kem-seed", 64).map((b, j) => (b + i * 7 + j) & 0xff);
  const kp = kem.keygen(seed);
  const m = det("kem-msg" + i, 32);
  const enc = kem.encapsulate(kp.publicKey, m);
  const ss2 = kem.decapsulate(enc.cipherText, kp.secretKey);
  const bad = enc.cipherText.slice(); bad[17] ^= 0x5a;
  const ssBad = kem.decapsulate(bad, kp.secretKey);
  V.mlkem1024.push({ seed: b64(seed), pk: b64(kp.publicKey), sk: b64(kp.secretKey), m: b64(m), ct: b64(enc.cipherText), ss: b64(enc.sharedSecret), ss_decaps: b64(ss2), ct_bad: b64(bad), ss_bad: b64(ssBad) });
}

// ML-DSA-87 (deterministic signatures via extraEntropy:false; hedged ones for verify-only)
V.mldsa87 = [];
for (let i = 0; i < 2; i++) {
  const seed = det("dsa-seed" + i, 32);
  const kp = dsa.keygen(seed);
  const msgs = [new Uint8Array(0), det("dsa-msg-a" + i, 33), det("dsa-msg-b" + i, 1000)];
  const sigs = msgs.map((m) => ({ msg: b64(m), sig_det: b64(dsa.sign(m, kp.secretKey, { extraEntropy: false })), sig_hedged: b64(dsa.sign(m, kp.secretKey)) }));
  const ctxSig = dsa.sign(msgs[1], kp.secretKey, { extraEntropy: false, context: new TextEncoder().encode("ctx!") });
  V.mldsa87.push({ seed: b64(seed), pk: b64(kp.publicKey), sk: b64(kp.secretKey), sigs, ctx: "ctx!", sig_ctx: b64(ctxSig) });
}

// Argon2id reference outputs (hash-wasm) for the Python KDF binding check
V.argon2id = [];
for (const [pw, t, m, p] of [["pw", 1, 8, 1], ["密码 test ✓", 2, 64, 2], ["x", 3, 1024, 4]]) {
  const salt = det("argon-salt" + pw, 16);
  const out = await argon2id({ password: new TextEncoder().encode(pw), salt, iterations: t, memorySizeKiB: m, parallelism: p, hashLen: 32 });
  V.argon2id.push({ password: pw, salt: b64(salt), t, m, p, out: b64(out) });
}

// pqcore artifacts
const payloads = { p0: new Uint8Array(0), p5: new TextEncoder().encode("hello"), p64k: det("pl64k", 65536), p64k1: det("pl64k1", 65537), p2b: det("pl2b", 65536 * 2 + 123) };
const kpA = await pq.generateKeypair();
const kpB = await pq.generateKeypair();
V.keypairA = { pub: kpA.pub, key: kpA.key, fingerprint: kpA.fingerprint, signerFingerprint: kpA.signerFingerprint };
V.keypairB = { pub: kpB.pub, key: kpB.key, fingerprint: kpB.fingerprint, signerFingerprint: kpB.signerFingerprint };
V.payloads = Object.fromEntries(Object.entries(payloads).map(([k, v]) => [k, b64(v)]));
V.hybrid = {};
for (const [k, v] of Object.entries(payloads)) V.hybrid[k] = b64(await pq.encryptHybrid(kpA.pub, v));
V.hybrid_signed = {};
for (const [k, v] of Object.entries(payloads)) V.hybrid_signed[k] = b64(await pq.encryptHybridSigned(kpA.pub, v, kpB.key));
V.password = { password: "pw-测试 ✓", files: {} };
for (const [k, v] of Object.entries(payloads)) V.password.files[k] = b64(await pq.encryptPassword(V.password.password, v, SMALL));
V.wrapped_key = { passphrase: "kp-口令", container: await pq.wrapSecretKey(kpA.key, "kp-口令", SMALL) };

// volume
const vol = pq.newVolume({ hideNames: true, label: "向量卷 ✓" });
await pq.addPasswordSlot(vol.header, vol.vmk, "vol-pw ✓", SMALL);
await pq.addPubkeySlot(vol.header, vol.vmk, kpA.pub);
await pq.addPasswordSlot(vol.header, vol.vmk, "second-pw", SMALL);
V.volume = { header: vol.header, vmk: b64(vol.vmk), password: "vol-pw ✓", password2: "second-pw", files: {} };
for (const [k, v] of Object.entries(payloads)) V.volume.files[k] = b64(await pq.encryptVolumeBytes(vol.vmk, vol.volumeId, v));
const manifest = { v: 1, dir: "0123456789abcdef", entries: { "00000000000000aa": { n: "照片 2026.jpg", t: "f" }, "00000000000000bb": { n: "子目录", t: "d" } } };
V.volume.manifest_plain = manifest;
V.volume.manifest_enc = b64(await pq.encryptVolumeBytes(vol.vmk, vol.volumeId, new TextEncoder().encode(JSON.stringify(manifest))));

fs.writeFileSync(fileURLToPath(P("./vectors.json")), JSON.stringify(V, null, 1));
console.log("wrote vectors.json");
