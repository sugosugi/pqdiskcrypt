// Runs the frozen browser-version engine (legacy-js/pqvolume.js) on a real directory through a
// small node:fs adapter of the File System Access API. Used by test_pqdiskcrypt.py to prove that
// a tree encrypted by the browser version is restored by the Python version.
//   node _verify/js-encrypt-dir.mjs <dir> <password>
import { webcrypto, randomBytes as nodeRandom } from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";

const here = new URL(".", import.meta.url);
const P = (rel) => new URL(rel, here).href;
const { createPQCrypto } = await import(P("./legacy-js/pqcore.js"));
const { createVolumeFS } = await import(P("./legacy-js/pqvolume.js"));
const noble = await import(P("./legacy-js/vendor/@noble__post-quantum@0.5.4__ml-kem.js"));
const hw = await import(P("./legacy-js/vendor/hash-wasm@4.12.0.js"));

const mlkem = { keygen: () => noble.ml_kem1024.keygen(), encapsulate: (pk) => noble.ml_kem1024.encapsulate(pk), decapsulate: (ct, sk) => noble.ml_kem1024.decapsulate(ct, sk) };
const argon2id = async ({ password, salt, iterations, memorySizeKiB, parallelism, hashLen }) =>
  hw.argon2id({ password, salt, iterations, parallelism, memorySize: memorySizeKiB, hashLength: hashLen, outputType: "binary" });
const randomBytes = (n) => new Uint8Array(nodeRandom(n));
const pq = createPQCrypto({ subtle: webcrypto.subtle, randomBytes, mlkem, argon2id, mldsa: null });
const vfs = createVolumeFS(pq, { randomBytes });

const dex = (name, msg) => { const e = new Error(msg || name); e.name = name; return e; };

class NodeFile {
  constructor(p) { this.p = p; const st = fs.statSync(p); this.name = path.basename(p); this.size = st.size; this.lastModified = st.mtimeMs; this._a = 0; this._b = st.size; }
  slice(a = 0, b = this.size) { const f = new NodeFile(this.p); f._a = this._a + a; f._b = Math.min(this._a + b, this._b); f.size = f._b - f._a; return f; }
  async arrayBuffer() { const fh = await fsp.open(this.p, "r"); try { const buf = Buffer.alloc(this._b - this._a); await fh.read(buf, 0, buf.length, this._a); return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length); } finally { await fh.close(); } }
  stream() { const rs = fs.createReadStream(this.p, { start: this._a, end: Math.max(this._a, this._b - 1), highWaterMark: 70000 }); return new ReadableStream({ start(c) { rs.on("data", (d) => c.enqueue(new Uint8Array(d))); rs.on("end", () => c.close()); rs.on("error", (e) => c.error(e)); } }); }
}
class NodeWritable {
  constructor(p) { this.p = p; this.tmp = p + ".tmp-" + nodeRandom(4).toString("hex"); this.fd = fs.openSync(this.tmp, "w"); this.done = false; }
  async write(chunk) { if (this.done) throw dex("InvalidStateError"); fs.writeSync(this.fd, Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength)); }
  async close() { if (this.done) throw dex("InvalidStateError"); this.done = true; fs.closeSync(this.fd); fs.renameSync(this.tmp, this.p); }
  async abort() { if (this.done) return; this.done = true; fs.closeSync(this.fd); try { fs.unlinkSync(this.tmp); } catch (_e) { /* ignore */ } }
}
class NodeFileHandle {
  constructor(p) { this.p = p; this.kind = "file"; this.name = path.basename(p); }
  async getFile() { return new NodeFile(this.p); }
  async createWritable() { return new NodeWritable(this.p); }
}
class NodeDirHandle {
  constructor(p) { this.p = p; this.kind = "directory"; this.name = path.basename(p); }
  async *entries() { for (const d of fs.readdirSync(this.p, { withFileTypes: true })) { const full = path.join(this.p, d.name); yield [d.name, d.isDirectory() ? new NodeDirHandle(full) : new NodeFileHandle(full)]; } }
  async getFileHandle(name, opts = {}) {
    const full = path.join(this.p, name);
    if (fs.existsSync(full)) { if (fs.statSync(full).isDirectory()) throw dex("TypeMismatchError"); return new NodeFileHandle(full); }
    if (!opts.create) throw dex("NotFoundError");
    fs.writeFileSync(full, "");
    return new NodeFileHandle(full);
  }
  async getDirectoryHandle(name, opts = {}) {
    const full = path.join(this.p, name);
    if (fs.existsSync(full)) { if (!fs.statSync(full).isDirectory()) throw dex("TypeMismatchError"); return new NodeDirHandle(full); }
    if (!opts.create) throw dex("NotFoundError");
    fs.mkdirSync(full);
    return new NodeDirHandle(full);
  }
  async removeEntry(name, opts = {}) {
    const full = path.join(this.p, name);
    if (!fs.existsSync(full)) throw dex("NotFoundError");
    if (fs.statSync(full).isDirectory()) { if (!opts.recursive && fs.readdirSync(full).length) throw dex("InvalidModificationError"); fs.rmSync(full, { recursive: true }); }
    else fs.unlinkSync(full);
  }
}

const [dir, password] = process.argv.slice(2);
const root = new NodeDirHandle(path.resolve(dir));
const vol = pq.newVolume({ hideNames: true, label: "JS 引擎所建" });
await pq.addPasswordSlot(vol.header, vol.vmk, password, { timeCost: 1, memKiB: 8, parallelism: 1 });
await vfs.writeVolumeHeader(root, vol.header);
const res = await vfs.encryptTree(root, { vmk: vol.vmk, volumeId: vol.volumeId, hideNames: true }, { verify: true });
console.log(JSON.stringify({ files: res.files, errors: res.errors, cancelled: res.cancelled }));
process.exit(res.errors.length ? 1 : 0);
