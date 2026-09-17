/*
 * pqvolume —— 硬盘 / 目录树加密引擎（浏览器 File System Access API / Node 仿真通用）
 * ============================================================================
 *
 * 输入是一个目录句柄（FileSystemDirectoryHandle 的子集）：
 *   dir.entries() / getFileHandle(name,{create}) / getDirectoryHandle(name,{create}) / removeEntry(name,{recursive})
 *   fileHandle.getFile() → { name, size, stream() } ；fileHandle.createWritable() → { write, close, abort }
 * 引擎只依赖这些方法，因此可以在 Node 里用内存目录树（_verify/fakefs.mjs）跑完整的端到端测试。
 *
 * 磁盘布局：
 *   根目录/.pqvolume          卷头（JSON）：卷 ID、选项、密钥槽。丢失 = 全卷无法解密，务必备份。
 *   <文件名>.pqfc             普通模式：原地逐文件加密，目录结构与文件名保持可见。
 *   <16 位十六进制 ID>.pqfc   隐藏文件名模式：文件与目录都改成随机 ID，
 *   <ID>/.pqdir               每个目录的加密清单（ID → 原名），清单本身也是卷文件。
 *
 * 安全次序（每个文件）：写出密文 → 关闭 → （可选）重新读取并完整校验认证标签 → 才删除原文件。
 * 任一步失败：删除写了一半的输出，原文件原样保留，记录错误，继续处理其它文件。
 * 取消：在两块之间检查，取消时同样丢弃半成品、保留原文件。
 *
 * “明文优先”规则：目录里若存在明文文件，本次一律（重新）加密并覆盖同名密文——绝不为了
 * “断点续传”而根据同名密文猜测“已经加密过”后删除明文（那可能删掉一份改动过的新文件）。
 */

export const VOLUME_HEADER_NAME = ".pqvolume";
export const DIR_MANIFEST_NAME = ".pqdir";
export const ENC_EXT = ".pqfc";
const ID_BYTES = 8; // 16 位十六进制；每目录内碰撞概率可忽略，且不会撞上 Windows 路径长度限制

// 操作系统自己的元数据目录：无法访问或加密后会被系统重建，直接跳过（仅根目录一级）。
export const SYSTEM_DIRS = new Set([
  "System Volume Information", "$RECYCLE.BIN", "$Recycle.Bin", "Recovery",
  ".Spotlight-V100", ".fseventsd", ".Trashes", ".TemporaryItems", ".DocumentRevisions-V100",
  "lost+found",
]);

const _TE = new TextEncoder(), _TD = new TextDecoder();
const isNotFound = (e) => e && (e.name === "NotFoundError" || e.code === "NOT_FOUND");
const isFatal = (e) => e && (e.name === "NotAllowedError" || e.name === "SecurityError" || e.code === "ABORTED");

function hex(bytes) { return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(""); }

// 写缓冲：把 64 KiB 粒度的密文块合并成 ~1 MiB 再交给 FileSystemWritableFileStream，减少 IPC。
class BufferedSink {
  constructor(writable, limit = 1 << 20) { this.w = writable; this.limit = limit; this.parts = []; this.len = 0; this.closed = false; }
  async write(u8) {
    this.parts.push(u8); this.len += u8.length;
    if (this.len >= this.limit) await this.flush();
  }
  async flush() {
    if (!this.len) return;
    const buf = new Uint8Array(this.len); let o = 0;
    for (const p of this.parts) { buf.set(p, o); o += p.length; }
    this.parts = []; this.len = 0;
    await this.w.write(buf);
  }
  async close() { await this.flush(); this.closed = true; await this.w.close(); }
  async abort() { this.parts = []; this.len = 0; if (this.closed) return; try { await this.w.abort(); } catch (_e) { /* 已关闭 / 不支持 */ } }
}

export function createVolumeFS(pq, { randomBytes }) {
  if (!pq || !randomBytes) throw new Error("createVolumeFS: 缺少 pq / randomBytes");

  // ---- 目录小工具 -------------------------------------------------------------
  async function listEntries(dir) {
    const out = [];
    for await (const [name, handle] of dir.entries()) out.push({ name, kind: handle.kind });
    // 稳定顺序：文件在前、目录在后，各按名字排序，便于日志 / 测试可复现
    out.sort((a, b) => (a.kind === b.kind ? (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) : a.kind === "file" ? -1 : 1));
    return out;
  }
  async function exists(dir, name) {
    try { await dir.getFileHandle(name); return "file"; } catch (e) {
      if (e && e.name === "TypeMismatchError") return "directory";
      if (!isNotFound(e)) throw e;
    }
    try { await dir.getDirectoryHandle(name); return "directory"; } catch (e) {
      if (e && e.name === "TypeMismatchError") return "file";
      if (!isNotFound(e)) throw e;
    }
    return null;
  }
  async function readFileBytes(dir, name) {
    const f = await (await dir.getFileHandle(name)).getFile();
    return new Uint8Array(await f.arrayBuffer());
  }
  async function writeFileBytes(dir, name, bytes) {
    const h = await dir.getFileHandle(name, { create: true });
    const w = await h.createWritable();
    let ok = false;
    try { await w.write(bytes); await w.close(); ok = true; }
    finally { if (!ok) { try { await w.abort(); } catch (_e) { /* 忽略 */ } } }
  }
  async function removeIfEmpty(dir, name) {
    try { await dir.removeEntry(name); return true; } catch (_e) { return false; }
  }
  // 只读文件开头 ≤ 74 字节判断一个 .pqfc 的归属（不读正文）。
  async function probeFile(dir, name) {
    const f = await (await dir.getFileHandle(name)).getFile();
    const head = new Uint8Array(await f.slice(0, pq.VOLUME_HDR_LEN).arrayBuffer());
    return { size: f.size, probe: pq.probeHeader(head) };
  }
  function joinPath(base, name) { return base ? base + "/" + name : name; }

  // ---- 卷头 -------------------------------------------------------------------
  async function readVolumeHeader(root) {
    let bytes;
    try { bytes = await readFileBytes(root, VOLUME_HEADER_NAME); }
    catch (e) { if (isNotFound(e)) return null; throw e; }
    let obj;
    try { obj = JSON.parse(_TD.decode(bytes)); }
    catch (_e) { throw new Error("卷头文件 " + VOLUME_HEADER_NAME + " 不是有效 JSON（已损坏？可用备份恢复）"); }
    pq.validateVolumeHeader(obj);
    return obj;
  }
  async function writeVolumeHeader(root, header) {
    pq.validateVolumeHeader(header);
    await writeFileBytes(root, VOLUME_HEADER_NAME, _TE.encode(JSON.stringify(header, null, 2)));
  }

  // ---- 目录清单（隐藏文件名模式）---------------------------------------------
  // 明文 JSON：{ v:1, dir:<本目录在磁盘上的 ID，根为 "">, entries:{ <id>: { n:原名, t:"f"|"d" } } }
  async function loadManifest(dir, dirId, ctx) {
    let bytes;
    try { bytes = await readFileBytes(dir, DIR_MANIFEST_NAME); }
    catch (e) { if (isNotFound(e)) return null; throw e; }
    const pt = await pq.decryptVolumeBytes(ctx.vmk, ctx.volumeId, bytes);
    let m;
    try { m = JSON.parse(_TD.decode(pt)); } catch (_e) { throw new Error("目录清单解密后不是有效 JSON"); }
    if (!m || m.v !== 1 || typeof m.dir !== "string" || !m.entries || typeof m.entries !== "object")
      throw new Error("目录清单格式异常");
    if (m.dir !== dirId) throw new Error("目录清单与所在目录不匹配（清单可能被移动 / 调换）");
    return m;
  }
  async function saveManifest(dir, dirId, entries, ctx) {
    const pt = _TE.encode(JSON.stringify({ v: 1, dir: dirId, entries }));
    await writeFileBytes(dir, DIR_MANIFEST_NAME, await pq.encryptVolumeBytes(ctx.vmk, ctx.volumeId, pt));
  }
  function newId(taken) {
    for (;;) { const id = hex(randomBytes(ID_BYTES)); if (!taken.has(id)) { taken.add(id); return id; } }
  }

  // ---- 扫描（不改动任何东西）---------------------------------------------------
  // 返回 { files, bytes, dirs, encrypted, encryptedBytes, foreign, skippedDirs, plain }
  //   files/bytes   ：将被加密的明文文件数 / 字节数（volumeId 为空时：一切非工具文件）
  //   encrypted     ：已属于本卷的 .pqfc（volumeId 非空时）
  //   foreign       ：本工具格式但不属于本卷 / 非卷模式的 .pqfc（加密、解密时都跳过，绝不二次加密）
  async function scanTree(root, { volumeId = null, signal = null } = {}) {
    const st = { files: 0, bytes: 0, dirs: 0, encrypted: 0, encryptedBytes: 0, foreign: 0, skippedDirs: [], plain: 0, largest: 0 };
    async function walk(dir, rel, isRoot) {
      if (signal && signal.aborted) throw Object.assign(new Error("已取消"), { code: "ABORTED" });
      for (const e of await listEntries(dir)) {
        if (e.kind === "directory") {
          if (isRoot && SYSTEM_DIRS.has(e.name)) { st.skippedDirs.push(e.name); continue; }
          st.dirs++;
          let sub;
          try { sub = await dir.getDirectoryHandle(e.name); } catch (_e) { st.skippedDirs.push(joinPath(rel, e.name)); continue; }
          await walk(sub, joinPath(rel, e.name), false);
          continue;
        }
        if (isRoot && e.name === VOLUME_HEADER_NAME) continue;
        if (e.name === DIR_MANIFEST_NAME) continue;
        let size = 0;
        if (e.name.endsWith(ENC_EXT)) {
          let info;
          try { info = await probeFile(dir, e.name); } catch (_e) { continue; }
          size = info.size;
          if (info.probe.ok && info.probe.volumeId && volumeId && pq.bytesEqual(info.probe.volumeId, volumeId)) {
            st.encrypted++; st.encryptedBytes += size; continue;
          }
          if (info.probe.ok) { st.foreign++; continue; } // 其它卷 / 单文件模式：加密与解密时都跳过，绝不二次加密
        } else {
          try { size = (await (await dir.getFileHandle(e.name)).getFile()).size; } catch (_e) { continue; }
        }
        st.files++; st.bytes += size; if (size > st.largest) st.largest = size;
      }
    }
    await walk(root, "", true);
    return st;
  }

  // ---- 加密整棵树 ---------------------------------------------------------------
  // ctx  = { vmk, volumeId, hideNames }
  // opts = { keepOriginals=false, verify=true, onEvent(ev), signal }
  // 返回 { files, bytes, skipped(已属本卷), foreign(其它卷 / 单文件模式，跳过), errors:[{path,message}], cancelled }
  async function encryptTree(root, ctx, opts = {}) {
    const keep = !!opts.keepOriginals, verify = opts.verify !== false;
    const emit = (ev) => { if (opts.onEvent) opts.onEvent(ev); };
    const res = { files: 0, bytes: 0, skipped: 0, foreign: 0, errors: [], cancelled: false };
    const aborted = () => !!(opts.signal && opts.signal.aborted);

    async function encryptOne(srcDir, name, dstDir, outName, relPath) {
      const fh = await srcDir.getFileHandle(name);
      const file = await fh.getFile();
      emit({ type: "file-start", path: relPath, size: file.size });
      // 输出名已被占用：只允许覆盖“本卷自己的旧密文”（上次中断留下的同名副本）；
      // 其它任何东西（目录 / 明文 / 别的卷或单文件模式的 .pqfc）一律不覆盖。
      const ex = await exists(dstDir, outName);
      if (ex === "directory") throw new Error("输出名 " + outName + " 已被同名目录占用，未处理");
      if (ex === "file") {
        let ours = false;
        try { const p = await probeFile(dstDir, outName); ours = !!(p.probe.ok && p.probe.volumeId && pq.bytesEqual(p.probe.volumeId, ctx.volumeId)); } catch (_e) { ours = false; }
        if (!ours) throw new Error("输出名 " + outName + " 已存在且不是本卷的密文，未覆盖");
      }
      const outH = await dstDir.getFileHandle(outName, { create: true });
      const sink = new BufferedSink(await outH.createWritable());
      let written = false;
      try {
        await pq.encryptVolumeStream(ctx.vmk, ctx.volumeId, file.stream(), sink,
          { signal: opts.signal, onProgress: (n) => emit({ type: "progress", bytes: n }) });
        await sink.close();
        written = true;
      } finally {
        if (!written) { await sink.abort(); try { await dstDir.removeEntry(outName); } catch (_e) { /* 可能没创建成功 */ } }
      }
      if (verify) {
        emit({ type: "verify-start", path: relPath });
        let good = false;
        try {
          const f2 = await (await dstDir.getFileHandle(outName)).getFile();
          const r = await pq.decryptVolumeStream(ctx.vmk, ctx.volumeId, new pq.ByteReader(f2.stream()), null,
            { signal: opts.signal, onProgress: (n) => emit({ type: "progress", bytes: n }) });
          good = r.bytesOut === file.size;
          if (!good) throw new Error("校验：解密长度与原文件不符");
        } finally {
          if (!good) { try { await dstDir.removeEntry(outName); } catch (_e) { /* 忽略 */ } }
        }
      }
      if (!keep) await srcDir.removeEntry(name);
      res.files++; res.bytes += file.size;
      emit({ type: "file-done", path: relPath, size: file.size });
    }

    async function walk(srcDir, dstDir, dirId, rel, isRoot) {
      if (aborted()) throw Object.assign(new Error("已取消"), { code: "ABORTED" });
      const entries = await listEntries(srcDir);
      const same = srcDir === dstDir;
      // 隐藏模式：目标目录的清单（ID → 原名）；反向表用于给同名明文复用旧 ID
      let manifest = null, byName = new Map(), taken = new Set();
      if (ctx.hideNames) {
        try { manifest = await loadManifest(dstDir, dirId, ctx); }
        catch (e) { res.errors.push({ path: joinPath(rel, DIR_MANIFEST_NAME), message: "目录清单无法读取，跳过该目录：" + e.message }); emit({ type: "dir-skip", path: rel || "(根)", reason: e.message }); return; }
        const dstNames = same ? entries : await listEntries(dstDir);
        const present = new Set(dstNames.map((e) => e.name));
        const kept = {};
        for (const [id, ent] of Object.entries((manifest && manifest.entries) || {})) {
          if (present.has(id) || present.has(id + ENC_EXT)) kept[id] = ent; // 清理孤儿条目
        }
        manifest = { entries: kept };
        for (const [id, ent] of Object.entries(kept)) { taken.add(id); byName.set(ent.t + ":" + ent.n, id); }
        for (const e of dstNames) taken.add(e.name.endsWith(ENC_EXT) ? e.name.slice(0, -ENC_EXT.length) : e.name);
      }

      // 分类
      const plainFiles = [], plainDirs = [], encDirs = [];
      for (const e of entries) {
        if (e.kind === "directory") {
          if (isRoot && SYSTEM_DIRS.has(e.name)) { emit({ type: "dir-skip", path: e.name, reason: "系统目录" }); continue; }
          if (ctx.hideNames && manifest.entries[e.name] && manifest.entries[e.name].t === "d") { encDirs.push(e.name); continue; } // 已是加密目录：仍进去找新放入的明文
          plainDirs.push(e.name);
          continue;
        }
        if (isRoot && e.name === VOLUME_HEADER_NAME) continue;
        if (e.name === DIR_MANIFEST_NAME) continue;
        if (e.name.endsWith(ENC_EXT)) {
          let info;
          try { info = await probeFile(srcDir, e.name); }
          catch (err) { res.errors.push({ path: joinPath(rel, e.name), message: err.message }); continue; }
          if (info.probe.ok && info.probe.volumeId && pq.bytesEqual(info.probe.volumeId, ctx.volumeId)) { res.skipped++; continue; } // 已加密
          if (info.probe.ok) {
            // 本工具格式但不属于本卷（别的卷 / 单文件模式）：跳过，绝不二次加密——
            // 最常见的情形是误选了某个加密卷的子目录，二次加密只会把事情搞乱。
            res.foreign++;
            emit({ type: "file-skip", path: joinPath(rel, e.name), reason: "已是本工具的加密文件（其它卷 / 单文件模式），未二次加密，原地保留" + (ctx.hideNames && !same ? "（其所在目录名因此保留）" : "") });
            continue;
          }
          // 只是名字以 .pqfc 结尾的普通文件：按普通数据处理
        }
        plainFiles.push(e.name);
      }

      // 先处理本身以 .pqfc 结尾的“外来容器”，避免 x 的输出 x.pqfc 与它撞名
      plainFiles.sort((a, b) => (b.endsWith(ENC_EXT) ? 1 : 0) - (a.endsWith(ENC_EXT) ? 1 : 0));

      // 隐藏模式：先为本轮全部明文条目分配 ID 并落盘清单，再动任何文件
      const idOf = new Map();
      if (ctx.hideNames) {
        for (const n of plainFiles) { const k = "f:" + n; const id = byName.get(k) || newId(taken); byName.set(k, id); manifest.entries[id] = { n, t: "f" }; idOf.set(k, id); }
        for (const n of plainDirs) { const k = "d:" + n; const id = byName.get(k) || newId(taken); byName.set(k, id); manifest.entries[id] = { n, t: "d" }; idOf.set(k, id); }
        try { await saveManifest(dstDir, dirId, manifest.entries, ctx); }
        catch (e) { res.errors.push({ path: joinPath(rel, DIR_MANIFEST_NAME), message: "目录清单写入失败，跳过该目录：" + e.message }); return; }
      }

      for (const n of plainFiles) {
        if (aborted()) throw Object.assign(new Error("已取消"), { code: "ABORTED" });
        const relPath = joinPath(rel, n);
        const outName = ctx.hideNames ? idOf.get("f:" + n) + ENC_EXT : n + ENC_EXT;
        try { await encryptOne(srcDir, n, dstDir, outName, relPath); }
        catch (e) {
          if (isFatal(e)) throw e;
          res.errors.push({ path: relPath, message: e.message || String(e) });
          emit({ type: "file-error", path: relPath, message: e.message || String(e) });
        }
      }
      for (const n of plainDirs) {
        if (aborted()) throw Object.assign(new Error("已取消"), { code: "ABORTED" });
        let childSrc;
        try { childSrc = await srcDir.getDirectoryHandle(n); }
        catch (e) { res.errors.push({ path: joinPath(rel, n), message: e.message }); continue; }
        let childDst = childSrc, childId = n;
        if (ctx.hideNames) {
          childId = idOf.get("d:" + n);
          try { childDst = await dstDir.getDirectoryHandle(childId, { create: true }); }
          catch (e) { res.errors.push({ path: joinPath(rel, n), message: "无法创建目标目录：" + e.message }); continue; }
        }
        await walk(childSrc, childDst, childId, joinPath(rel, n), false);
        if (ctx.hideNames && !keep) await removeIfEmpty(srcDir, n); // 只删已经腾空的原目录
      }
      // 隐藏模式下已加密的目录：以它自己为源和目标递归（新放进去的明文会就地加密并登记到该目录清单）
      for (const id of encDirs) {
        if (aborted()) throw Object.assign(new Error("已取消"), { code: "ABORTED" });
        let d;
        try { d = await srcDir.getDirectoryHandle(id); } catch (_e) { continue; }
        await walk(d, d, id, joinPath(rel, manifest.entries[id].n), false);
      }
    }

    try { await walk(root, root, "", "", true); }
    catch (e) { if (e && e.code === "ABORTED") res.cancelled = true; else throw e; }
    return res;
  }

  // ---- 解密整棵树 ---------------------------------------------------------------
  // opts = { keepOriginals=false, onEvent, signal }
  async function decryptTree(root, ctx, opts = {}) {
    const keep = !!opts.keepOriginals;
    const emit = (ev) => { if (opts.onEvent) opts.onEvent(ev); };
    const res = { files: 0, bytes: 0, skipped: 0, errors: [], warnings: [], cancelled: false, headerRemoved: false };
    const aborted = () => !!(opts.signal && opts.signal.aborted);

    async function decryptOne(srcDir, name, dstDir, outName, relPath) {
      const fh = await srcDir.getFileHandle(name);
      const file = await fh.getFile();
      emit({ type: "file-start", path: relPath, size: file.size });
      if (await exists(dstDir, outName)) {
        res.skipped++;
        emit({ type: "file-skip", path: relPath, reason: "目标 " + outName + " 已存在，未覆盖（密文保留）" });
        return;
      }
      const outH = await dstDir.getFileHandle(outName, { create: true });
      const sink = new BufferedSink(await outH.createWritable());
      let written = false;
      try {
        await pq.decryptVolumeStream(ctx.vmk, ctx.volumeId, new pq.ByteReader(file.stream()), sink,
          { signal: opts.signal, onProgress: (n) => emit({ type: "progress", bytes: n }) });
        await sink.close();
        written = true;
      } finally {
        if (!written) { await sink.abort(); try { await dstDir.removeEntry(outName); } catch (_e) { /* 忽略 */ } }
      }
      if (!keep) await srcDir.removeEntry(name);
      res.files++; res.bytes += file.size;
      emit({ type: "file-done", path: relPath, size: file.size });
    }

    // 返回本目录（含子目录）是否全部成功
    async function walk(srcDir, dstDir, dirId, rel, isRoot) {
      if (aborted()) throw Object.assign(new Error("已取消"), { code: "ABORTED" });
      const entries = await listEntries(srcDir);
      let manifest = null, clean = true;
      if (ctx.hideNames) {
        try { manifest = await loadManifest(srcDir, dirId, ctx); }
        catch (e) { res.errors.push({ path: joinPath(rel, DIR_MANIFEST_NAME), message: e.message }); clean = false; }
        if (manifest === null && entries.some((e) => e.name.endsWith(ENC_EXT))) {
          // 清单丢失：内容照常救回，但文件 / 目录只能按 ID 命名；记为警告并保留卷头
          res.warnings.push({ path: joinPath(rel, DIR_MANIFEST_NAME), message: "目录清单缺失：该目录内的文件 / 子目录名无法恢复，已按 ID 命名还原" });
          emit({ type: "file-warn", path: joinPath(rel, DIR_MANIFEST_NAME), message: "目录清单缺失，该目录内容按 ID 命名还原" });
          clean = false;
        }
      }
      const ents = (manifest && manifest.entries) || {};

      for (const e of entries) {
        if (e.kind !== "file") continue;
        if (aborted()) throw Object.assign(new Error("已取消"), { code: "ABORTED" });
        if (isRoot && e.name === VOLUME_HEADER_NAME) continue;
        if (e.name === DIR_MANIFEST_NAME) continue;
        if (!e.name.endsWith(ENC_EXT)) continue; // 明文文件，不动
        const relPath = joinPath(rel, e.name);
        let info;
        try { info = await probeFile(srcDir, e.name); }
        catch (err) { res.errors.push({ path: relPath, message: err.message }); clean = false; continue; }
        if (!(info.probe.ok && info.probe.volumeId && pq.bytesEqual(info.probe.volumeId, ctx.volumeId))) {
          res.skipped++; emit({ type: "file-skip", path: relPath, reason: info.probe.ok ? "不属于本卷（其它卷 / 单文件模式），已跳过" : "不是本工具的加密文件，已跳过" });
          continue;
        }
        let outName;
        if (ctx.hideNames) {
          const id = e.name.slice(0, -ENC_EXT.length);
          const ent = ents[id];
          if (ent && ent.t === "f") outName = ent.n;
          else { outName = id; emit({ type: "file-warn", path: relPath, message: "清单中没有此文件的原名，已按 ID 命名还原" }); }
        } else {
          outName = e.name.slice(0, -ENC_EXT.length);
        }
        try { await decryptOne(srcDir, e.name, dstDir, outName, ctx.hideNames ? joinPath(rel, outName) : relPath); }
        catch (err) {
          if (isFatal(err)) throw err;
          clean = false;
          res.errors.push({ path: relPath, message: err.message || String(err) });
          emit({ type: "file-error", path: relPath, message: err.message || String(err) });
        }
      }
      for (const e of entries) {
        if (e.kind !== "directory") continue;
        if (aborted()) throw Object.assign(new Error("已取消"), { code: "ABORTED" });
        if (isRoot && SYSTEM_DIRS.has(e.name)) continue;
        let childSrc;
        try { childSrc = await srcDir.getDirectoryHandle(e.name); }
        catch (err) { res.errors.push({ path: joinPath(rel, e.name), message: err.message }); clean = false; continue; }
        let childDst = childSrc, childRel = joinPath(rel, e.name);
        const ent = ctx.hideNames ? ents[e.name] : null;
        if (ent && ent.t === "d") {
          try { childDst = await dstDir.getDirectoryHandle(ent.n, { create: true }); childRel = joinPath(rel, ent.n); }
          catch (err) { res.errors.push({ path: joinPath(rel, e.name), message: "无法创建目标目录：" + err.message }); clean = false; continue; }
        }
        const sub = await walk(childSrc, childDst, e.name, childRel, false);
        if (!sub) clean = false;
        if (sub && childDst !== childSrc && !keep) await removeIfEmpty(srcDir, e.name);
      }
      if (ctx.hideNames && manifest && clean && !keep) { try { await srcDir.removeEntry(DIR_MANIFEST_NAME); } catch (_e) { /* 忽略 */ } }
      return clean;
    }

    try {
      const clean = await walk(root, root, "", "", true);
      if (clean && !keep && res.errors.length === 0) {
        try { await root.removeEntry(VOLUME_HEADER_NAME); res.headerRemoved = true; } catch (_e) { /* 忽略 */ }
      }
    } catch (e) { if (e && e.code === "ABORTED") res.cancelled = true; else throw e; }
    return res;
  }

  return { readVolumeHeader, writeVolumeHeader, scanTree, encryptTree, decryptTree, listEntries, exists, readFileBytes, writeFileBytes, BufferedSink };
}
