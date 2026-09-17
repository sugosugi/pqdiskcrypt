/*
 * pqcrypto-core —— 抗量子加密核心（浏览器 / Node 通用）—— 格式 v2 + 卷模式
 * ============================================================================
 *
 * ⚠ 重要：本版本（文件格式 v2）刻意【不】兼容旧的 v1 / pqfilecrypt.py。
 *   旧的 .pqfc / .pub / .key 无法用本版本解开，反之亦然。这是为了换取一套
 *   更强、更可证明安全的密码学构造（见下）。
 *
 * 第四轮（硬盘加密）新增【卷模式】（MODE_VOLUME = 4），文件版本字节仍为 2：
 *   · 每个加密卷（一块硬盘 / 一个目录树）有一把随机 32 字节【卷主密钥 VMK】；
 *     VMK 从不直接落盘，只以“密钥槽”形式存在于卷头 .pqvolume 中：
 *       - 口令槽：Argon2id(口令, salt) → SHA-512(标签 ‖ 主密钥) → {包裹密钥, 承诺值}
 *       - 公钥槽：X25519 + ML-KEM-1024 混合 KEM（同 v2 组合器、独立域标签）→ {包裹密钥, 承诺值}
 *     再用 AES-256-GCM（AAD = 标签 ‖ 卷 ID ‖ 槽类型）包裹 VMK。任一槽都能解出 VMK，
 *     故可随时增删口令 / 公钥而【无需重新加密整块硬盘】（LUKS / BitLocker 的密钥槽思路）。
 *   · 每个文件用独立随机 salt 从 VMK 派生自己的密钥：
 *       SHA-512(标签 ‖ VMK ‖ 卷 ID ‖ salt) → {文件密钥 32B, 承诺值 32B}
 *     文件头 = MAGIC ‖ v2 ‖ mode=4 ‖ 卷 ID(16) ‖ salt(16) ‖ 承诺值(32)，正文沿用
 *     与 v2 完全相同的 64 KiB 分块流式 AES-256-GCM（头作 AAD，nonce = 计数器 ‖ 末块标记）。
 *     Argon2id 只在解锁卷时跑一次，成千上万个文件的逐文件加密只有哈希 + AES 开销。
 *   · 新增真正的【流式】接口（ReadableStream → sink），大文件不再整体读入内存。
 *   · 旧版工具遇到 mode=4 文件会以“未知模式”安全拒绝，不会误处理。
 *
 * 设计要点：
 *   · 混合 KEM（公钥模式）：X25519（Web Crypto，经典）+ ML-KEM-1024（注入，后量子）。
 *     —— 组合器采用 X-Wing 风格的“随机预言机一次性哈希”构造：
 *           t = SHA-512( 域分隔标签 ‖ ss_mlkem ‖ ss_x25519
 *                        ‖ mlkem_ct ‖ mlkem_pk ‖ eph_x25519_pk ‖ recip_x25519_pk ‖ salt )
 *        把【两个共享密钥】与【全部相关公开值】一次性绑定。
 *        只要其中【任一】KEM 仍安全，派生密钥即安全（混合安全的核心目标）；
 *        同时把密文 / 公钥绑死，杜绝重封装 / 密钥混淆 / 非规范点等一类攻击。
 *     —— 相较旧版 “HKDF(ss_M‖ss_X)” 的拼接组合器：新构造不依赖 HKDF-Extract 的
 *        “对偶 PRF”这一较强假设，且显式绑定了收件人静态公钥。
 *   · 口令模式：Argon2id（注入，内存硬 KDF）得到主密钥，再经 SHA-512 派生。
 *   · 密钥承诺（key commitment）：上述 SHA-512 输出 64 字节，前 32 字节作 AES 密钥，
 *     后 32 字节作【承诺值】写入文件头。解密时先以常数时间核对承诺值，再做 GCM。
 *     —— AES-GCM 本身【不】承诺密钥（存在分区谕示 / 多密钥伪造一类隐患）；
 *        增加承诺值后，一段密文只可能被【唯一】正确密钥合法解开，
 *        消除该类隐患，同时让“口令/密钥错误”能快速、明确地失败。
 *   · 批量加密：AES-256-GCM，64 KiB 分块流式、逐块认证，
 *     nonce = 大端计数器 ‖ 1 字节结束标记，天然防截断 / 防重排 / 防拼接。
 *   · 仅用浏览器原生、已审计的 Web Crypto 实现 AES-256-GCM / SHA-512 / SHA-256 / X25519；
 *     仅把浏览器还做不到的两件事（ML-KEM、Argon2id）作为依赖注入。
 *
 * 依赖注入（createPQCrypto 的参数）让核心逻辑与 ML-KEM / Argon2id 的具体实现解耦，
 * 既可在 Node 中用真实 Web Crypto 做往返自测，也便于单独审计、替换实现。
 */

// ----------------------------------------------------------------------------
// 常量
// ----------------------------------------------------------------------------
const MAGIC = new Uint8Array([0x50, 0x51, 0x46, 0x43, 0x52, 0x59, 0x50, 0x54]); // "PQFCRYPT"
const VERSION = 2;              // ← 格式 v2（不兼容 v1）
const MODE_HYBRID = 1;
const MODE_PASSWORD = 2;
const MODE_HYBRID_SIGNED = 3;   // 混合公钥模式 + 发件人 ML-DSA 签名（头部布局同 MODE_HYBRID）
const MODE_VOLUME = 4;          // 卷模式（硬盘加密）：文件密钥由卷主密钥 VMK + 逐文件 salt 派生

const VOLUME_ID_LEN = 16;       // 卷 ID（随机，公开；写进每个文件头以识别归属）
const VMK_LEN = 32;             // 卷主密钥长度
const VOLUME_FORMAT = "pqdisk-volume-v1";
const SLOT_PASSWORD = "password";
const SLOT_PUBKEY = "pubkey";

const CHUNK_SIZE = 64 * 1024;   // 明文分块（64 KiB）
const KEY_LEN = 32;             // AES-256
const COMMIT_LEN = 32;          // 密钥承诺值长度（SHA-512 后半段）
const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;             // AES-GCM 认证标签（128 bit）
const X25519_LEN = 32;          // 原始 X25519 公钥 / 私钥长度
const MAX_BLOCK = CHUNK_SIZE + TAG_LEN; // 合法密文块长度上限（明文块 + GCM 标签）

// Argon2id 默认参数（写进文件头，解密端自动读取）：内存 256 MiB / t=4 / p=4。
// 这是相当强的设置（远高于 OWASP 下限）；浏览器 WASM 下 256 MiB 已接近移动端可用上限，
// 继续抬高内存对安全收益有限、却显著增加 OOM 风险，故维持此值。
const ARGON_TIME = 4;
const ARGON_MEM_KIB = 256 * 1024; // 256 MiB
const ARGON_PAR = 4;

// 解密时对 Argon2 参数的安全上限：防止恶意 .pqfc / 私钥容器把内存设成
// 几个 GiB 来触发内存耗尽（DoS）。合法文件远低于此上限。
const ARGON_MEM_CAP_KIB = 2 * 1024 * 1024; // 2 GiB
const ARGON_TIME_CAP = 64;
const ARGON_PAR_CAP = 16;

// ML-KEM-1024（FIPS 203）定长字节数，用于严格校验、拒绝畸形输入。
const MLKEM1024_PK_LEN = 1568;
const MLKEM1024_SK_LEN = 3168;
const MLKEM1024_CT_LEN = 1568;

// ML-DSA-87（FIPS 204，安全等级 5，与 ML-KEM-1024 同级）定长字节数。
// 以下为预期值；运行期仍以注入库 mldsa.lengths 为准做严格校验（防错配参数集）。
const MLDSA87_PK_LEN  = 2592;
const MLDSA87_SK_LEN  = 4896;
const MLDSA87_SIG_LEN = 4627;
const SIG_ALG_MLDSA87 = 1;       // 签名封套里的算法标识字节
const SIG_ENVELOPE_HDR_MAX = 1 + 2 + MLDSA87_PK_LEN + 2 + MLDSA87_SIG_LEN; // 封套头部上限，防畸形

// RFC 8410：X25519 私钥的 PKCS#8 DER 前缀（用于把 32 字节原始私钥导入 Web Crypto）
const PKCS8_X25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

// 域分隔标签（domain separation）：确保不同用途的哈希互不“串味”，
// 也把协议版本钉进密钥派生，杜绝跨版本 / 跨用途的混淆攻击。
const _TE = new TextEncoder();
const DS_HYBRID  = _TE.encode("pqfilecrypt:v2:hybrid-kem:x25519+ml-kem-1024");
const DS_PW      = _TE.encode("pqfilecrypt:v2:password-kdf:argon2id");
const DS_KEYWRAP = _TE.encode("pqfilecrypt:v2:keywrap-kdf:argon2id");
const DS_FP      = _TE.encode("pqfilecrypt:v2:public-key-fingerprint");
const DS_SIGN    = _TE.encode("pqfilecrypt:v2:sender-auth:ml-dsa-87");
const DS_SIG_FP  = _TE.encode("pqfilecrypt:v2:signer-fingerprint");
// 卷模式（硬盘加密）专用标签：与 v2 单文件路径彻底隔离。
const DS_VOL_FILE   = _TE.encode("pqdisk:v1:file-key:vmk");
const DS_VOL_PW     = _TE.encode("pqdisk:v1:slot-kdf:argon2id");
const DS_VOL_HYBRID = _TE.encode("pqdisk:v1:slot-kem:x25519+ml-kem-1024");
const DS_VOL_WRAP   = _TE.encode("pqdisk:v1:slot-wrap:aes-256-gcm");

// ----------------------------------------------------------------------------
// 小工具
// ----------------------------------------------------------------------------
function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

// 常数时间比较：不随匹配前缀长度提前返回，避免计时侧信道。
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// 带机器可读 code 的错误（供 UI 区分“口令错误”与其它失败，而不必匹配中文文案）。
function mkErr(message, code) { const e = new Error(message); if (code) e.code = code; return e; }

// 尽力清零敏感缓冲区（JS 无法保证彻底抹除，仅缩小暴露窗口）。
function wipe(...arrays) {
  for (const a of arrays) {
    try { if (a && a.fill) a.fill(0); } catch (_e) { /* 视图可能已分离，忽略 */ }
  }
}

function u16be(n) { return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]); }
function u32be(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
function readU16be(b, o) { return (b[o] << 8) | b[o + 1]; }
function readU32be(b, o) {
  return ((b[o] * 0x1000000) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3]) >>> 0;
}

const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_LOOKUP = (() => {
  const t = new Int16Array(256).fill(-1);
  for (let i = 0; i < B64_CHARS.length; i++) t[B64_CHARS.charCodeAt(i)] = i;
  return t;
})();

function b64encode(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
    out += B64_CHARS[a >> 2];
    out += B64_CHARS[((a & 3) << 4) | (b === undefined ? 0 : b >> 4)];
    out += b === undefined ? "=" : B64_CHARS[((b & 15) << 2) | (c === undefined ? 0 : c >> 6)];
    out += c === undefined ? "=" : B64_CHARS[c & 63];
  }
  return out;
}

// 严格 Base64 解码：拒绝非法字符与不可能的长度（length % 4 === 1），
// 消除“宽松解码”带来的可塑性（同一字节串有多种文本表示）。容忍可选 '=' 填充。
function b64decode(str) {
  if (typeof str !== "string") throw new Error("Base64 解码失败：输入不是字符串");
  let s = str;
  // 去掉尾部 ASCII 空白（换行 / 空格），但不容忍内部杂字符。
  s = s.replace(/[\r\n\t ]+$/g, "");
  let pad = 0;
  while (s.endsWith("=")) { s = s.slice(0, -1); pad++; }
  if (pad > 2) throw new Error("Base64 解码失败：填充非法");
  if (s.length % 4 === 1) throw new Error("Base64 解码失败：长度非法");
  const out = new Uint8Array(Math.floor(s.length * 3 / 4));
  let p = 0, buf = 0, bits = 0;
  for (let i = 0; i < s.length; i++) {
    const v = B64_LOOKUP[s.charCodeAt(i)];
    if (v < 0) throw new Error("Base64 解码失败：含非法字符");
    buf = (buf << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; out[p++] = (buf >> bits) & 0xff; }
  }
  // 第三轮：规范化（canonical）检查——末尾不足一字节的残余位必须全为 0。
  // 否则 "QQ==" 与 "QR==" 会解出同一字节串，即同一密钥有多种文本表示（可塑性）。
  if (bits > 0 && (buf & ((1 << bits) - 1)) !== 0)
    throw new Error("Base64 解码失败：非规范编码（残余位非零）");
  return out.subarray(0, p);
}

// ----------------------------------------------------------------------------
// 工厂：注入 { subtle, randomBytes, mlkem, argon2id }
//   subtle      : SubtleCrypto（window.crypto.subtle / Node webcrypto.subtle）
//   randomBytes : (n)=>Uint8Array 安全随机字节
//   mlkem       : { keygen()->{publicKey,secretKey},
//                   encapsulate(pk)->{cipherText,sharedSecret},
//                   decapsulate(ct,sk)->sharedSecret }   (ML-KEM-1024 / FIPS 203)
//   argon2id    : async ({password,salt,iterations,memorySizeKiB,parallelism,hashLen})
//                   -> Uint8Array(hashLen)
// ----------------------------------------------------------------------------
function createPQCrypto({ subtle, randomBytes, mlkem, argon2id, mldsa }) {
  if (!subtle) throw new Error("createPQCrypto: 缺少 subtle (Web Crypto)");
  if (!randomBytes) throw new Error("createPQCrypto: 缺少 randomBytes");

  // ---- 原语封装 -----------------------------------------------------------
  async function sha256(data) {
    return new Uint8Array(await subtle.digest("SHA-256", data));
  }
  async function sha512(data) {
    return new Uint8Array(await subtle.digest("SHA-512", data));
  }

  async function importAesKey(rawKey) {
    return subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt", "decrypt"]);
  }

  // 12 字节 nonce = 11 字节大端计数器 + 1 字节结束标记（0x01=最后一块）。
  function nonce(counter, isLast) {
    const n = new Uint8Array(NONCE_LEN);
    let c = counter;
    for (let i = 10; i >= 0; i--) { n[i] = c & 0xff; c = Math.floor(c / 256); }
    n[11] = isLast ? 0x01 : 0x00;
    return n;
  }

  // ---- 流式 AEAD 内核 -----------------------------------------------------
  // 同一文件用唯一密钥 → 计数器从 0 起即可保证 nonce 不重复；
  // 末块标记 + 计数器使任何截断 / 扩展 / 重排都会令认证失败。
  async function encryptStream(rawKey, header, data) {
    const aesKey = await importAesKey(rawKey);
    const chunks = [];
    for (let off = 0; off < data.length; off += CHUNK_SIZE) {
      chunks.push(data.subarray(off, Math.min(off + CHUNK_SIZE, data.length)));
    }
    if (chunks.length === 0) chunks.push(new Uint8Array(0)); // 空文件也产生一个空块

    const parts = [];
    for (let i = 0; i < chunks.length; i++) {
      const isLast = i === chunks.length - 1;
      const blob = new Uint8Array(await subtle.encrypt(
        { name: "AES-GCM", iv: nonce(i, isLast), additionalData: header, tagLength: 128 },
        aesKey, chunks[i],
      ));
      parts.push(u32be(blob.length), blob);
    }
    return concatBytes(...parts);
  }

  async function decryptStream(rawKey, header, body) {
    const aesKey = await importAesKey(rawKey);
    const blocks = [];
    let off = 0;
    while (off < body.length) {
      if (off + 4 > body.length) throw new Error("文件意外结束（可能已损坏或被截断）");
      const clen = readU32be(body, off); off += 4;
      // 合法块长度区间：[TAG_LEN, CHUNK_SIZE+TAG_LEN]，提前拒绝畸形长度。
      if (clen < TAG_LEN || clen > MAX_BLOCK)
        throw new Error("密文块长度异常（文件可能已损坏或被篡改）");
      if (off + clen > body.length) throw new Error("文件意外结束（可能已损坏或被截断）");
      blocks.push(body.subarray(off, off + clen)); off += clen;
    }
    if (blocks.length === 0) throw new Error("密文为空或已损坏");

    const out = [];
    for (let i = 0; i < blocks.length; i++) {
      const isLast = i === blocks.length - 1;
      let pt;
      try {
        pt = new Uint8Array(await subtle.decrypt(
          { name: "AES-GCM", iv: nonce(i, isLast), additionalData: header, tagLength: 128 },
          aesKey, blocks[i],
        ));
      } catch (e) {
        throw new Error("认证失败：文件被篡改 / 被截断，或密钥 / 口令不正确。");
      }
      out.push(pt);
    }
    return concatBytes(...out);
  }

  // ---- 密钥派生 -----------------------------------------------------------
  // 把 64 字节哈希输出切成 { 加密密钥 32B, 承诺值 32B }。
  // 在随机预言机模型下两段相互独立：公开承诺值不会泄露加密密钥。
  function splitKeyCommit(h64) {
    return { encKey: h64.subarray(0, KEY_LEN), commit: h64.subarray(KEY_LEN, KEY_LEN + COMMIT_LEN) };
  }

  // 混合 KEM 组合器（X-Wing 风格，随机预言机一次性哈希）。
  // 绑定两份共享密钥 + 全部相关公开值；输出 64B → {encKey, commit}。
  // label 默认为 v2 单文件标签（字节行为不变）；卷模式的公钥槽传入独立标签 DS_VOL_HYBRID。
  async function hybridDerive({ ssMlkem, ssX25519, mlkemCt, mlkemPk, ephPk, recipPk, salt, label = DS_HYBRID }) {
    const seed = concatBytes(label, ssMlkem, ssX25519, mlkemCt, mlkemPk, ephPk, recipPk, salt);
    const h = await sha512(seed);
    wipe(seed);
    return splitKeyCommit(h);
  }

  // Argon2id 主密钥（内存硬）。
  async function argon2Raw(password, salt, timeCost, memKiB, parallelism, hashLen = KEY_LEN) {
    if (!argon2id) throw new Error("口令模式需要注入 argon2id 实现");
    const pw = typeof password === "string" ? _TE.encode(password) : password;
    const key = await argon2id({
      password: pw, salt,
      iterations: timeCost, memorySizeKiB: memKiB, parallelism, hashLen,
    });
    return key instanceof Uint8Array ? key : new Uint8Array(key);
  }

  // 口令派生：Argon2id 主密钥 → SHA-512(标签 ‖ 主密钥) → {encKey, commit}。
  async function passwordDerive(master) {
    const h = await sha512(concatBytes(DS_PW, master));
    return splitKeyCommit(h);
  }

  // 私钥容器派生：与口令派生同构，但用独立域标签。
  async function keywrapDerive(master) {
    const h = await sha512(concatBytes(DS_KEYWRAP, master));
    return splitKeyCommit(h);
  }

  // ---- X25519（Web Crypto；原始私钥用 PKCS#8 包装存取）-------------------
  async function x25519GenerateRaw() {
    const kp = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const pub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
    const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
    // 第三轮：严格校验 PKCS#8 形状（RFC 8410 v0 结构，固定 48 字节 = 16 字节前缀 + 32 字节私钥），
    // 而不是盲取末 32 字节——若某实现导出带公钥附件的 v2 结构，末 32 字节会是【公钥】。
    if (pkcs8.length !== PKCS8_X25519_PREFIX.length + X25519_LEN
        || !bytesEqual(pkcs8.subarray(0, PKCS8_X25519_PREFIX.length), PKCS8_X25519_PREFIX))
      throw new Error("X25519 私钥导出格式异常（非预期的 PKCS#8 结构），已拒绝以防误用");
    const priv = pkcs8.subarray(PKCS8_X25519_PREFIX.length);
    const out = { publicKey: pub, privateKey: new Uint8Array(priv) };
    wipe(pkcs8);
    return out;
  }

  async function x25519ImportPrivate(rawPriv) {
    const pkcs8 = concatBytes(PKCS8_X25519_PREFIX, rawPriv);
    return subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, false, ["deriveBits"]);
  }

  async function x25519ImportPublic(rawPub) {
    return subtle.importKey("raw", rawPub, { name: "X25519" }, false, []);
  }

  async function x25519Exchange(privKeyObj, peerPubRaw) {
    const peer = await x25519ImportPublic(peerPubRaw);
    // Web Crypto 的 X25519 在结果为全零（低阶点）时会抛错；
    // 即便不抛，混合组合器也会把 ML-KEM 共享密钥一并绑定，安全不受单点失效影响。
    const bits = await subtle.deriveBits({ name: "X25519", public: peer }, privKeyObj, X25519_LEN * 8);
    return new Uint8Array(bits);
  }

  // ---- 文件头 -------------------------------------------------------------
  // 注意：文件头整体作为每个 AES-GCM 块的 AAD 被认证；承诺值也随头一起写入并受保护。
  function buildHeaderHybrid(ephPub, mlkemCt, salt, commit) {
    return concatBytes(
      MAGIC, new Uint8Array([VERSION, MODE_HYBRID]),
      ephPub, u16be(mlkemCt.length), mlkemCt, salt, commit,
    );
  }

  function buildHeaderPassword(salt, timeCost, memKiB, parallelism, commit) {
    return concatBytes(
      MAGIC, new Uint8Array([VERSION, MODE_PASSWORD]),
      salt, new Uint8Array([timeCost]), u32be(memKiB), new Uint8Array([parallelism]), commit,
    );
  }

  // 卷模式文件头（定长 74 字节）：MAGIC ‖ v ‖ mode=4 ‖ 卷 ID(16) ‖ 文件 salt(16) ‖ 承诺值(32)
  function buildHeaderVolume(volumeId, fileSalt, commit) {
    return concatBytes(
      MAGIC, new Uint8Array([VERSION, MODE_VOLUME]),
      volumeId, fileSalt, commit,
    );
  }
  const VOLUME_HDR_LEN = MAGIC.length + 2 + VOLUME_ID_LEN + SALT_LEN + COMMIT_LEN;

  function parseHeader(buf) {
    const need = (n, off) => { if (off + n > buf.length) throw new Error("文件头不完整"); };
    need(MAGIC.length, 0);
    if (!bytesEqual(buf.subarray(0, MAGIC.length), MAGIC))
      throw new Error("不是有效的 PQFCRYPT 文件（魔数不匹配）");
    let o = MAGIC.length;
    need(2, o);
    const version = buf[o], mode = buf[o + 1]; o += 2;
    if (version !== VERSION)
      throw new Error("不支持的文件版本：" + version + "（本工具仅支持格式 v" + VERSION + "，不兼容旧版 / pqfilecrypt.py）");

    const info = { version, mode };
    if (mode === MODE_HYBRID || mode === MODE_HYBRID_SIGNED) {
      need(X25519_LEN, o); const ephPub = buf.subarray(o, o + X25519_LEN); o += X25519_LEN;
      need(2, o); const ctlen = readU16be(buf, o); o += 2;
      if (ctlen !== MLKEM1024_CT_LEN) throw new Error("文件头损坏：ML-KEM 密文长度异常");
      need(ctlen, o); const mlkemCt = buf.subarray(o, o + ctlen); o += ctlen;
      need(SALT_LEN, o); const salt = buf.subarray(o, o + SALT_LEN); o += SALT_LEN;
      need(COMMIT_LEN, o); const commit = buf.subarray(o, o + COMMIT_LEN); o += COMMIT_LEN;
      Object.assign(info, { ephPub, mlkemCt, salt, commit });
    } else if (mode === MODE_PASSWORD) {
      need(SALT_LEN, o); const salt = buf.subarray(o, o + SALT_LEN); o += SALT_LEN;
      need(1, o); const timeCost = buf[o]; o += 1;
      need(4, o); const memKiB = readU32be(buf, o); o += 4;
      need(1, o); const parallelism = buf[o]; o += 1;
      need(COMMIT_LEN, o); const commit = buf.subarray(o, o + COMMIT_LEN); o += COMMIT_LEN;
      Object.assign(info, { salt, timeCost, memKiB, parallelism, commit });
    } else if (mode === MODE_VOLUME) {
      need(VOLUME_ID_LEN, o); const volumeId = buf.subarray(o, o + VOLUME_ID_LEN); o += VOLUME_ID_LEN;
      need(SALT_LEN, o); const salt = buf.subarray(o, o + SALT_LEN); o += SALT_LEN;
      need(COMMIT_LEN, o); const commit = buf.subarray(o, o + COMMIT_LEN); o += COMMIT_LEN;
      Object.assign(info, { volumeId, salt, commit });
    } else {
      throw new Error("未知模式：" + mode);
    }
    info.raw = buf.subarray(0, o);
    info.bodyOffset = o;
    return info;
  }

  // 无需密钥的“探头”：只看魔数 / 版本 / 模式（及卷模式下的卷 ID），用于给硬盘上的
  // .pqfc 文件分类（本卷 / 其它卷 / 单文件模式 / 根本不是本工具文件）。不抛错。
  function probeHeader(buf) {
    if (!buf || buf.length < MAGIC.length + 2 || !bytesEqual(buf.subarray(0, MAGIC.length), MAGIC)) return { ok: false };
    const version = buf[MAGIC.length], mode = buf[MAGIC.length + 1];
    const info = { ok: true, version, mode, volumeId: null };
    if (version === VERSION && mode === MODE_VOLUME && buf.length >= VOLUME_HDR_LEN)
      info.volumeId = buf.subarray(MAGIC.length + 2, MAGIC.length + 2 + VOLUME_ID_LEN);
    return info;
  }

  // ---- 密钥对（JSON 对象）-------------------------------------------------
  async function generateKeypair() {
    const x = await x25519GenerateRaw();
    const mk = mlkem.keygen();
    const mkPub = mk.publicKey, mkSecret = mk.secretKey;
    const haveDsa = !!mldsa;
    let dPub = null, dSecret = null;
    if (haveDsa) { const dk = mldsa.keygen(); dPub = dk.publicKey; dSecret = dk.secretKey; }
    const pub = {
      v: haveDsa ? 3 : 2,
      alg: haveDsa ? "X25519+ML-KEM-1024+ML-DSA-87" : "X25519+ML-KEM-1024",
      x25519_pub: b64encode(x.publicKey),
      mlkem_pub: b64encode(mkPub),
      ...(haveDsa ? { mldsa_pub: b64encode(dPub) } : {}),
    };
    const key = {
      ...pub,
      x25519_priv: b64encode(x.privateKey),
      mlkem_secret: b64encode(mkSecret),
      ...(haveDsa ? { mldsa_secret: b64encode(dSecret) } : {}),
    };
    const fp = await fingerprint(x.publicKey, mkPub);
    const sfp = haveDsa ? await signerFingerprint(dPub) : null;
    wipe(x.privateKey);
    if (dSecret) wipe(dSecret);
    return { pub, key, fingerprint: fp, signerFingerprint: sfp };
  }

  // 指纹：SHA-256(域标签 ‖ 公钥) 截断到 16 字节(128-bit)。
  // 伪造同指纹公钥（二次原像）需 ~2^128 算力，实际不可行；域标签防跨用途碰撞。
  async function fingerprint(...parts) {
    const digest = (await sha256(concatBytes(DS_FP, ...parts))).subarray(0, 16);
    return Array.from(digest).map((b) => b.toString(16).padStart(2, "0")).join(":");
  }

  // 签名者指纹：SHA-256(独立域标签 ‖ ML-DSA 公钥) 截断到 16 字节，
  // 与“加密身份指纹”用不同域标签区分；供收件人带外核验发件人身份。
  async function signerFingerprint(mldsaPub) {
    const digest = (await sha256(concatBytes(DS_SIG_FP, mldsaPub))).subarray(0, 16);
    return Array.from(digest).map((b) => b.toString(16).padStart(2, "0")).join(":");
  }

  // ---- 严格输入校验 / 资源上限 --------------------------------------------
  function assertArgonSane(timeCost, memKiB, parallelism) {
    if (!(timeCost >= 1 && timeCost <= ARGON_TIME_CAP))
      throw new Error("Argon2 时间参数超出允许范围");
    if (!(parallelism >= 1 && parallelism <= ARGON_PAR_CAP))
      throw new Error("Argon2 并行度超出允许范围");
    if (!(memKiB >= 8 && memKiB <= ARGON_MEM_CAP_KIB))
      throw new Error("Argon2 内存参数超出允许范围（已拒绝，以防内存耗尽攻击）");
  }

  function validatePub(pub) {
    if (!pub || !pub.x25519_pub || !pub.mlkem_pub)
      throw new Error("这不是有效的 .pub 公钥文件");
    const x = b64decode(pub.x25519_pub), m = b64decode(pub.mlkem_pub);
    if (x.length !== X25519_LEN)
      throw new Error("公钥无效：X25519 公钥长度应为 32 字节");
    if (m.length !== MLKEM1024_PK_LEN)
      throw new Error("公钥无效：ML-KEM-1024 公钥长度应为 " + MLKEM1024_PK_LEN + " 字节");
    let d = null;
    if (pub.mldsa_pub) {
      d = b64decode(pub.mldsa_pub);
      if (d.length !== MLDSA87_PK_LEN)
        throw new Error("公钥无效：ML-DSA-87 公钥长度应为 " + MLDSA87_PK_LEN + " 字节");
    }
    return { x, m, d };
  }

  // 校验私钥对象，返回解码后的 { xPriv, mkSecret, xPub, mkPub }。
  // v2 要求私钥文件同时含公钥（混合组合器需绑定收件人静态公钥）。
  function validateKeyObj(obj) {
    if (!obj || !obj.x25519_priv || !obj.mlkem_secret)
      throw new Error("这不是有效的 .key 私钥文件");
    if (!obj.x25519_pub || !obj.mlkem_pub)
      throw new Error("私钥文件缺少对应公钥字段（v2 私钥需同时包含公钥）");
    const xPriv = b64decode(obj.x25519_priv);
    const mkSecret = b64decode(obj.mlkem_secret);
    const xPub = b64decode(obj.x25519_pub);
    const mkPub = b64decode(obj.mlkem_pub);
    if (xPriv.length !== X25519_LEN) throw new Error("私钥无效：X25519 私钥长度应为 32 字节");
    if (mkSecret.length !== MLKEM1024_SK_LEN) throw new Error("私钥无效：ML-KEM-1024 私钥长度应为 " + MLKEM1024_SK_LEN + " 字节");
    if (xPub.length !== X25519_LEN) throw new Error("私钥无效：内含 X25519 公钥长度异常");
    if (mkPub.length !== MLKEM1024_PK_LEN) throw new Error("私钥无效：内含 ML-KEM 公钥长度异常");
    let dPub = null, dSecret = null;
    if (obj.mldsa_secret || obj.mldsa_pub) {
      if (!obj.mldsa_secret || !obj.mldsa_pub)
        throw new Error("私钥无效：ML-DSA 公钥 / 私钥字段必须成对出现");
      dSecret = b64decode(obj.mldsa_secret);
      dPub = b64decode(obj.mldsa_pub);
      if (dSecret.length !== MLDSA87_SK_LEN) throw new Error("私钥无效：ML-DSA-87 私钥长度应为 " + MLDSA87_SK_LEN + " 字节");
      if (dPub.length !== MLDSA87_PK_LEN) throw new Error("私钥无效：内含 ML-DSA 公钥长度异常");
    }
    return { xPriv, mkSecret, xPub, mkPub, dPub, dSecret };
  }

  // ---- 高层加 / 解密 ------------------------------------------------------
  async function encryptHybrid(recipientPub, data) {
    if (!mlkem) throw new Error("混合模式需要注入 ML-KEM 实现");
    const { x: xPubRaw, m: mkPub } = validatePub(recipientPub);

    const eph = await x25519GenerateRaw();
    const ephPrivObj = await x25519ImportPrivate(eph.privateKey);
    const ssX = await x25519Exchange(ephPrivObj, xPubRaw);
    const enc = mlkem.encapsulate(mkPub);
    const mlkemCt = enc.cipherText, ssK = enc.sharedSecret;

    const salt = randomBytes(SALT_LEN);
    const { encKey, commit } = await hybridDerive({
      ssMlkem: ssK, ssX25519: ssX, mlkemCt, mlkemPk: mkPub,
      ephPk: eph.publicKey, recipPk: xPubRaw, salt,
    });
    const header = buildHeaderHybrid(eph.publicKey, mlkemCt, salt, commit);
    const body = await encryptStream(encKey, header, data);
    wipe(eph.privateKey, ssX, ssK, encKey, commit);
    return concatBytes(header, body);
  }

  async function encryptPassword(password, data, params = {}) {
    const timeCost = params.timeCost ?? ARGON_TIME;
    const memKiB = params.memKiB ?? ARGON_MEM_KIB;
    const parallelism = params.parallelism ?? ARGON_PAR;
    const salt = randomBytes(SALT_LEN);
    const master = await argon2Raw(password, salt, timeCost, memKiB, parallelism);
    const { encKey, commit } = await passwordDerive(master);
    const header = buildHeaderPassword(salt, timeCost, memKiB, parallelism, commit);
    const body = await encryptStream(encKey, header, data);
    wipe(master, encKey, commit);
    return concatBytes(header, body);
  }

  // ---- 发件人认证（可选，Sign-then-Encrypt + 收件人绑定）-------------------
  // · 对“定长小哈希”签名，签名值放进【密文内部】的封套，故对外不泄露发件人身份；
  // · 被签名的消息绑定：域标签 ‖ 收件人 X25519 公钥 ‖ 收件人 ML-KEM 公钥 ‖
  //   发件人 ML-DSA 公钥 ‖ SHA-512(明文)。绑定收件人 → 抵抗“偷偷转发/改投”
  //   （恶意收件人无法把你的签名重投给第三方冒充成发给对方）；绑定明文哈希 →
  //   证明对“这份内容”的作者身份；签名开销与文件大小无关（明文先压成 64 字节）。
  // · 签名是可选项，默认不签名（保留可否认性，并与既有 v2 文件 100% 兼容）。
  // · 与机密性层正交：封套先被既有“承诺 + 流式 GCM”整体认证，ML-DSA 验签是其上
  //   再加的一道发件人身份证明；验签失败一律“失败关闭”（拒绝返回明文）。

  // 头部：与 buildHeaderHybrid 字节一致，仅模式字节为 MODE_HYBRID_SIGNED。
  function buildHeaderHybridSigned(ephPub, mlkemCt, salt, commit) {
    return concatBytes(
      MAGIC, new Uint8Array([VERSION, MODE_HYBRID_SIGNED]),
      ephPub, u16be(mlkemCt.length), mlkemCt, salt, commit,
    );
  }

  // 被签名的消息（定长，与文件大小无关）。用 WebCrypto SHA-512 压缩明文，
  // 不引入新的核心依赖；ML-DSA 内部再哈希一次，等价于“预哈希签名”。
  async function signedMessage({ recipXPub, recipMkPub, senderDsaPub, plaintext }) {
    const ptHash = await sha512(plaintext);
    const m = concatBytes(DS_SIGN, recipXPub, recipMkPub, senderDsaPub, ptHash);
    wipe(ptHash);
    return m;
  }

  // 签名封套（= 待加密明文）：自描述、含算法标识与两段长度，便于校验与未来扩展。
  function buildSignedEnvelope(senderDsaPub, signature, plaintext) {
    return concatBytes(
      new Uint8Array([SIG_ALG_MLDSA87]),
      u16be(senderDsaPub.length), senderDsaPub,
      u16be(signature.length), signature,
      plaintext,
    );
  }

  function parseSignedEnvelope(buf) {
    let o = 0;
    const need = (n) => { if (o + n > buf.length) throw new Error("签名封套不完整（文件可能已损坏）"); };
    need(1); const alg = buf[o]; o += 1;
    if (alg !== SIG_ALG_MLDSA87) throw new Error("未知的签名算法标识：" + alg);
    need(2); const pkLen = readU16be(buf, o); o += 2;
    if (pkLen !== MLDSA87_PK_LEN) throw new Error("签名封套损坏：发件人公钥长度异常");
    need(pkLen); const senderDsaPub = buf.subarray(o, o + pkLen); o += pkLen;
    need(2); const sigLen = readU16be(buf, o); o += 2;
    if (sigLen !== MLDSA87_SIG_LEN) throw new Error("签名封套损坏：签名长度异常");
    need(sigLen); const signature = buf.subarray(o, o + sigLen); o += sigLen;
    if (o > SIG_ENVELOPE_HDR_MAX) throw new Error("签名封套头过大（已拒绝）");
    return { senderDsaPub, signature, plaintext: buf.subarray(o) };
  }

  // 加密并签名（混合公钥模式 + 发件人 ML-DSA 签名）。
  // signerKeyObj 必须是含 ML-DSA 私钥的密钥（即发件人自己的 .key，需用新版生成）。
  async function encryptHybridSigned(recipientPub, data, signerKeyObj) {
    if (!mlkem) throw new Error("混合模式需要注入 ML-KEM 实现");
    if (!mldsa) throw new Error("签名需要注入 ML-DSA 实现");
    const { x: xPubRaw, m: mkPub } = validatePub(recipientPub);
    const sk = validateKeyObj(signerKeyObj);
    if (!sk.dSecret || !sk.dPub)
      throw new Error("用于签名的私钥不含 ML-DSA 签名密钥（请在“密钥”页生成含签名身份的新密钥对）。");

    // 1) 先签名（绑定收件人 + 发件人 + 明文哈希 + 域标签）
    const msg = await signedMessage({ recipXPub: xPubRaw, recipMkPub: mkPub, senderDsaPub: sk.dPub, plaintext: data });
    const signature = mldsa.sign(msg, sk.dSecret);
    wipe(msg);
    // 2) 组装签名封套作为待加密明文
    const envelope = buildSignedEnvelope(sk.dPub, signature, data);

    // 3) 走与 encryptHybrid 完全相同的混合加密流程，仅头部模式字节不同
    const eph = await x25519GenerateRaw();
    const ephPrivObj = await x25519ImportPrivate(eph.privateKey);
    const ssX = await x25519Exchange(ephPrivObj, xPubRaw);
    const enc = mlkem.encapsulate(mkPub);
    const mlkemCt = enc.cipherText, ssK = enc.sharedSecret;
    const salt = randomBytes(SALT_LEN);
    const { encKey, commit } = await hybridDerive({
      ssMlkem: ssK, ssX25519: ssX, mlkemCt, mlkemPk: mkPub,
      ephPk: eph.publicKey, recipPk: xPubRaw, salt,
    });
    const header = buildHeaderHybridSigned(eph.publicKey, mlkemCt, salt, commit);
    const out = await encryptStream(encKey, header, envelope);
    wipe(eph.privateKey, ssX, ssK, encKey, commit, sk.dSecret, sk.xPriv, sk.mkSecret);
    return concatBytes(header, out);
  }

  // 自动识别模式；混合模式需 opts.keyObj，口令模式需 opts.password。
  async function decrypt(fileBytes, opts = {}) {
    const hdr = parseHeader(fileBytes);
    const body = fileBytes.subarray(hdr.bodyOffset);
    let encKey, commit, toWipe = [];
    let recipXPub = null, recipMkPub = null; // 仅签名模式用：以收件人自身公钥重算签名消息

    if (hdr.mode === MODE_PASSWORD) {
      if (opts.password == null) throw new Error("该文件为口令模式，请提供口令。");
      assertArgonSane(hdr.timeCost, hdr.memKiB, hdr.parallelism); // 防恶意头触发内存耗尽
      const master = await argon2Raw(opts.password, hdr.salt, hdr.timeCost, hdr.memKiB, hdr.parallelism);
      ({ encKey, commit } = await passwordDerive(master));
      toWipe = [master, encKey, commit];
    } else if (hdr.mode === MODE_HYBRID || hdr.mode === MODE_HYBRID_SIGNED) {
      if (!opts.keyObj) throw new Error("该文件为混合公钥模式，请提供你的私钥文件 (.key)。");
      if (!mlkem) throw new Error("混合模式需要注入 ML-KEM 实现");
      const { xPriv, mkSecret, xPub, mkPub } = validateKeyObj(opts.keyObj);
      recipXPub = xPub; recipMkPub = mkPub;
      const xPrivObj = await x25519ImportPrivate(xPriv);
      const ssX = await x25519Exchange(xPrivObj, hdr.ephPub);
      const ssK = mlkem.decapsulate(hdr.mlkemCt, mkSecret);
      ({ encKey, commit } = await hybridDerive({
        ssMlkem: ssK, ssX25519: ssX, mlkemCt: hdr.mlkemCt, mlkemPk: mkPub,
        ephPk: hdr.ephPub, recipPk: xPub, salt: hdr.salt,
      }));
      toWipe = [xPriv, mkSecret, ssX, ssK, encKey, commit];
    } else {
      throw new Error("未知模式：" + hdr.mode);
    }

    // 关键：先以常数时间核对密钥承诺值，再解密。
    // 这既提供“密钥承诺”安全属性（一段密文只可能被唯一密钥合法解开），
    // 又让“口令/密钥错误”快速、明确地失败。
    if (!bytesEqual(commit, hdr.commit)) {
      wipe(...toWipe);
      throw hdr.mode === MODE_PASSWORD
        ? mkErr("口令错误，或文件已损坏 / 被篡改。", "BAD_PASSWORD")
        : mkErr("私钥与此文件不匹配，或文件已损坏 / 被篡改。", "KEY_MISMATCH");
    }

    let decrypted;
    try {
      decrypted = await decryptStream(encKey, hdr.raw, body);
    } finally {
      wipe(...toWipe);
    }

    // 签名模式：密文已通过“承诺 + 流式 GCM”整体认证；此处对封套内的 ML-DSA
    // 签名再做发件人验证。验签用【收件人自身】公钥重算签名消息 → 即便恶意收件人
    // 把别人的签名封套重投给你，因绑定的收件人不是你，验签也会失败（防偷偷转发）。
    // 任何失败一律“失败关闭”：抛错，绝不把明文当作“未签名”静默返回。
    if (hdr.mode === MODE_HYBRID_SIGNED) {
      if (!mldsa) throw new Error("此文件含发件人签名，但未注入 ML-DSA 验证实现。");
      const env = parseSignedEnvelope(decrypted);
      const msg = await signedMessage({
        recipXPub, recipMkPub, senderDsaPub: env.senderDsaPub, plaintext: env.plaintext,
      });
      const ok = mldsa.verify(env.signature, msg, env.senderDsaPub);
      wipe(msg);
      if (!ok) throw new Error("发件人签名验证失败：文件可能被篡改，或并非声称的发件人 / 收件人。");
      const sfp = await signerFingerprint(env.senderDsaPub);
      return {
        plaintext: env.plaintext, mode: hdr.mode,
        signed: true, signerFingerprint: sfp,
        signerPublicKey: b64encode(env.senderDsaPub),
      };
    }
    return { plaintext: decrypted, mode: hdr.mode, signed: false };
  }

  // ---- 私钥静态加密：.key 文件落盘前用口令加密（容器 v2）------------------
  // 直接缓解“.key 被偷 = 全军覆没”。容器为本工具自定义 JSON，含密钥承诺值；
  // 解封时先核对承诺值（钉死 口令/参数/salt），再做 GCM（钉死 nonce/密文）。
  const KEYWRAP_ALG = "pqfilecrypt-key-v2";
  const KEYWRAP_AAD = _TE.encode(KEYWRAP_ALG);

  function isWrappedKey(obj) {
    return !!obj && obj.alg === KEYWRAP_ALG && typeof obj.ciphertext === "string";
  }

  async function wrapSecretKey(keyObj, passphrase, params = {}) {
    if (!argon2id) throw new Error("加密私钥需要注入 argon2id 实现");
    if (!passphrase) throw new Error("用于保护私钥的口令不能为空");
    validateKeyObj(keyObj); // 确保是完整 v2 私钥（含公钥）
    const timeCost = params.timeCost ?? ARGON_TIME;
    const memKiB = params.memKiB ?? ARGON_MEM_KIB;
    const parallelism = params.parallelism ?? ARGON_PAR;
    const salt = randomBytes(SALT_LEN);
    const master = await argon2Raw(passphrase, salt, timeCost, memKiB, parallelism);
    const { encKey, commit } = await keywrapDerive(master);
    const aesKey = await importAesKey(encKey);
    const iv = randomBytes(NONCE_LEN);
    const pt = _TE.encode(JSON.stringify(keyObj));
    const ct = new Uint8Array(await subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: KEYWRAP_AAD, tagLength: 128 }, aesKey, pt,
    ));
    wipe(master, encKey, pt);
    return {
      alg: KEYWRAP_ALG,
      note: "口令保护的 pqfilecrypt 私钥（格式 v2）；在本工具“解密”页载入即可（需口令）。",
      kdf: "argon2id",
      kdf_params: { t: timeCost, m: memKiB, p: parallelism, salt: b64encode(salt) },
      commit: b64encode(commit),
      cipher: "AES-256-GCM",
      nonce: b64encode(iv),
      ciphertext: b64encode(ct),
    };
  }

  async function unwrapSecretKey(container, passphrase) {
    if (!argon2id) throw new Error("解锁私钥需要注入 argon2id 实现");
    if (!isWrappedKey(container)) throw new Error("这不是受口令保护的 v2 私钥文件");
    if (!passphrase) throw new Error("请输入解锁私钥的口令");
    const p = container.kdf_params || {};
    const salt = b64decode(p.salt || "");
    if (salt.length !== SALT_LEN) throw new Error("私钥容器损坏：salt 长度异常");
    const timeCost = p.t | 0, memKiB = p.m >>> 0, parallelism = p.p | 0;
    assertArgonSane(timeCost, memKiB, parallelism); // 防御恶意容器的资源耗尽
    const storedCommit = b64decode(container.commit || "");
    if (storedCommit.length !== COMMIT_LEN) throw new Error("私钥容器损坏：承诺值长度异常");

    const master = await argon2Raw(passphrase, salt, timeCost, memKiB, parallelism);
    const { encKey, commit } = await keywrapDerive(master);
    if (!bytesEqual(commit, storedCommit)) {
      wipe(master, encKey);
      throw mkErr("口令错误，或私钥文件已损坏 / 被篡改。", "BAD_PASSWORD");
    }
    const aesKey = await importAesKey(encKey);
    const iv = b64decode(container.nonce || "");
    if (iv.length !== NONCE_LEN) { wipe(master, encKey); throw new Error("私钥容器损坏：nonce 长度异常"); }
    let pt;
    try {
      pt = new Uint8Array(await subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: KEYWRAP_AAD, tagLength: 128 },
        aesKey, b64decode(container.ciphertext),
      ));
    } catch (e) {
      wipe(master, encKey);
      throw mkErr("口令错误，或私钥文件已损坏 / 被篡改。", "BAD_PASSWORD");
    }
    wipe(master, encKey);
    let obj;
    try { obj = JSON.parse(new TextDecoder().decode(pt)); }
    catch (e) { throw new Error("私钥容器解密后内容不是有效 JSON"); }
    finally { wipe(pt); }
    validateKeyObj(obj); // 解封后的对象必须是完整 v2 私钥
    return obj;
  }

  // ==========================================================================
  //  第四轮：真正的流式 AEAD（大文件不整体读入内存）
  //  线格式与 encryptStream / decryptStream 逐字节相同（u32 长度 ‖ 密文块，
  //  nonce = 计数器 ‖ 末块标记，头作 AAD），两者可互相解开；仅 I/O 方式不同。
  // ==========================================================================

  // 把任意分片的 ReadableStream 重切成恰好 CHUNK_SIZE 的块，并给出“是否末块”。
  // 末块判定需要“看一眼后面还有没有数据”，故始终扣留一块待定：
  //   · 流结束且余料为空 → 待定块即末块（文件长度恰为块长的整数倍）；
  //   · 流结束且余料非空 → 待定块非末块，余料为末块；
  //   · 空文件 → 一个空的末块（与 encryptStream 的“空文件也产生一个空块”一致）。
  async function* rechunk(readable, size) {
    const reader = readable.getReader();
    const pieces = []; let total = 0; let pending = null;
    const take = (n) => {
      const out = new Uint8Array(n); let o = 0;
      while (o < n) {
        const p = pieces[0]; const k = Math.min(n - o, p.length);
        out.set(p.subarray(0, k), o); o += k;
        if (k === p.length) pieces.shift(); else pieces[0] = p.subarray(k);
      }
      total -= n;
      return out;
    };
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!value || !value.length) continue;
        pieces.push(value instanceof Uint8Array ? value : new Uint8Array(value)); total += value.length;
        while (total >= size) {
          const chunk = take(size);
          if (pending) yield { chunk: pending, last: false };
          pending = chunk;
        }
      }
      if (total > 0) {
        if (pending) yield { chunk: pending, last: false };
        yield { chunk: take(total), last: true };
      } else {
        yield { chunk: pending || new Uint8Array(0), last: true };
      }
    } finally {
      try { reader.releaseLock(); } catch (_e) { /* 已释放 */ }
    }
  }

  // 按需拉取的字节读取器：readExact(n) 恰好读 n 字节；干净的 EOF 返回 null，
  // 残缺（还剩 1..n-1 字节）则抛“意外结束”。atEOF() 用于末块判定。
  class ByteReader {
    constructor(readable) { this.r = readable.getReader(); this.pieces = []; this.avail = 0; this.done = false; }
    async fill(n) {
      while (this.avail < n && !this.done) {
        const { value, done } = await this.r.read();
        if (done) { this.done = true; break; }
        if (value && value.length) { this.pieces.push(value instanceof Uint8Array ? value : new Uint8Array(value)); this.avail += value.length; }
      }
      return this.avail >= n;
    }
    async readExact(n) {
      if (!(await this.fill(n))) {
        if (this.avail === 0) return null;
        throw new Error("文件意外结束（可能已损坏或被截断）");
      }
      const out = new Uint8Array(n); let o = 0;
      while (o < n) {
        const p = this.pieces[0]; const k = Math.min(n - o, p.length);
        out.set(p.subarray(0, k), o); o += k;
        if (k === p.length) this.pieces.shift(); else this.pieces[0] = p.subarray(k);
      }
      this.avail -= n;
      return out;
    }
    async atEOF() { return !(await this.fill(1)); }
    async cancel() { try { await this.r.cancel(); } catch (_e) { /* 忽略 */ } }
  }

  function checkAbort(opts) {
    if (opts && opts.signal && opts.signal.aborted) throw mkErr("已取消", "ABORTED");
  }

  // 流式加密：只写正文（调用方先写头），sink.write(Uint8Array) 须返回 Promise。
  async function encryptStreamTo(rawKey, header, readable, sink, opts = {}) {
    const aesKey = await importAesKey(rawKey);
    let i = 0, bytesIn = 0, bytesOut = 0;
    for await (const { chunk, last } of rechunk(readable, CHUNK_SIZE)) {
      checkAbort(opts);
      const blob = new Uint8Array(await subtle.encrypt(
        { name: "AES-GCM", iv: nonce(i, last), additionalData: header, tagLength: 128 },
        aesKey, chunk,
      ));
      await sink.write(u32be(blob.length));
      await sink.write(blob);
      i++; bytesIn += chunk.length; bytesOut += 4 + blob.length;
      if (opts.onProgress) opts.onProgress(chunk.length);
    }
    return { blocks: i, bytesIn, bytesOut };
  }

  // 流式解密：sink 为 null 时只校验不输出（用于“写入后校验”）。
  async function decryptStreamTo(rawKey, header, reader, sink, opts = {}) {
    const aesKey = await importAesKey(rawKey);
    let i = 0, bytesOut = 0;
    for (;;) {
      checkAbort(opts);
      const lenB = await reader.readExact(4);
      if (lenB === null) { if (i === 0) throw new Error("密文为空或已损坏"); break; }
      const clen = readU32be(lenB, 0);
      if (clen < TAG_LEN || clen > MAX_BLOCK)
        throw new Error("密文块长度异常（文件可能已损坏或被篡改）");
      const block = await reader.readExact(clen);
      if (block === null) throw new Error("文件意外结束（可能已损坏或被截断）");
      const isLast = await reader.atEOF();
      let pt;
      try {
        pt = new Uint8Array(await subtle.decrypt(
          { name: "AES-GCM", iv: nonce(i, isLast), additionalData: header, tagLength: 128 },
          aesKey, block,
        ));
      } catch (e) {
        throw new Error("认证失败：文件被篡改 / 被截断，或密钥 / 口令不正确。");
      }
      if (sink) await sink.write(pt);
      i++; bytesOut += pt.length;
      if (opts.onProgress) opts.onProgress(pt.length);
    }
    return { blocks: i, bytesOut };
  }

  // ==========================================================================
  //  第四轮：卷模式（硬盘加密）—— 卷主密钥 VMK、密钥槽、逐文件密钥
  // ==========================================================================

  // 逐文件密钥派生：SHA-512(标签 ‖ VMK ‖ 卷 ID ‖ 文件 salt) → {文件密钥, 承诺值}。
  // 随机预言机下各文件密钥相互独立；承诺值让“VMK 不对 / 文件属于别的卷”快速明确失败。
  async function volumeFileDerive(vmk, volumeId, fileSalt) {
    if (!(vmk instanceof Uint8Array) || vmk.length !== VMK_LEN) throw new Error("卷主密钥长度异常");
    const h = await sha512(concatBytes(DS_VOL_FILE, vmk, volumeId, fileSalt));
    return splitKeyCommit(h);
  }

  function newVolume({ hideNames = false, label = "" } = {}) {
    const vmk = randomBytes(VMK_LEN);
    const volumeId = randomBytes(VOLUME_ID_LEN);
    const header = {
      format: VOLUME_FORMAT,
      volume_id: b64encode(volumeId),
      created: new Date().toISOString(),
      label: String(label || "").slice(0, 200),
      hide_names: !!hideNames,
      slots: [],
    };
    return { vmk, volumeId, header };
  }

  function slotAad(volumeId, type) {
    return concatBytes(DS_VOL_WRAP, volumeId, new Uint8Array([type === SLOT_PASSWORD ? 1 : 2]));
  }

  async function wrapVmk(encKey, aad, vmk) {
    const aesKey = await importAesKey(encKey);
    const iv = randomBytes(NONCE_LEN);
    const ct = new Uint8Array(await subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, aesKey, vmk,
    ));
    return { nonce: iv, ct };
  }

  async function unwrapVmk(encKey, aad, iv, ct) {
    const aesKey = await importAesKey(encKey);
    let pt;
    try {
      pt = new Uint8Array(await subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, aesKey, ct,
      ));
    } catch (_e) {
      throw new Error("密钥槽解封失败：卷头已损坏 / 被篡改");
    }
    if (pt.length !== VMK_LEN) { wipe(pt); throw new Error("密钥槽解封结果长度异常"); }
    return pt;
  }

  // 严格校验卷头（.pqvolume）。返回 { volumeId }。未知槽类型直接拒绝（不猜）。
  function validateVolumeHeader(h) {
    if (!h || typeof h !== "object" || h.format !== VOLUME_FORMAT)
      throw new Error("这不是有效的 pqdisk 卷头（.pqvolume）");
    const volumeId = b64decode(h.volume_id || "");
    if (volumeId.length !== VOLUME_ID_LEN) throw new Error("卷头损坏：卷 ID 长度异常");
    if (typeof h.hide_names !== "boolean") throw new Error("卷头损坏：缺少 hide_names 标志");
    if (!Array.isArray(h.slots) || h.slots.length === 0) throw new Error("卷头不含任何密钥槽，无法解锁");
    const lenIs = (s, n, what) => { const b = b64decode(s || ""); if (b.length !== n) throw new Error("卷头损坏：" + what + "长度异常"); return b; };
    h.slots.forEach((s, i) => {
      const at = "密钥槽 #" + (i + 1) + " ";
      if (!s || typeof s !== "object") throw new Error("卷头损坏：" + at + "格式异常");
      lenIs(s.commit, COMMIT_LEN, at + "承诺值");
      lenIs(s.nonce, NONCE_LEN, at + "nonce");
      lenIs(s.wrapped_key, VMK_LEN + TAG_LEN, at + "包裹密钥");
      if (s.type === SLOT_PASSWORD) {
        const p = s.kdf_params || {};
        if (s.kdf !== "argon2id") throw new Error("卷头损坏：" + at + "KDF 未知");
        lenIs(p.salt, SALT_LEN, at + "salt");
        assertArgonSane(p.t | 0, p.m >>> 0, p.p | 0);
      } else if (s.type === SLOT_PUBKEY) {
        lenIs(s.eph_x25519_pub, X25519_LEN, at + "临时公钥");
        lenIs(s.mlkem_ct, MLKEM1024_CT_LEN, at + "ML-KEM 密文");
        lenIs(s.salt, SALT_LEN, at + "salt");
      } else {
        throw new Error("卷头含不支持的密钥槽类型“" + String(s.type) + "”（可能由更新版本创建）");
      }
    });
    return { volumeId };
  }

  async function addPasswordSlot(header, vmk, password, params = {}) {
    if (!argon2id) throw new Error("口令槽需要注入 argon2id 实现");
    if (!password) throw new Error("口令不能为空");
    const volumeId = b64decode(header.volume_id || "");
    if (volumeId.length !== VOLUME_ID_LEN) throw new Error("卷头损坏：卷 ID 长度异常");
    const timeCost = params.timeCost ?? ARGON_TIME;
    const memKiB = params.memKiB ?? ARGON_MEM_KIB;
    const parallelism = params.parallelism ?? ARGON_PAR;
    const salt = randomBytes(SALT_LEN);
    const master = await argon2Raw(password, salt, timeCost, memKiB, parallelism);
    const h = await sha512(concatBytes(DS_VOL_PW, master));
    const { encKey, commit } = splitKeyCommit(h);
    const { nonce: iv, ct } = await wrapVmk(encKey, slotAad(volumeId, SLOT_PASSWORD), vmk);
    const slot = {
      type: SLOT_PASSWORD, kdf: "argon2id",
      kdf_params: { t: timeCost, m: memKiB, p: parallelism, salt: b64encode(salt) },
      commit: b64encode(commit), nonce: b64encode(iv), wrapped_key: b64encode(ct),
      created: new Date().toISOString(),
    };
    wipe(master, h);
    if (!Array.isArray(header.slots)) header.slots = [];
    header.slots.push(slot);
    return slot;
  }

  async function addPubkeySlot(header, vmk, recipientPub) {
    if (!mlkem) throw new Error("公钥槽需要注入 ML-KEM 实现");
    const volumeId = b64decode(header.volume_id || "");
    if (volumeId.length !== VOLUME_ID_LEN) throw new Error("卷头损坏：卷 ID 长度异常");
    const { x: xPubRaw, m: mkPub } = validatePub(recipientPub);
    const eph = await x25519GenerateRaw();
    const ephPrivObj = await x25519ImportPrivate(eph.privateKey);
    const ssX = await x25519Exchange(ephPrivObj, xPubRaw);
    const enc = mlkem.encapsulate(mkPub);
    const salt = randomBytes(SALT_LEN);
    const { encKey, commit } = await hybridDerive({
      ssMlkem: enc.sharedSecret, ssX25519: ssX, mlkemCt: enc.cipherText, mlkemPk: mkPub,
      ephPk: eph.publicKey, recipPk: xPubRaw, salt, label: DS_VOL_HYBRID,
    });
    const { nonce: iv, ct } = await wrapVmk(encKey, slotAad(volumeId, SLOT_PUBKEY), vmk);
    const slot = {
      type: SLOT_PUBKEY, alg: "X25519+ML-KEM-1024",
      fingerprint: await fingerprint(xPubRaw, mkPub),
      eph_x25519_pub: b64encode(eph.publicKey), mlkem_ct: b64encode(enc.cipherText), salt: b64encode(salt),
      commit: b64encode(commit), nonce: b64encode(iv), wrapped_key: b64encode(ct),
      created: new Date().toISOString(),
    };
    wipe(eph.privateKey, ssX, enc.sharedSecret, encKey, commit);
    if (!Array.isArray(header.slots)) header.slots = [];
    header.slots.push(slot);
    return slot;
  }

  function removeSlot(header, index) {
    validateVolumeHeader(header);
    if (!(index >= 0 && index < header.slots.length)) throw new Error("密钥槽序号无效");
    if (header.slots.length <= 1) throw new Error("不能删除最后一个密钥槽：那会让整个卷永久无法解锁");
    return header.slots.splice(index, 1)[0];
  }

  // 解锁卷：用口令（尝试全部口令槽）或私钥（尝试全部公钥槽）解出 VMK。
  // 返回 { vmk, slotIndex }。每个槽先常数时间核对承诺值，再做 GCM 解封。
  async function unlockVolume(header, opts = {}) {
    const { volumeId } = validateVolumeHeader(header);
    if (opts.password != null) {
      if (!argon2id) throw new Error("口令槽需要注入 argon2id 实现");
      let tried = 0;
      for (let i = 0; i < header.slots.length; i++) {
        const s = header.slots[i];
        if (s.type !== SLOT_PASSWORD) continue;
        tried++;
        const p = s.kdf_params;
        const master = await argon2Raw(opts.password, b64decode(p.salt), p.t | 0, p.m >>> 0, p.p | 0);
        const h = await sha512(concatBytes(DS_VOL_PW, master));
        const { encKey, commit } = splitKeyCommit(h);
        const match = bytesEqual(commit, b64decode(s.commit));
        if (!match) { wipe(master, h); continue; }
        try {
          const vmk = await unwrapVmk(encKey, slotAad(volumeId, SLOT_PASSWORD), b64decode(s.nonce), b64decode(s.wrapped_key));
          return { vmk, slotIndex: i, volumeId };
        } finally { wipe(master, h); }
      }
      if (tried === 0) throw mkErr("此卷没有口令密钥槽，请改用私钥解锁。", "NO_SLOT");
      throw mkErr("口令错误，或卷头已损坏 / 被篡改。", "BAD_PASSWORD");
    }
    if (opts.keyObj) {
      if (!mlkem) throw new Error("公钥槽需要注入 ML-KEM 实现");
      const { xPriv, mkSecret, xPub, mkPub } = validateKeyObj(opts.keyObj);
      try {
        let tried = 0;
        const xPrivObj = await x25519ImportPrivate(xPriv);
        for (let i = 0; i < header.slots.length; i++) {
          const s = header.slots[i];
          if (s.type !== SLOT_PUBKEY) continue;
          tried++;
          const ephPub = b64decode(s.eph_x25519_pub), mlkemCt = b64decode(s.mlkem_ct);
          let ssX, ssK;
          try {
            ssX = await x25519Exchange(xPrivObj, ephPub);
            ssK = mlkem.decapsulate(mlkemCt, mkSecret);
          } catch (_e) { continue; }
          const { encKey, commit } = await hybridDerive({
            ssMlkem: ssK, ssX25519: ssX, mlkemCt, mlkemPk: mkPub,
            ephPk: ephPub, recipPk: xPub, salt: b64decode(s.salt), label: DS_VOL_HYBRID,
          });
          const match = bytesEqual(commit, b64decode(s.commit));
          if (!match) { wipe(ssX, ssK, encKey, commit); continue; }
          try {
            const vmk = await unwrapVmk(encKey, slotAad(volumeId, SLOT_PUBKEY), b64decode(s.nonce), b64decode(s.wrapped_key));
            return { vmk, slotIndex: i, volumeId };
          } finally { wipe(ssX, ssK, encKey, commit); }
        }
        if (tried === 0) throw mkErr("此卷没有公钥密钥槽，请改用口令解锁。", "NO_SLOT");
        throw mkErr("此私钥与卷的任何公钥槽都不匹配，或卷头已损坏 / 被篡改。", "KEY_MISMATCH");
      } finally { wipe(xPriv, mkSecret); }
    }
    throw new Error("解锁卷需要提供口令或私钥");
  }

  // ---- 卷内文件：流式 / 整块 ------------------------------------------------
  // 流式加密一个文件：写头 + 正文到 sink。返回 { blocks, bytesIn, bytesOut(含头) }。
  async function encryptVolumeStream(vmk, volumeId, readable, sink, opts = {}) {
    const fileSalt = randomBytes(SALT_LEN);
    const { encKey, commit } = await volumeFileDerive(vmk, volumeId, fileSalt);
    const header = buildHeaderVolume(volumeId, fileSalt, commit);
    try {
      await sink.write(header);
      const r = await encryptStreamTo(encKey, header, readable, sink, opts);
      return { ...r, bytesOut: r.bytesOut + header.length };
    } finally { wipe(encKey, commit); }
  }

  // 从流里读出卷文件头并核对：返回 { hdr, encKey }。分两步读：先 10 字节判类型，
  // 让“不是卷文件 / 属于别的卷”这类错误在读取任何正文之前就明确报出。
  async function openVolumeStream(vmk, volumeId, reader) {
    const head = await reader.readExact(MAGIC.length + 2);
    if (head === null) throw new Error("文件为空，不是有效的加密文件");
    const p = probeHeader(head);
    if (!p.ok) throw mkErr("不是本工具的加密文件（魔数不匹配）", "NOT_PQFC");
    if (p.version !== VERSION || p.mode !== MODE_VOLUME) throw mkErr("这不是卷模式文件（可能是单文件模式或其它版本）", "NOT_VOLUME_FILE");
    const rest = await reader.readExact(VOLUME_HDR_LEN - head.length);
    if (rest === null) throw new Error("文件头不完整");
    const hdr = parseHeader(concatBytes(head, rest));
    if (!bytesEqual(hdr.volumeId, volumeId)) throw mkErr("此文件属于另一个加密卷", "FOREIGN_VOLUME");
    const { encKey, commit } = await volumeFileDerive(vmk, volumeId, hdr.salt);
    if (!bytesEqual(commit, hdr.commit)) {
      wipe(encKey, commit);
      throw mkErr("卷主密钥与此文件不匹配：文件已损坏 / 被篡改。", "KEY_MISMATCH");
    }
    wipe(commit);
    return { hdr, encKey };
  }

  // 流式解密（sink=null 仅校验）。返回 { blocks, bytesOut }。
  async function decryptVolumeStream(vmk, volumeId, reader, sink, opts = {}) {
    const { hdr, encKey } = await openVolumeStream(vmk, volumeId, reader);
    try { return await decryptStreamTo(encKey, hdr.raw, reader, sink, opts); }
    finally { wipe(encKey); }
  }

  // 整块接口（目录清单等小数据），线格式与流式接口相同。
  async function encryptVolumeBytes(vmk, volumeId, data) {
    const fileSalt = randomBytes(SALT_LEN);
    const { encKey, commit } = await volumeFileDerive(vmk, volumeId, fileSalt);
    const header = buildHeaderVolume(volumeId, fileSalt, commit);
    try { return concatBytes(header, await encryptStream(encKey, header, data)); }
    finally { wipe(encKey, commit); }
  }

  async function decryptVolumeBytes(vmk, volumeId, bytes) {
    const p = probeHeader(bytes);
    if (!p.ok) throw mkErr("不是本工具的加密文件（魔数不匹配）", "NOT_PQFC");
    if (p.version !== VERSION || p.mode !== MODE_VOLUME) throw mkErr("这不是卷模式文件", "NOT_VOLUME_FILE");
    const hdr = parseHeader(bytes);
    if (!bytesEqual(hdr.volumeId, volumeId)) throw mkErr("此文件属于另一个加密卷", "FOREIGN_VOLUME");
    const { encKey, commit } = await volumeFileDerive(vmk, volumeId, hdr.salt);
    if (!bytesEqual(commit, hdr.commit)) { wipe(encKey, commit); throw mkErr("卷主密钥与此文件不匹配：文件已损坏 / 被篡改。", "KEY_MISMATCH"); }
    try { return await decryptStream(encKey, hdr.raw, bytes.subarray(hdr.bodyOffset)); }
    finally { wipe(encKey, commit); }
  }

  // 明文长度 → 卷文件的确切密文长度（供扫描时估算占用）。
  function volumeCiphertextLength(n) {
    const blocks = Math.max(1, Math.ceil(n / CHUNK_SIZE));
    return VOLUME_HDR_LEN + n + blocks * (4 + TAG_LEN);
  }

  // ---- 启动自检（known-answer / 往返 / 篡改拒绝）---------------------------
  // 在真正用注入的算法库加密用户数据之前，先用一段极小载荷把整条流水线跑通：
  //   · RNG 不是常量 / 全零；
  //   · ML-KEM 参数集正确（长度符合 FIPS 203 ML-KEM-1024）且 KEM 往返自洽；
  //   · 混合模式 / 口令模式 / 私钥容器三条路径都能加解密往返；
  //   · 篡改密文 / 错误口令会被正确拒绝（承诺 + GCM 生效）。
  // 任何一步失败都抛错——调用方据此【禁用】加解密，避免用一个被损坏 / 被替换的
  // 算法库产出“看似成功、实则不安全或无法解开”的文件。
  // 局限：自检只能发现“行为不正确”（损坏 / 错配参数集 / 构建出错），无法发现
  //       “行为正确但暗中泄密”的恶意库——后者由严格 CSP（connect-src 'none'
  //       等，全程禁止任何外联）兜底。
  // 性能：口令 / 容器自检使用调用方传入的【极小】Argon2 参数（仅验证流水线，
  //       不代表实际加密强度），故每次启动开销极低、不会占用 256 MiB。
  async function selfTest(opts = {}) {
    const ap = opts.argon2Params || { timeCost: 1, memKiB: 8, parallelism: 1 };
    const T = _TE.encode("pqfilecrypt self-test ✔ 自检");

    // 1) RNG 抽样
    const r1 = randomBytes(32), r2 = randomBytes(32);
    if (bytesEqual(r1, r2)) throw new Error("RNG 两次输出相同");
    if (r1.every((b) => b === 0)) throw new Error("RNG 输出全零");

    // 2) ML-KEM 参数集 + KEM 往返
    if (mlkem) {
      const kk = mlkem.keygen();
      if (kk.publicKey.length !== MLKEM1024_PK_LEN || kk.secretKey.length !== MLKEM1024_SK_LEN)
        throw new Error("ML-KEM 公/私钥长度不符（疑似注入了错误参数集，非 ML-KEM-1024）");
      const en = mlkem.encapsulate(kk.publicKey);
      if (en.cipherText.length !== MLKEM1024_CT_LEN || en.sharedSecret.length !== KEY_LEN)
        throw new Error("ML-KEM 密文/共享密钥长度异常");
      const ss2 = mlkem.decapsulate(en.cipherText, kk.secretKey);
      if (!bytesEqual(en.sharedSecret, ss2)) throw new Error("ML-KEM 封装/解封共享密钥不一致");

      // 3) 混合模式往返 + 篡改拒绝
      const kp = await generateKeypair();
      const ct = await encryptHybrid(kp.pub, T);
      if (!bytesEqual((await decrypt(ct, { keyObj: kp.key })).plaintext, T))
        throw new Error("混合模式往返结果不匹配");
      const bad = ct.slice(); bad[bad.length - 1] ^= 0xff;
      let rejected = false;
      try { await decrypt(bad, { keyObj: kp.key }); } catch (_e) { rejected = true; }
      if (!rejected) throw new Error("混合模式未能拒绝被篡改的密文");

      // 私钥容器往返（极小 Argon2 参数）
      if (argon2id) {
        const cont = await wrapSecretKey(kp.key, "self-test", ap);
        const un = await unwrapSecretKey(cont, "self-test");
        if (un.x25519_priv !== kp.key.x25519_priv || un.mlkem_secret !== kp.key.mlkem_secret)
          throw new Error("私钥容器封装/解封不一致");
      }
    }

    // 3.5) 发件人签名（ML-DSA-87）：参数集长度 + 签名往返 + 篡改拒绝 +
    //      端到端“签名加密 → 解密验签”往返 + 篡改密文拒绝。需 mlkem + mldsa。
    if (mldsa && mlkem) {
      const L = mldsa.lengths || {};
      if (L.publicKey !== MLDSA87_PK_LEN || L.secretKey !== MLDSA87_SK_LEN || L.signature !== MLDSA87_SIG_LEN)
        throw new Error("ML-DSA 参数集长度不符（疑似注入了错误参数集，非 ML-DSA-87）");
      const dk = mldsa.keygen();
      if (dk.publicKey.length !== MLDSA87_PK_LEN || dk.secretKey.length !== MLDSA87_SK_LEN)
        throw new Error("ML-DSA 公/私钥长度异常");
      const dm = _TE.encode("pqfilecrypt sign self-test ✔");
      const ds = mldsa.sign(dm, dk.secretKey);
      if (ds.length !== MLDSA87_SIG_LEN) throw new Error("ML-DSA 签名长度异常");
      if (!mldsa.verify(ds, dm, dk.publicKey)) throw new Error("ML-DSA 签名往返验证失败");
      const dsBad = ds.slice(); dsBad[0] ^= 0xff;
      if (mldsa.verify(dsBad, dm, dk.publicKey)) throw new Error("ML-DSA 未能拒绝被篡改的签名");

      // 端到端：发件人=收件人=同一新密钥对（含签名身份）
      const kpS = await generateKeypair();
      if (!kpS.key.mldsa_secret) throw new Error("自检：生成的密钥缺少 ML-DSA 签名身份");
      const sct = await encryptHybridSigned(kpS.pub, T, kpS.key);
      const sres = await decrypt(sct, { keyObj: kpS.key });
      if (!sres.signed || !bytesEqual(sres.plaintext, T))
        throw new Error("签名模式端到端往返 / 验签失败");
      if (sres.signerPublicKey !== kpS.key.mldsa_pub)
        throw new Error("验签返回的发件人公钥与预期不一致");
      const sbad = sct.slice(); sbad[sbad.length - 1] ^= 0xff;
      let srej = false;
      try { await decrypt(sbad, { keyObj: kpS.key }); } catch (_e) { srej = true; }
      if (!srej) throw new Error("签名模式未能拒绝被篡改的密文");
    }

    // 4) 口令模式往返 + 错误口令拒绝（极小 Argon2 参数）
    if (argon2id) {
      const ctp = await encryptPassword("self-test-pw", T, ap);
      if (!bytesEqual((await decrypt(ctp, { password: "self-test-pw" })).plaintext, T))
        throw new Error("口令模式往返结果不匹配");
      let rej = false;
      try { await decrypt(ctp, { password: "wrong-pw" }); } catch (_e) { rej = true; }
      if (!rej) throw new Error("口令模式未能拒绝错误口令");
    }

    // 5) 卷模式（硬盘加密）：密钥槽往返 + 错误口令 / 错误私钥拒绝 +
    //    流式 ↔ 整块互通 + 篡改 / 截断拒绝 + 卷 ID 归属校验（极小 Argon2 参数）。
    if (argon2id && mlkem && typeof ReadableStream === "function") {
      const vol = newVolume({ hideNames: true, label: "self-test" });
      await addPasswordSlot(vol.header, vol.vmk, "vol-pw", ap);
      const owner = await generateKeypair();
      await addPubkeySlot(vol.header, vol.vmk, owner.pub);
      validateVolumeHeader(vol.header);
      const u1 = await unlockVolume(vol.header, { password: "vol-pw" });
      if (!bytesEqual(u1.vmk, vol.vmk) || u1.slotIndex !== 0) throw new Error("卷口令槽解锁结果不一致");
      const u2 = await unlockVolume(vol.header, { keyObj: owner.key });
      if (!bytesEqual(u2.vmk, vol.vmk) || u2.slotIndex !== 1) throw new Error("卷公钥槽解锁结果不一致");
      let vrej = false;
      try { await unlockVolume(vol.header, { password: "wrong" }); } catch (_e) { vrej = true; }
      if (!vrej) throw new Error("卷模式未能拒绝错误口令");
      vrej = false;
      try { await unlockVolume(vol.header, { keyObj: (await generateKeypair()).key }); } catch (_e) { vrej = true; }
      if (!vrej) throw new Error("卷模式未能拒绝不匹配的私钥");

      // 流式加密 → 整块解密；整块加密 → 流式解密（线格式一致）
      const big = new Uint8Array(CHUNK_SIZE + 7); for (let i = 0; i < big.length; i++) big[i] = (i * 31) & 0xff;
      const outParts = [];
      const sink = { write: async (b) => { outParts.push(b); } };
      const stream = new ReadableStream({ start(c) { c.enqueue(big.subarray(0, 1000)); c.enqueue(big.subarray(1000)); c.close(); } });
      await encryptVolumeStream(vol.vmk, vol.volumeId, stream, sink);
      const ctv = concatBytes(...outParts);
      if (!bytesEqual(await decryptVolumeBytes(vol.vmk, vol.volumeId, ctv), big)) throw new Error("卷模式 流式加密→整块解密 不一致");
      const ctb = await encryptVolumeBytes(vol.vmk, vol.volumeId, big);
      const got = [];
      const rd = new ByteReader(new ReadableStream({ start(c) { c.enqueue(ctb.slice(0, 50)); c.enqueue(ctb.slice(50)); c.close(); } }));
      await decryptVolumeStream(vol.vmk, vol.volumeId, rd, { write: async (b) => { got.push(b); } });
      if (!bytesEqual(concatBytes(...got), big)) throw new Error("卷模式 整块加密→流式解密 不一致");
      if (ctb.length !== volumeCiphertextLength(big.length)) throw new Error("卷模式密文长度估算与实际不符");
      // 空文件
      const ct0 = await encryptVolumeBytes(vol.vmk, vol.volumeId, new Uint8Array(0));
      if ((await decryptVolumeBytes(vol.vmk, vol.volumeId, ct0)).length !== 0) throw new Error("卷模式空文件往返失败");
      // 篡改 / 截断 / 属于别的卷 → 全部拒绝
      const bad = ctb.slice(); bad[bad.length - 1] ^= 0xff;
      vrej = false; try { await decryptVolumeBytes(vol.vmk, vol.volumeId, bad); } catch (_e) { vrej = true; }
      if (!vrej) throw new Error("卷模式未能拒绝被篡改的密文");
      vrej = false;
      try { await decryptVolumeStream(vol.vmk, vol.volumeId, new ByteReader(new Blob([ctb.slice(0, ctb.length - 3)]).stream()), null); } catch (_e) { vrej = true; }
      if (!vrej) throw new Error("卷模式流式解密未能拒绝被截断的密文");
      const other = newVolume();
      vrej = false; try { await decryptVolumeBytes(other.vmk, other.volumeId, ctb); } catch (e) { vrej = e.code === "FOREIGN_VOLUME"; }
      if (!vrej) throw new Error("卷模式未能识别属于别的卷的文件");
      vrej = false; try { await decryptVolumeBytes(other.vmk, vol.volumeId, ctb); } catch (e) { vrej = e.code === "KEY_MISMATCH"; }
      if (!vrej) throw new Error("卷模式未能拒绝错误的卷主密钥");
      wipe(vol.vmk, u1.vmk, u2.vmk, other.vmk);
    }

    return true;
  }

  return {
    // 高层
    generateKeypair, encryptHybrid, encryptPassword, decrypt, fingerprint,
    selfTest,
    // 发件人认证（可选签名）
    encryptHybridSigned, signerFingerprint, signedMessage,
    buildHeaderHybridSigned, buildSignedEnvelope, parseSignedEnvelope,
    // 私钥静态加密
    wrapSecretKey, unwrapSecretKey, isWrappedKey,
    // 校验 / 资源上限
    validatePub, validateKeyObj, assertArgonSane,
    // 第四轮：流式 AEAD + 卷模式（硬盘加密）
    ByteReader, rechunk, encryptStreamTo, decryptStreamTo,
    newVolume, validateVolumeHeader, addPasswordSlot, addPubkeySlot, removeSlot, unlockVolume,
    encryptVolumeStream, decryptVolumeStream, openVolumeStream, encryptVolumeBytes, decryptVolumeBytes,
    volumeFileDerive, buildHeaderVolume, probeHeader, volumeCiphertextLength,
    // 中层（便于测试 / 复用 / 跨实现对拍）
    encryptStream, decryptStream, hybridDerive, passwordDerive, keywrapDerive, argon2Raw,
    buildHeaderHybrid, buildHeaderPassword, parseHeader,
    x25519GenerateRaw, x25519ImportPrivate, x25519ImportPublic, x25519Exchange,
    // 工具 / 常量
    b64encode, b64decode, concatBytes, bytesEqual, wipe,
    MODE_HYBRID, MODE_PASSWORD, MODE_HYBRID_SIGNED, MODE_VOLUME, VERSION, CHUNK_SIZE, KEY_LEN, COMMIT_LEN, SALT_LEN,
    VOLUME_ID_LEN, VMK_LEN, VOLUME_HDR_LEN, VOLUME_FORMAT, SLOT_PASSWORD, SLOT_PUBKEY,
    ARGON_TIME, ARGON_MEM_KIB, ARGON_PAR,
    MLKEM1024_PK_LEN, MLKEM1024_SK_LEN, MLKEM1024_CT_LEN,
    MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_SIG_LEN,
  };
}



// 把核心工厂导出，便于在 Node 中用真实 Web Crypto 做往返自测（见顶部设计注释）。
export { createPQCrypto };

// ===========================================================================
//  第三轮加固：口令卫生（纯函数、无依赖、浏览器 / Node 通用，可被 _verify 直接测试）
//  · passwordStrength : 启发式强度估算 + 硬性拦截（过短 / 极常见口令）
//  · normalizePassword: Unicode NFC 统一表示，避免同一口令在不同设备 / 输入法下字节不同而无法解密
//  · passwordHints    : 易被忽视的输入陷阱（首尾空格、全角字符）
//  · kdfCostExceedsDefault: 文件 / 私钥容器声明的 Argon2 参数是否明显高于本工具默认值
//    （由文件控制的参数 → 解密前提示用户，避免恶意文件让浏览器长时间卡死 / 内存耗尽）
// ===========================================================================

// 极常见口令（公开泄露榜单头部 + 中文用户高频）。命中即硬性拦截，不接受“确认后继续”。
const COMMON_PASSWORDS = new Set([
  "password", "password1", "password123", "passw0rd", "p@ssw0rd", "123456", "1234567", "12345678",
  "123456789", "1234567890", "12345678910", "qwerty", "qwerty123", "qwertyuiop", "abc123", "abcd1234",
  "111111", "11111111", "000000", "00000000", "88888888", "66666666", "123123", "123321", "654321",
  "1q2w3e4r", "1qaz2wsx", "zxcvbnm", "asdfgh", "asdfghjkl", "iloveyou", "admin", "admin123", "root",
  "letmein", "welcome", "monkey", "dragon", "sunshine", "princess", "football", "baseball", "master",
  "hello", "freedom", "whatever", "trustno1", "woaini", "woaini1314", "5201314", "1314520", "a123456",
  "123456a", "a12345678", "123456abc", "aa123456", "qq123456", "7758521", "1234qwer", "12qwaszx",
]);

// 常见键盘走位 / 常见片段：出现即扣分（不硬拦，因为可能只是长口令的一部分）。
const WEAK_FRAGMENTS = ["qwerty", "asdf", "zxcv", "1qaz", "2wsx", "password", "admin", "letmein", "iloveyou", "woaini", "1314", "520", "abc123", "123456"];

function normalizePassword(pw) {
  const s = String(pw ?? "");
  return typeof s.normalize === "function" ? s.normalize("NFC") : s;
}

// 返回 { bits, score(0..4), label, blocked, reason, warnings[] }。
// 估算是【启发式】：只能挡住明显糟糕的口令，不能证明一个口令是好的。
function passwordStrength(pw) {
  const s = normalizePassword(pw);
  const chars = Array.from(s); // 按码点计数（避免把一个中文字 / emoji 拆成多个 UTF-16 单元）
  const res = { length: chars.length, bits: 0, score: 0, label: "—", blocked: false, reason: "", warnings: [] };
  if (chars.length === 0) { res.blocked = true; res.reason = "口令不能为空"; return res; }

  let lower = 0, upper = 0, digit = 0, symbol = 0, other = 0;
  for (const ch of chars) {
    const c = ch.codePointAt(0);
    if (c >= 0x61 && c <= 0x7a) lower++;
    else if (c >= 0x41 && c <= 0x5a) upper++;
    else if (c >= 0x30 && c <= 0x39) digit++;
    else if (c < 0x80) symbol++;
    else other++;
  }
  let pool = 0;
  if (lower) pool += 26;
  if (upper) pool += 26;
  if (digit) pool += 10;
  if (symbol) pool += 33;
  const ascii = lower + upper + digit + symbol;
  let bits = ascii ? ascii * Math.log2(pool) : 0;
  bits += other * 7; // 非 ASCII（中文 / 日文 / 带音标字母 …）保守按每字 7 bit 计：人选的词组远低于字符集熵

  // 扣分：单调 / 重复序列（aaaa、1234、abcd、9876）
  let runs = 0;
  for (let i = 1; i < chars.length; i++) {
    const a = chars[i - 1].codePointAt(0), b = chars[i].codePointAt(0);
    if (b === a || b === a + 1 || b === a - 1) runs++;
  }
  bits -= runs * 3;
  // 扣分：常见片段 / 键盘走位
  const low = s.toLowerCase();
  for (const f of WEAK_FRAGMENTS) if (low.includes(f)) bits -= 10;
  // 扣分：字符种类极少
  const uniq = new Set(chars).size;
  if (uniq <= 2) bits = Math.min(bits, 10);
  else if (uniq <= 4) bits = Math.min(bits, 24);
  bits = Math.max(0, Math.round(bits));
  res.bits = bits;

  if (COMMON_PASSWORDS.has(low) || COMMON_PASSWORDS.has(low.replace(/[^a-z0-9@]/g, ""))) {
    res.blocked = true; res.reason = "这是公开泄露榜单上的极常见口令，会被瞬间猜中";
  } else if (chars.length < 8) {
    res.blocked = true; res.reason = "口令至少需要 8 个字符（推荐 12 个以上，或使用随机生成的口令）";
  }

  if (bits < 28) { res.score = 0; res.label = "很弱"; }
  else if (bits < 40) { res.score = 1; res.label = "弱"; }
  else if (bits < 60) { res.score = 2; res.label = "一般"; }
  else if (bits < 80) { res.score = 3; res.label = "较强"; }
  else { res.score = 4; res.label = "强"; }

  if (ascii && !other && digit === ascii) res.warnings.push("纯数字口令（生日 / 手机号类）极易被穷举");
  if (lower && !upper && !digit && !symbol && !other && chars.length < 16) res.warnings.push("仅小写字母且较短，建议加长或混入其它字符");
  for (const h of passwordHints(pw)) res.warnings.push(h);
  return res;
}

// 输入陷阱提示（不影响强度分）。
function passwordHints(pw) {
  const s = String(pw ?? "");
  const hints = [];
  if (/^\s|\s$/.test(s)) hints.push("口令首尾含空白字符，跨设备输入时极易遗漏");
  if (/[\uFF01-\uFF5E\u3000]/.test(s)) hints.push("含全角字符（可能是输入法处于全角模式），请确认是有意为之");
  if (typeof s.normalize === "function" && s.normalize("NFC") !== s)
    hints.push("口令含组合字符，已按 Unicode NFC 统一表示以免跨设备无法解密");
  return hints;
}

function fmtKiB(kib) { const k = Number(kib) || 0; return k < 1024 ? k + " KiB" : Math.round(k / 1024) + " MiB"; }

// 由文件 / 私钥容器声明的 Argon2 参数明显高于默认值（内存或时间任一超过 2 倍）→ 返回描述串，否则 null。
function kdfCostExceedsDefault(timeCost, memKiB, parallelism) {
  const mem = Number(memKiB) || 0, t = Number(timeCost) || 0, p = Number(parallelism) || 0;
  if (mem > 2 * ARGON_MEM_KIB || t > 2 * ARGON_TIME || p > 2 * ARGON_PAR) {
    return `此文件声明的口令派生参数为 内存 ${fmtKiB(mem)} / t=${t} / p=${p}，`
      + `明显高于本工具默认值（${fmtKiB(ARGON_MEM_KIB)} / t=${ARGON_TIME} / p=${ARGON_PAR}）。`
      + `这些参数由文件本身决定，可能是对方刻意设置，也可能是恶意文件试图让你的浏览器长时间卡死或内存耗尽。`;
  }
  return null;
}

export { passwordStrength, normalizePassword, passwordHints, kdfCostExceedsDefault, fmtKiB, COMMON_PASSWORDS };
