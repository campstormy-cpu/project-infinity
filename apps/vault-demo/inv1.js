/* INV1 passphrase mode in JavaScript (WebCrypto + Argon2id from hash-wasm).
 * Byte-compatible with packages/vault/infinity_vault/vault.py for mode 1 (passphrase), uncompressed.
 * Not supported here: hybrid mode (X25519 + ML-KEM-768) and compressed payloads. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.INV1 = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";
  const MAGIC = [0x49, 0x4e, 0x56, 0x31]; // "INV1"
  const BASE = 7, PASS = 57, HL = BASE + PASS, WRAP_CT = 80, OVERHEAD_SLACK = 4096;
  const MIN_CHARS = 12, MAX_KDF_LANES = 16, MAX_KDF_T = 10;
  const DEFAULT_MAX_KIB = 512 * 1024;
  const subtle = () => globalThis.crypto.subtle;
  const enc = new TextEncoder();

  class VaultError extends Error {}
  class FormatError extends VaultError {}
  class DecryptError extends VaultError {}
  const BAD = "No se puede descifrar (frase incorrecta o archivo dañado)";

  const concat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0), o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
  const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
  const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; };
  const rd32 = (b, o) => new DataView(b.buffer, b.byteOffset).getUint32(o);
  const rd64 = (b, o) => Number(new DataView(b.buffer, b.byteOffset).getBigUint64(o));
  const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
  function ctEq(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }

  async function hkdf(ikm, info) {
    const k = await subtle().importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(await subtle().deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(info) }, k, 256));
  }
  const commit = (key, label) => hkdf(key, "INV1 commit " + label);
  const aesKey = (raw) => subtle().importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  async function gcmEnc(key, nonce, pt, aad) { return new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, await aesKey(key), pt)); }
  async function gcmDec(key, nonce, ct, aad) {
    try { return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, await aesKey(key), ct)); }
    catch (e) { throw new DecryptError(BAD); }
  }

  function normPass(p) {
    if (typeof p !== "string") throw new TypeError("la frase debe ser texto");
    const n = p.normalize("NFKC");
    if ([...n].length < MIN_CHARS) throw new Error(`La frase debe tener al menos ${MIN_CHARS} caracteres.`);
    if (/[\ud800-\udfff]/.test(n.replace(/[\ud800-\udbff][\udc00-\udfff]/g, ""))) throw new Error("La frase contiene Unicode inválido.");
    return enc.encode(n);
  }
  function checkKdf(m, t, lanes, maxKib) {
    if (!(lanes >= 1 && lanes <= MAX_KDF_LANES && t >= 1 && t <= MAX_KDF_T && m >= 8 * lanes && m <= maxKib)) throw new FormatError("parámetros de derivación de llave fuera de rango");
  }
  async function kek(argon, pw, salt, m, t, lanes) {
    return argon({ password: pw, salt, parallelism: lanes, iterations: t, memorySize: m, hashLength: 32, outputType: "binary" });
  }

  /** Cheap structural checks BEFORE any key derivation. */
  function precheck(blob, maxPlain) {
    const need = HL + 12 + WRAP_CT + 12 + 8;
    if (blob.length < need) throw new FormatError("archivo truncado");
    const bodyLen = rd64(blob, need - 8);
    if (bodyLen < 16 || bodyLen > maxPlain + OVERHEAD_SLACK + 16) throw new FormatError("longitud del cuerpo fuera de rango");
    if (blob.length !== need + bodyLen) throw new FormatError("archivo truncado o con datos sobrantes");
    return { need, bodyLen };
  }

  /** Read the header without any key: what an observer of the file can see. */
  function inspect(blob) {
    if (blob.length < BASE || MAGIC.some((v, i) => blob[i] !== v)) throw new FormatError("no es un archivo INV1");
    const out = { version: blob[4], mode: blob[5], flags: blob[6], size: blob.length };
    out.modeName = out.mode === 1 ? "frase (Argon2id + AES-256-GCM)" : out.mode === 2 ? "híbrido (X25519 + ML-KEM-768)" : "desconocido";
    out.compressed = !!(out.flags & 1);
    if (out.mode === 1 && blob.length >= HL) { out.m_kib = rd32(blob, 23); out.t = rd32(blob, 27); out.lanes = blob[31]; }
    return out;
  }

  async function encrypt(data, passphrase, argon, opts = {}) {
    const m = opts.m_kib ?? 256 * 1024, t = opts.t ?? 3, lanes = opts.lanes ?? 4;
    checkKdf(m, t, lanes, DEFAULT_MAX_KIB);
    const maxPlain = opts.maxPlaintext ?? 256 * 1024 * 1024;
    if (data.length > maxPlain) throw new Error("el texto supera el máximo permitido");
    const pw = normPass(passphrase), salt = rand(16);
    const k = await kek(argon, pw, salt, m, t, lanes);
    const header = concat(Uint8Array.from([...MAGIC, 1, 1, 0]), salt, u32(m), u32(t), Uint8Array.of(lanes), await commit(k, "kek"));
    const dek = rand(32), wn = rand(12);
    const wrapped = await gcmEnc(k, wn, concat(dek, await commit(dek, "dek")), header);
    const bn = rand(12), pre = concat(header, wn, wrapped, bn);
    const body = await gcmEnc(dek, bn, data, concat(pre, u64(data.length + 16)));
    return concat(pre, u64(body.length), body);
  }

  async function decrypt(blob, passphrase, argon, opts = {}) {
    const maxKib = opts.maxKdfKib ?? DEFAULT_MAX_KIB, maxPlain = opts.maxPlaintext ?? 256 * 1024 * 1024;
    if (blob.length < BASE || MAGIC.some((v, i) => blob[i] !== v)) throw new FormatError("no es un archivo INV1");
    if (blob[4] !== 1) throw new FormatError("versión no soportada " + blob[4]);
    if (blob[5] !== 1) throw new FormatError(blob[5] === 2 ? "este archivo usa el modo híbrido; la demo del navegador solo abre el modo frase" : "modo desconocido");
    if (blob[6] & ~1) throw new FormatError("banderas desconocidas");
    if (blob[6] & 1) throw new FormatError("este archivo está comprimido; la demo del navegador no incluye el descompresor");
    if (blob.length < HL) throw new FormatError("archivo truncado");
    const m = rd32(blob, 23), t = rd32(blob, 27), lanes = blob[31];
    checkKdf(m, t, lanes, maxKib);
    const { need, bodyLen } = precheck(blob, maxPlain);
    const pw = normPass(passphrase);
    const k = await kek(argon, pw, blob.slice(7, 23), m, t, lanes);
    if (!ctEq(blob.slice(32, 64), await commit(k, "kek"))) throw new DecryptError(BAD);
    const header = blob.slice(0, HL), wn = blob.slice(HL, HL + 12), wrapped = blob.slice(HL + 12, HL + 12 + WRAP_CT);
    const bn = blob.slice(HL + 12 + WRAP_CT, HL + 24 + WRAP_CT);
    const un = await gcmDec(k, wn, wrapped, header);
    const dek = un.slice(0, 32);
    if (!ctEq(un.slice(32), await commit(dek, "dek"))) throw new DecryptError(BAD);
    return gcmDec(dek, bn, blob.slice(need), concat(blob.slice(0, need - 8), u64(bodyLen)));
  }

  return { encrypt, decrypt, inspect, VaultError, FormatError, DecryptError, HEADER_LEN: HL };
});
