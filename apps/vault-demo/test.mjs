// Run: node test.mjs   (needs `npm i hash-wasm@4.11.0` reachable via NODE_PATH for the vault tests)
import { createRequire } from "module";
import assert from "assert";
const require = createRequire(import.meta.url);
const T = require("./thunder.js");
const INV1 = require("./inv1.js");
let argon; try { argon = require("hash-wasm").argon2id; } catch (e) { console.log("hash-wasm not found: vault tests skipped"); }
let pass = 0, fail = 0;
const t = async (name, fn) => { try { await fn(); pass++; console.log("ok  ", name); } catch (e) { fail++; console.log("FAIL", name, "\n    ", e.message.split("\n")[0]); } };

const EN = "It was the best of times and it was the worst of times, and the people of the city did not know what the next day would bring. They gathered in the market to talk about the news from the north, and some of them said that the army would come before winter. Others thought the message was only a rumor, because nobody had seen the soldiers with their own eyes. The old man at the bakery told them to keep calm, to save what they could, and to wait for the letter that the mayor had promised to send when he knew the truth about the road.";
const ES = "No sabemos todavía lo que va a pasar con el proyecto, pero todos los que trabajan en la oficina piensan que la decisión llegará antes de que termine el mes. Durante la reunión de ayer, el director explicó que el dinero se usará para comprar equipos nuevos y para pagar a las personas que ayudaron con el trabajo del año pasado. Algunos dijeron que era una buena idea, otros tenían dudas sobre los plazos, y la mayoría quería saber cuándo van a recibir el mensaje oficial con la fecha y los detalles del plan.";
const norm = (s) => T.strip(s);
const has = (res, plain) => res.some((r) => norm(r.text).includes(norm(plain).slice(0, 60)));

function caesar(s, k) { return T.shiftText(s, k); }
function vigEnc(s, key) { let j = 0; return s.replace(/[A-Za-z]/g, (c) => { const b = c <= "Z" ? 65 : 97; return String.fromCharCode(b + ((c.charCodeAt(0) - b + key.charCodeAt(j++ % key.length) - 65) % 26)); }); }
function railEnc(s, r) { const rows = Array.from({ length: r }, () => ""); let i = 0, d = 1; for (const ch of s) { rows[i] += ch; if (i === 0) d = 1; else if (i === r - 1) d = -1; i += d; } return rows.join(""); }
function colEnc(s, order) { const L = order.length, cols = Array.from({ length: L }, () => ""); [...s].forEach((c, i) => (cols[i % L] += c)); return order.map((o) => cols[o]).join(""); }
function affEnc(s, a, b) { return s.replace(/[A-Za-z]/g, (c) => { const base = c <= "Z" ? 65 : 97; return String.fromCharCode(base + ((a * (c.charCodeAt(0) - base) + b) % 26)); }); }
function subEnc(s, key) { return s.replace(/[A-Za-z]/g, (c) => { const o = key[c.toUpperCase().charCodeAt(0) - 65]; return c <= "Z" ? o : o.toLowerCase(); }); }
const xor = (bytes, key) => bytes.map((b, i) => b ^ key[i % key.length]);
const te = (s) => Array.from(new TextEncoder().encode(s));

await t("caesar EN", () => assert(has(T.solveCaesar(caesar(EN, 7)), EN)));
await t("caesar ES", () => assert(has(T.solveCaesar(caesar(ES, 13)), ES)));
await t("atbash", () => assert(has(T.solveAtbash(T.analyze ? EN.replace(/[A-Za-z]/g, (c) => { const b = c <= "Z" ? 65 : 97; return String.fromCharCode(b + 25 - (c.charCodeAt(0) - b)); }) : ""), EN)));
await t("affine EN", () => assert(has(T.solveAffine(affEnc(EN, 7, 3)), EN)));
await t("vigenere EN key LEMON", () => assert(has(T.solveVigenere(vigEnc(EN, "LEMON")), EN)));
await t("vigenere ES key CLAVESECRETA", () => assert(has(T.solveVigenere(vigEnc(ES, "CLAVESECRETA")), ES)));
await t("rail fence 4 rails", () => assert(has(T.solveRail(railEnc(norm(EN), 4)), EN)));
await t("columnar 5 cols", () => assert(has(T.solveColumnar(colEnc(norm(EN), [3, 0, 4, 1, 2])), EN)));
await t("substitution EN", () => {
  const key = "QWERTYUIOPASDFGHJKLZXCVBNM"; const r = T.solveSubstitution(subEnc(EN, key));
  const got = norm(r[0].text), want = norm(EN); let ok = 0; for (let i = 0; i < want.length; i++) if (got[i] === want[i]) ok++;
  assert(ok / want.length > 0.9, `only ${(100 * ok / want.length).toFixed(0)}% letters recovered`);
});
await t("substitution ES", () => {
  const r = T.solveSubstitution(subEnc(ES, "MNBVCXZLKJHGFDSAPOIUYTREWQ")); const got = norm(r[0].text), want = norm(ES); let ok = 0; for (let i = 0; i < want.length; i++) if (got[i] === want[i]) ok++;
  assert(ok / want.length > 0.9, `only ${(100 * ok / want.length).toFixed(0)}% letters recovered`);
});
await t("substitution: text too short is refused rather than guessed", () => assert.deepEqual(T.solveSubstitution("QWE RTY UIO"), []));
await t("analyze: substitution through analyze", () => { const r = T.analyze(subEnc(EN, "QWERTYUIOPASDFGHJKLZXCVBNM")); assert(r.findings.some((f) => f.kind === "cipher" && /Sustitución/.test(f.title))); });
await t("xor single byte", () => assert(has(T.solveXor(xor(te(EN), [0x5a])), EN)));
await t("xor repeating key", () => assert(has(T.solveXor(xor(te(EN), te("ICE9"))), EN)));

await t("analyze: base64 of text", () => { const r = T.analyze(Buffer.from("hola mundo, este es un mensaje de prueba").toString("base64")); assert(r.findings[0].result.includes("hola mundo")); });
await t("analyze: layered hex(base64)", () => { const b = Buffer.from(Buffer.from("capas dentro de capas de codificacion").toString("base64")).toString("hex"); const r = T.analyze(b); assert(r.findings[0].result.includes("capas dentro"), JSON.stringify(r.findings[0])); });
await t("analyze: binary", () => { const r = T.analyze("01001000 01101111 01101100 01100001"); assert(r.findings[0].result === "Hola"); });
await t("analyze: morse", () => { const r = T.analyze(".... --- .-.. .-"); assert(r.findings[0].result === "HOLA"); });
await t("analyze: caesar through analyze", () => { const r = T.analyze(caesar(EN, 11)); assert(r.findings.some((f) => f.kind === "cipher" && norm(f.result).includes(norm(EN).slice(0, 50)))); });
await t("analyze: vigenere through analyze", () => { const r = T.analyze(vigEnc(ES, "LLAVE")); assert(r.findings.some((f) => f.kind === "cipher" && norm(f.result).includes(norm(ES).slice(0, 50)))); });
await t("analyze: short Caesar text is called Caesar, not an over-fitted Vigenere", () => {
  const short = "Nos vemos en la plaza al amanecer. Trae el mensaje, no hables con nadie y espera la señal de la campana antes de cruzar el puente.";
  const f = T.analyze(caesar(short, 5)).findings.find((x) => x.kind === "cipher"); assert(f && /César/.test(f.title), f && f.title); assert(norm(f.result).includes(norm(short).slice(0, 40)));
});
await t("analyze: plain text is called plain", () => assert(T.analyze(EN).findings[0].kind === "plain"));
await t("analyze: random bytes are NOT broken, and it says so", () => {
  const rnd = require("crypto").randomBytes(200); const r = T.analyze(rnd.toString("base64"));
  assert(!r.findings.some((f) => f.kind === "cipher"), "claimed to break random data");
  assert(r.findings.some((f) => /aleatori/i.test(f.title)));
});
await t("analyze: AES-GCM output is not broken", () => {
  const c = require("crypto"); const k = c.randomBytes(32), iv = c.randomBytes(12); const ci = c.createCipheriv("aes-256-gcm", k, iv);
  const ct = Buffer.concat([iv, ci.update(EN), ci.final(), ci.getAuthTag()]); const r = T.analyze(ct.toString("base64"));
  assert(!r.findings.some((f) => f.kind === "cipher"));
});
await t("analyze: hash is identified, not reversed", () => { const r = T.analyze("5d41402abc4b2a76b9719d911017c592"); assert(/MD5/.test(r.findings.find((f) => /resumen/.test(f.title)).title) && !r.findings.some((f) => f.result)); });
await t("analyze: JWT alg none raises alert", () => {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString("base64url"); const r = T.analyze(`${b({ alg: "none", typ: "JWT" })}.${b({ sub: "1" })}.`);
  assert(r.findings.some((f) => f.kind === "alert" && /alg=none/.test(f.detail)));
});
await t("analyze: private key block raises alert", () => assert(T.analyze("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----").findings.some((f) => f.kind === "alert")));
await t("passphrase check ranks", () => { assert(T.passphraseCheck("password123").level === 1); assert(T.passphraseCheck("caballo bateria grapa correcto lluvia").level >= 3); });

if (argon) {
  const P = { m_kib: 8, t: 1, lanes: 1 }; const PW = "frase de prueba larga y unica"; const enc = new TextEncoder();
  await t("vault roundtrip", async () => { const b = await INV1.encrypt(enc.encode("secreto ñ"), PW, argon, P); assert.equal(new TextDecoder().decode(await INV1.decrypt(b, PW, argon, { maxKdfKib: 64 })), "secreto ñ"); });
  await t("vault wrong passphrase", async () => { const b = await INV1.encrypt(enc.encode("x"), PW, argon, P); await assert.rejects(INV1.decrypt(b, "otra frase distinta larga", argon, { maxKdfKib: 64 }), INV1.DecryptError); });
  await t("vault: every flipped bit of the header/body is rejected", async () => {
    const b = await INV1.encrypt(enc.encode("integridad"), PW, argon, P);
    for (let i = 0; i < b.length; i++) { const c = b.slice(); c[i] ^= 1 << (i % 8); await assert.rejects(INV1.decrypt(c, PW, argon, { maxKdfKib: 64 }), INV1.VaultError, `byte ${i} accepted`); }
  });
  await t("vault: hostile KDF params rejected before Argon2", async () => {
    const b = await INV1.encrypt(enc.encode("x"), PW, argon, P); const c = b.slice(); new DataView(c.buffer).setUint32(23, 600 * 1024); const t0 = Date.now();
    await assert.rejects(INV1.decrypt(c, PW, argon), INV1.FormatError); assert(Date.now() - t0 < 200);
  });
  await t("vault: short and surrogate passphrases refused", async () => { await assert.rejects(INV1.encrypt(enc.encode("x"), "corta", argon, P)); await assert.rejects(INV1.encrypt(enc.encode("x"), "abcdefghijkl\ud800", argon, P)); });
  await t("vault: inspect shows header without any key", async () => { const b = await INV1.encrypt(enc.encode("x"), PW, argon, P); const h = INV1.inspect(b); assert(h.mode === 1 && h.m_kib === 8 && h.t === 1 && h.lanes === 1 && !h.compressed); });
  await t("vault: analyze recognises INV1 in base64", async () => { const b = await INV1.encrypt(enc.encode("x"), PW, argon, P); const r = T.analyze(Buffer.from(b).toString("base64")); assert(r.findings.some((f) => f.kind === "inv1")); assert(!r.findings.some((f) => f.kind === "cipher")); });
}
console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
