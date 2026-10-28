/* Thunder: deterministic analysis engine. No network, no model, nothing leaves the page.
 * Knows: layered encodings, classical ciphers (Caesar, Atbash, Affine, Vigenere, rail fence, columnar
 * transposition, simple substitution, XOR), and how to recognise (not break) modern formats.
 * It cannot break modern encryption, and it says so. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.Thunder = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const FREQ = {
    en: [8.17,1.49,2.78,4.25,12.7,2.23,2.02,6.09,6.97,0.15,0.77,4.03,2.41,6.75,7.51,1.93,0.1,5.99,6.33,9.06,2.76,0.98,2.36,0.15,1.97,0.07],
    es: [12.53,1.42,4.68,5.86,13.68,0.69,1.01,0.7,6.25,0.44,0.02,4.97,3.15,6.71,8.68,2.51,0.88,6.87,7.98,4.63,3.93,0.9,0.01,0.22,0.9,0.52],
  };
  const WORDS = {
    en: "THE AND THAT HAVE FOR NOT WITH YOU THIS BUT HIS FROM THEY SAY HER SHE WILL ONE ALL WOULD THERE THEIR WHAT OUT ABOUT WHO GET WHICH WHEN MAKE CAN LIKE TIME NO JUST HIM KNOW TAKE PEOPLE INTO YEAR YOUR GOOD SOME COULD THEM SEE OTHER THAN THEN NOW LOOK ONLY COME ITS OVER THINK ALSO BACK AFTER USE TWO HOW OUR WORK FIRST WELL WAY EVEN NEW WANT BECAUSE ANY THESE GIVE DAY MOST ARE WAS WERE HAS HAD BEEN KEY SECRET MESSAGE".split(" "),
    es: "QUE DE LA EL EN LOS DEL SE LAS POR UN PARA CON UNA SU AL ES LO COMO MAS PERO SUS LE YA O FUE ESTE HA SI PORQUE ESTA SON ENTRE ESTA CUANDO MUY SIN SOBRE TAMBIEN ME HASTA HAY DONDE QUIEN DESDE TODO NOS DURANTE TODOS UNO LES NI CONTRA OTROS ESE ESO ANTE ELLOS ESTO MI ANTES ALGUNOS QUE UNOS YO OTRO OTRAS OTRA EL TANTO ESA ESTAS SEA MENSAJE CLAVE SECRETO".split(" "),
  };
  const BIGRAMS = {
    en: "TH HE IN ER AN RE ON AT EN ND TI ES OR TE OF ED IS IT AL AR ST TO NT NG SE HA AS OU IO LE VE CO ME DE HI RI RO IC NE EA RA CE LI CH LL BE MA SI OM UR".split(" "),
    es: "DE ES EN EL LA OS UE AR RA ER CI OR QU AN DO AL RE CO NT AD ST TA TE IE AC ON SE IA CA ES NA ST LO RI TO UN PA RO PO LE ME IO SA NO".split(" "),
  };
  // Bigram cost tables (26x26, quantised -log10 P(b|a) * 16, 62-level alphabet). English: derived from Python's own
  // documentation text (~370k letters); Spanish: from a small hand-written corpus (~2k letters), so weaker.
  const SAFE = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const BG = { en: "kOKQjXVsOzZEJDrSxEFCSUeaTkIgRbBhlzMDzEihLUzQRcEumuGzFpPgDbvHMzPGdfDdzPbCMqhzizILROAOgbCrdSVUKVwTJHLZQfXwKTIHPMWcNuhONGQNUFFHaTVMVsGZTWLNdgCwZPaTAWzLQEHfebYzIWQXBSSNHnfLSJNRyLJGHcVkolDfZe4eokGzmiYfGezTVPgeiujzSRLRQLRzhodNO9EVtTEEzSydzaTzVi1ifvUcXyzbYzzhYZNzdczzKcVY5SYnFkzYTVQOzTILOoOzzzEXWOBQklGsnFZXHWzaKLJaaqKzCObe7dptMxodOfHFzcOQNnengzHUIGIUGcLvjTTUHWuaHCRTZmXrSLPJWIajUsaQMATMzCPILUPmrpDiaWBdsaNzkFehHLzDUGXqhsOzTaxuazzsdzzTaeqzzsZp1eezezEXSOAVPgFoeXNLIUzNJJQeWiQyHWMSDRbRFudTTQKMnVGCLdTjUpHYRYDWiAEzmWWaJazKLKRfWkPwLNOVFbRxLzxFJFeKzHFFmxryzz6zzz6zzsFztzaoPzzzbrmzzzzzHhXYHalB7zjWfRGgzPOUicbzznGeBXEVaZGtodcVSBzaQHlcdROhJNKQORbZIzZWSKJCqPHDVSLafeFZdp3OumEzzddmPezcYcszteRz", es: "MKKIJTUWUVzJMEWOSFEPUOzvTdBYPOHdacGgzFSNIUbFMPLbzlbfCbTSFgeJDkzTWRCXfQPTEfzofiDcUO7hfhHkzTXRDYgMQUKfzpfjQVLKLYRYUUzDQCUPWFDSPSzdcZCWNMGbYaHezKQLJSZIKNGZziZdEXONGcZbKfzLRMDTaFLOFazjadBWONEbZbFfzORMESaLKOPazjadDQLJFYTiTYzMOFFSXLKNTXzqgREVNLCaYaLdzNQKCRZKJNOYziYcEULKEZWYJcxLOJHQXJILMXzhXb8eQQFYUjJmzIUREQhROLRUzrYlDYQPCdbdChzQTOJHcOMQHczlcfCfJJHVVZOnzIRQGRRSJEMSzsiZKRKJJkZWVazKMGTSRFAPVVzWMaCaSQCfcfKizMUPEWdDOSGdzndhIXPNHcZcNfzOSMKTaMLP6azkaeAeTMDjSjFmzJSRETSOOLSYzrhZFfHHEVhTMnzQTQKFPNNHNPzsTaAbTRBgdgKjzSWQBXeHPTLezoeiISLN9iWhLXzMXDQZgHKMVWzpTkFXPOAcacAgzPSNHUbNLPQbzkbeEULKEZWYJcxLOJHQXJILMXzhXbFUMKEZWZGcyLPJHQXJIJNXzhXbGXLICcZRMfzLNKKLaMGOKazjadBVNLFaXaLdzMQKCRYKJNOYziYc" };
  function bgFit(t, lang) { const tab = BG[lang]; let s = 0; for (let i = 0; i + 1 < t.length; i++) s += SAFE.indexOf(tab[(t.charCodeAt(i) - 65) * 26 + t.charCodeAt(i + 1) - 65]); return -(s / 16) / Math.max(t.length - 1, 1); }
  const TG_EN = "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";
  function tgFit(t) { let s = 0; for (let i = 0; i + 2 < t.length; i++) s += SAFE.indexOf(TG_EN[((t.charCodeAt(i) - 65) * 26 + t.charCodeAt(i + 1) - 65) * 26 + t.charCodeAt(i + 2) - 65]); return -(s / 16) / Math.max(t.length - 2, 1); }
  const BIGSET = { en: new Set(BIGRAMS.en), es: new Set(BIGRAMS.es) };

  // ---- text helpers
  const strip = (s) => s.normalize("NFD").replace(/[̀-ͯ]/g, "").toUpperCase().replace(/[^A-Z]/g, "");
  const mod = (n, m) => ((n % m) + m) % m;
  function counts(t) { const c = new Array(26).fill(0); for (let i = 0; i < t.length; i++) c[t.charCodeAt(i) - 65]++; return c; }
  function chi(c, n, lang) { let x = 0; for (let i = 0; i < 26; i++) { const e = (FREQ[lang][i] / 100) * n; x += ((c[i] - e) ** 2) / (e + 0.01); } return x; }
  function wordDensity(t, lang) { let h = 0; for (const w of WORDS[lang]) { if (w.length < 3) continue; let p = -1; while ((p = t.indexOf(w, p + 1)) !== -1) h += w.length; } return h / Math.max(t.length, 1); }
  function bigramDensity(t, lang) { let h = 0; for (let i = 0; i + 1 < t.length; i++) if (BIGSET[lang].has(t[i] + t[i + 1])) h++; return h / Math.max(t.length - 1, 1); }
  /** Higher is more language-like. Works on A-Z only text. */
  function plainness(t) {
    if (t.length < 4) return { score: -9, lang: "en" };
    const c = counts(t), n = t.length; let best = { score: -1e9, lang: "en" };
    for (const lang of ["en", "es"]) {
      const s = -chi(c, n, lang) / n + 3 * wordDensity(t, lang) + 1.2 * bigramDensity(t, lang);
      if (s > best.score) best = { score: s, lang };
    }
    return best;
  }
  const confidence = (s, n) => (n < 25 ? "baja (texto muy corto)" : s > 0.55 ? "alta" : s > 0.15 ? "media" : "baja");

  // ---- classical ciphers (operate on letters; non-letters are preserved by caesar/atbash/vigenere on display text)
  function shiftText(text, k) { return text.replace(/[A-Za-z]/g, (ch) => { const b = ch <= "Z" ? 65 : 97; return String.fromCharCode(b + mod(ch.charCodeAt(0) - b + k, 26)); }); }
  function atbash(text) { return text.replace(/[A-Za-z]/g, (ch) => { const b = ch <= "Z" ? 65 : 97; return String.fromCharCode(b + 25 - (ch.charCodeAt(0) - b)); }); }
  function vigDecrypt(text, key) { let j = 0; return text.replace(/[A-Za-z]/g, (ch) => { const b = ch <= "Z" ? 65 : 97; const k = key.charCodeAt(j++ % key.length) - 65; return String.fromCharCode(b + mod(ch.charCodeAt(0) - b - k, 26)); }); }
  const inv = (a) => { for (let x = 1; x < 26; x++) if ((a * x) % 26 === 1) return x; return null; };
  function affineDecrypt(text, a, b) { const ia = inv(a); return text.replace(/[A-Za-z]/g, (ch) => { const base = ch <= "Z" ? 65 : 97; return String.fromCharCode(base + mod(ia * (ch.charCodeAt(0) - base - b), 26)); }); }
  function railDecrypt(s, rails) {
    const n = s.length; if (rails < 2 || rails >= n) return s;
    const pattern = []; let r = 0, d = 1;
    for (let i = 0; i < n; i++) { pattern.push(r); if (r === 0) d = 1; else if (r === rails - 1) d = -1; r += d; }
    const idx = [...Array(n).keys()].sort((a, b) => pattern[a] - pattern[b] || a - b);
    const out = new Array(n); idx.forEach((pos, i) => (out[pos] = s[i])); return out.join("");
  }
  function columnarDecrypt(s, order) { // order[i] = which column is read i-th
    const L = order.length, n = s.length, rows = Math.ceil(n / L), full = n % L || L;
    const len = (col) => (col < full ? rows : rows - 1);
    const cols = []; let p = 0;
    for (const col of order) { cols[col] = s.slice(p, p + len(col)); p += len(col); }
    let out = ""; for (let r = 0; r < rows; r++) for (let c = 0; c < L; c++) if (r < cols[c].length) out += cols[c][r];
    return out;
  }
  function* perms(a) { if (a.length <= 1) { yield a; return; } for (let i = 0; i < a.length; i++) for (const p of perms([...a.slice(0, i), ...a.slice(i + 1)])) yield [a[i], ...p]; }

  function top(list, k = 3) { return list.sort((x, y) => y.score - x.score).slice(0, k); }
  function mk(method, key, text, stripped) { const p = plainness(stripped ?? strip(text)); return { method, key, text, score: p.score, lang: p.lang, confidence: confidence(p.score, (stripped ?? strip(text)).length) }; }

  function solveCaesar(text) { const out = []; for (let k = 1; k < 26; k++) { const t = shiftText(text, -k); out.push(mk("César / ROT", `desplazamiento ${k}`, t)); } return top(out); }
  function solveAtbash(text) { const t = atbash(text); return [mk("Atbash", "alfabeto invertido", t)]; }
  function solveAffine(text) { const out = []; for (const a of [3,5,7,9,11,15,17,19,21,23,25]) for (let b = 0; b < 26; b++) out.push(mk("Afín", `a=${a}, b=${b}`, affineDecrypt(text, a, b))); return top(out); }
  function solveVigenere(text) {
    const L = strip(text); if (L.length < 20) return [];
    const out = [];
    for (let len = 2; len <= Math.min(20, Math.floor(L.length / 12)); len++) { // >= 12 letters per key column, or the fit is noise
      let key = "";
      for (let col = 0; col < len; col++) {
        let col_s = ""; for (let i = col; i < L.length; i += len) col_s += L[i];
        let best = null;
        for (let k = 0; k < 26; k++) {
          const d = col_s.split("").map((ch) => String.fromCharCode(65 + mod(ch.charCodeAt(0) - 65 - k, 26))).join("");
          const c = counts(d); const s = Math.min(chi(c, d.length, "en"), chi(c, d.length, "es"));
          if (!best || s < best.s) best = { s, k };
        }
        key += A[best.k];
      }
      const fv = (k2) => { const d = strip(vigDecrypt(text, k2)); return Math.max(4 * bgFit(d, "en"), 4 * bgFit(d, "es")) + 3 * Math.max(wordDensity(d, "en"), wordDensity(d, "es")); };
      let bestKey = key, bestFit = fv(key);
      for (let pass = 0; pass < 3; pass++) for (let col = 0; col < len; col++) for (let k = 0; k < 26; k++) {
        const kk = bestKey.slice(0, col) + A[k] + bestKey.slice(col + 1); const f = fv(kk);
        if (f > bestFit + 1e-9) { bestFit = f; bestKey = kk; }
      }
      key = bestKey;
      const dec = vigDecrypt(text, key); const m = mk("Vigenère", `clave "${key}"`, dec);
      m.score -= 0.01 * len; out.push(m);
    }
    return top(out, 2);
  }
  function solveRail(text) { const s = text.replace(/\s+/g, ""); const out = []; for (let r = 2; r <= Math.min(12, s.length - 1); r++) out.push(mk("Valla (rail fence)", `${r} rieles`, railDecrypt(s, r))); return top(out); }
  function solveColumnar(text) {
    const s = strip(text); if (s.length < 12) return []; const out = [];
    for (let L = 2; L <= 7; L++) for (const p of perms([...Array(L).keys()])) out.push(mk("Transposición por columnas", `orden de columnas ${p.map((x) => x + 1).join("-")}`, columnarDecrypt(s, p)));
    return top(out);
  }
  function solveSubstitution(text, seed = 1) {
    const s = strip(text); if (s.length < 120) return [];
    let rnd = seed; const rand = () => ((rnd = (rnd * 1664525 + 1013904223) >>> 0) / 4294967296);
    const c = counts(s); const byFreq = [...Array(26).keys()].sort((a, b) => c[b] - c[a]);
    let bestAll = null;
    for (const lang of ["en", "es"]) {
      let bestLang = null;
      const order = [...Array(26).keys()].sort((a, b) => FREQ[lang][b] - FREQ[lang][a]);
      const fit = (map) => { let t = ""; for (let i = 0; i < s.length; i++) t += A[map[s.charCodeAt(i) - 65]]; return (lang === "en" ? 4 * tgFit(t) : 4 * bgFit(t, lang)) + 3 * wordDensity(t, lang); };
      for (let restart = 0; restart < 6; restart++) {
        const map = new Array(26); byFreq.forEach((ci, r) => (map[ci] = order[r]));
        if (restart) for (let k = 0; k < 6 * restart; k++) { const i = (rand() * 26) | 0, j = (rand() * 26) | 0; [map[i], map[j]] = [map[j], map[i]]; }
        let cur = fit(map), improved = true, rounds = 0;
        while (improved && rounds++ < 60) {
          improved = false;
          for (let i = 0; i < 26; i++) for (let j = i + 1; j < 26; j++) {
            [map[i], map[j]] = [map[j], map[i]]; const f = fit(map);
            if (f > cur + 1e-9) { cur = f; improved = true; } else [map[i], map[j]] = [map[j], map[i]];
          }
        }
        if (!bestLang || cur > bestLang.f) bestLang = { f: cur, map: map.slice(), lang };
      }
      let t = ""; for (let i = 0; i < s.length; i++) t += A[bestLang.map[s.charCodeAt(i) - 65]];
      bestLang.pl = plainness(t).score; // languages are compared on one common scale
      if (!bestAll || bestLang.pl > bestAll.pl) bestAll = bestLang;
    }
    const plain = text.replace(/[A-Za-z]/g, (ch) => { const u = A.indexOf(ch.toUpperCase()); const o = A[bestAll.map[u]]; return ch <= "Z" ? o : o.toLowerCase(); });
    const m = mk("Sustitución simple (heurística)", "alfabeto de sustitución recuperado por escalada", plain);
    if (s.length < 250) m.confidence = "baja (la sustitución necesita textos largos)";
    return [m];
  }

  // ---- bytes / XOR
  const printable = (b) => { let p = 0; for (const x of b) if ((x >= 32 && x < 127) || x === 9 || x === 10 || x === 13) p++; return p / Math.max(b.length, 1); };
  const latin = (b) => String.fromCharCode(...b);
  function byteScore(b) { const t = strip(latin(b)); const p = printable(b); return p < 0.9 ? -9 + p : plainness(t.length >= 4 ? t : "XXXX").score + p; }
  function xorSingle(bytes) { let best = null; for (let k = 0; k < 256; k++) { const d = bytes.map((x) => x ^ k); const s = byteScore(d); if (!best || s > best.s) best = { s, k, d }; } return best; }
  const ham = (a, b) => { let d = 0; for (let i = 0; i < a.length; i++) { let x = a[i] ^ b[i]; while (x) { d += x & 1; x >>= 1; } } return d; };
  function solveXor(bytes) {
    bytes = Array.from(bytes); const out = [];
    const one = xorSingle(bytes);
    out.push({ method: "XOR de un byte", key: `0x${one.k.toString(16).padStart(2, "0")}`, text: latin(one.d), score: one.s, lang: plainness(strip(latin(one.d))).lang, confidence: confidence(one.s, bytes.length) });
    if (bytes.length >= 40) {
      const cands = [];
      for (let ks = 2; ks <= Math.min(40, bytes.length >> 2); ks++) {
        const blocks = Math.min(4, Math.floor(bytes.length / ks)); let d = 0, n = 0;
        for (let i = 0; i + 1 < blocks; i++) { d += ham(bytes.slice(i * ks, (i + 1) * ks), bytes.slice((i + 1) * ks, (i + 2) * ks)) / ks; n++; }
        cands.push({ ks, d: d / Math.max(n, 1) });
      }
      cands.sort((x, y) => x.d - y.d);
      for (const { ks } of cands.slice(0, 3)) {
        const key = []; for (let c = 0; c < ks; c++) { const col = bytes.filter((_, i) => i % ks === c); key.push(xorSingle(col).k); }
        const d = bytes.map((x, i) => x ^ key[i % ks]); const s = byteScore(d);
        out.push({ method: "XOR de clave repetida", key: `${ks} bytes: ${key.map((k) => k.toString(16).padStart(2, "0")).join("")}`, text: latin(d), score: s, lang: plainness(strip(latin(d))).lang, confidence: confidence(s, bytes.length) });
      }
    }
    return top(out, 2);
  }

  // ---- encodings
  const B64 = /^[A-Za-z0-9+/_-]+={0,2}$/;
  function b64decode(s) { s = s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const bin = atob(s); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
  function b32decode(s) { const al = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; s = s.replace(/=+$/, "").toUpperCase(); let bits = "", out = []; for (const ch of s) { const v = al.indexOf(ch); if (v < 0) return null; bits += v.toString(2).padStart(5, "0"); } for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Uint8Array.from(out); }
  const MORSE = { ".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z","-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9" };
  function tryUtf8(b) { try { const t = new TextDecoder("utf-8", { fatal: true }).decode(b); return printable(Array.from(new TextEncoder().encode(t.replace(/[^\x00-\x7f]/g, "a")))) > 0.95 ? t : null; } catch (e) { return null; } }
  function entropy(b) { const c = new Array(256).fill(0); for (const x of b) c[x]++; let h = 0; for (const n of c) if (n) { const p = n / b.length; h -= p * Math.log2(p); } return h; }

  /** One decoding step: returns [{name, bytes?, text?}] candidates for the raw string. */
  function decodeStep(s) {
    const t = s.trim(); const out = [];
    const compact = t.replace(/\s+/g, "");
    const isBin = /^[01\s]+$/.test(t) && compact.length >= 8 && compact.length % 8 === 0 && /(^|\s)[01]{8}(\s|$)/.test(t);
    if (!isBin && /^(?:[0-9a-fA-F]{2}[\s:]?)+$/.test(t) && compact.replace(/[:]/g, "").length % 2 === 0 && compact.length >= 4) { const h = compact.replace(/:/g, ""); out.push({ name: "hexadecimal", bytes: Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16))) }); }
    if (isBin) out.push({ name: "binario (8 bits)", bytes: Uint8Array.from(compact.match(/.{8}/g).map((x) => parseInt(x, 2))) });
    if (/^[\d\s,]+$/.test(t) && /\d\s+\d/.test(t)) { const nums = t.split(/[\s,]+/).filter(Boolean).map(Number); if (nums.every((n) => n >= 0 && n < 256) && nums.length >= 3) out.push({ name: "decimal (bytes)", bytes: Uint8Array.from(nums) }); if (nums.every((n) => n >= 1 && n <= 26) && nums.length >= 3) out.push({ name: "A1Z26", text: nums.map((n) => A[n - 1]).join("") }); }
    if (/^[.\-\/\s|]+$/.test(t) && /[.-]/.test(t)) { const words = t.split(/\s*[\/|]\s*|\s{3,}/); const dec = words.map((w) => w.trim().split(/\s+/).map((c) => MORSE[c] ?? "?").join("")).join(" "); if (!dec.includes("?")) out.push({ name: "morse", text: dec }); }
    if (/%[0-9a-fA-F]{2}/.test(t)) { try { out.push({ name: "URL (porcentaje)", text: decodeURIComponent(t) }); } catch (e) {} }
    if (!/[ \t]/.test(t) && /^[A-Z2-7]+=*$/.test(compact.toUpperCase()) && compact.length >= 8 && /^[A-Z2-7=]+$/.test(compact) ) { const b = b32decode(compact); if (b) out.push({ name: "base32", bytes: b }); }
    if (!/[ \t]/.test(t) && compact.length >= 8 && B64.test(compact) && (compact.length % 4 === 0 || /[-_]/.test(compact) || !/=/.test(compact))) { try { out.push({ name: "base64", bytes: b64decode(compact) }); } catch (e) {} }
    return out;
  }

  // ---- format fingerprints (recognise, never break)
  function fingerprint(raw, bytes) {
    const f = []; const t = raw.trim();
    const head = bytes ? latin(bytes.slice(0, 8)) : "";
    if (bytes && bytes.length >= 4 && latin(bytes.slice(0, 4)) === "INV1") f.push({ kind: "inv1", title: "Archivo de la bóveda Infinity (INV1)", detail: "Se puede abrir con la frase correcta. Pásalo al panel «Descifrar» de la bóveda; Thunder nunca ve la frase." });
    if (head.startsWith("Salted__")) f.push({ kind: "info", title: "Cifrado de OpenSSL (cabecera «Salted__»)", detail: "Contenido cifrado con una llave derivada de una contraseña. Sin la contraseña no hay forma práctica de abrirlo." });
    if (/^-----BEGIN PGP/.test(t)) f.push({ kind: "info", title: "Mensaje o llave PGP", detail: "Cifrado de llave pública. Necesita la llave privada del destinatario." });
    if (/^-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(t)) f.push({ kind: "alert", title: "¡Esto parece una llave privada!", detail: "No la pegues en ningún sitio. Si ya la compartiste, trátala como comprometida y genera otra." });
    if (/^\$2[aby]\$\d\d\$/.test(t)) f.push({ kind: "info", title: "Hash de contraseña bcrypt", detail: "Es un resumen unidireccional, no un texto cifrado: no se puede «descifrar»." });
    if (/^\$argon2(id|i|d)\$/.test(t)) f.push({ kind: "info", title: "Hash de contraseña Argon2", detail: "Resumen unidireccional y costoso de adivinar a propósito. No se descifra." });
    const jwt = t.match(/^(eyJ[\w-]+)\.(eyJ[\w-]*)\.([\w-]*)$/);
    if (jwt) {
      try {
        const h = JSON.parse(new TextDecoder().decode(b64decode(jwt[1]))), p = JSON.parse(new TextDecoder().decode(b64decode(jwt[2])));
        const warn = String(h.alg).toLowerCase() === "none" ? " ¡alg=none: el token no lleva firma, no debe aceptarse!" : "";
        f.push({ kind: warn ? "alert" : "info", title: "Token JWT", detail: `Cabecera ${JSON.stringify(h)}. Contenido ${JSON.stringify(p)}. Un JWT firmado no está cifrado: cualquiera lo lee; la firma solo evita que se modifique (Thunder no la verifica).${warn}` });
      } catch (e) {}
    }
    const hex = t.replace(/\s/g, "");
    if (/^[0-9a-fA-F]+$/.test(hex)) {
      const names = { 32: "MD5 (o NTLM)", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256 (o SHA3-256/BLAKE2s)", 96: "SHA-384", 128: "SHA-512" };
      if (names[hex.length]) f.push({ kind: "info", title: `Parece un resumen (hash) ${names[hex.length]}`, detail: "Un hash no es un cifrado: no tiene llave ni inversa. Solo se puede intentar adivinar el original probando candidatos; Thunder no lo hace." });
    }
    if (bytes && bytes.length >= 64) {
      const h = entropy(bytes);
      if (h > Math.min(7.2, Math.log2(bytes.length) - 0.9)) f.push({ kind: "info", title: `Datos casi aleatorios (entropía ${h.toFixed(2)} de 8 bits por byte)`, detail: "Típico de cifrado moderno (AES, ChaCha20) o de datos comprimidos. Si es cifrado moderno, sin la llave no hay ataque práctico: AES-256 tiene 2^256 llaves posibles. Lo que sí falla en la vida real es la frase débil, no el algoritmo." });
    }
    return f;
  }

  /** Peel layers of encoding up to `depth` times. */
  function peel(raw, depth = 5) {
    const steps = []; let cur = raw; let bytes = null;
    for (let i = 0; i < depth; i++) {
      const cands = decodeStep(cur); let chosen = null;
      for (const c of cands) {
        const b = c.bytes ? c.bytes : new TextEncoder().encode(c.text);
        const text = c.text ?? tryUtf8(b);
        const looksInv1 = c.bytes && c.bytes.length > 4 && latin(c.bytes.slice(0, 4)) === "INV1";
        if (looksInv1 || (text !== null && text !== undefined && printable(Array.from(b)) > 0.9) || (!text && b.length >= 16)) { chosen = { c, b, text }; break; }
      }
      if (!chosen) break;
      steps.push(chosen.c.name); bytes = chosen.b;
      if (chosen.text == null) break; // binary: stop peeling
      cur = chosen.text;
    }
    return { steps, bytes, text: steps.length ? (bytes && tryUtf8(bytes)) : null, final: cur };
  }

  /** Main entry. Returns an ordered list of findings; never claims what it cannot support. */
  function analyze(raw) {
    const input = raw.trim(); const res = { findings: [], notes: [] };
    if (!input) return res;
    const pl = peel(input);
    if (pl.steps.length) {
      if (pl.bytes) res.findings.push(...fingerprint(pl.final, pl.bytes).filter((x) => x.kind === "inv1"));
      if (pl.text) res.findings.push({ kind: "decoded", title: `Codificación detectada: ${pl.steps.join(" → ")}`, detail: "No es cifrado, solo otra forma de escribir el mensaje.", result: pl.text });
      else if (!res.findings.some((f) => f.kind === "inv1")) res.findings.push({ kind: "bytes", title: `Codificación detectada: ${pl.steps.join(" → ")}`, detail: `Resultado binario de ${pl.bytes.length} bytes.` });
    }
    res.findings.push(...fingerprint(input, pl.bytes ?? new TextEncoder().encode(input)).filter((x) => x.kind !== "inv1"));
    const text = pl.text ?? input; const letters = strip(text);
    const already = plainness(letters).score;
    if (letters.length >= 8 && /[A-Za-zÀ-ÿ]/.test(text) && !res.findings.some((f) => f.kind === "inv1")) {
      if (already > 0.45) { res.findings.push({ kind: "plain", title: "Esto ya parece texto legible", detail: "No hay nada que descifrar o ya está descifrado." }); return res; }
      const batches = [solveCaesar(text), solveAtbash(text), solveAffine(text), solveVigenere(text), solveRail(text), solveColumnar(text), solveSubstitution(text)];
      // simpler explanations win ties: every extra degree of freedom lets a cipher "fit" any text
      const penalty = (m) => /Sustitución/.test(m.method) ? 0.25 : /Vigen/.test(m.method) ? 0.08 + 0.05 * ((m.key.match(/"(\w+)"/) || [0, ""])[1].length) : /columnas/.test(m.method) ? 0.12 : /Afín|Valla/.test(m.method) ? 0.05 : 0;
      const all = batches.flat().map((m) => ({ ...m, score: m.score - penalty(m) })).sort((a, b) => b.score - a.score);
      const good = all.filter((x) => x.score > 0.15).slice(0, 3);
      if (good.length) good.forEach((g) => res.findings.push({ kind: "cipher", title: `${g.method}: ${g.key}`, detail: `Idioma probable: ${g.lang === "es" ? "español" : "inglés"}. Confianza: ${g.confidence}.`, result: g.text }));
      else res.findings.push({ kind: "none", title: "Ningún cifrado clásico encaja", detail: "Probé César, Atbash, afín, Vigenère, valla, columnas y sustitución simple. Si es cifrado moderno, no hay ataque práctico sin la llave. Si es un cifrado clásico más raro (Playfair, Hill, Enigma), todavía no lo soporto." });
    } else if (pl.bytes && pl.bytes.length >= 16 && !res.findings.some((f) => f.kind === "inv1")) {
      const xs = solveXor(pl.bytes).filter((x) => x.score > 0.15);
      if (xs.length) xs.forEach((g) => res.findings.push({ kind: "cipher", title: `${g.method}: ${g.key}`, detail: `Confianza: ${g.confidence}.`, result: g.text }));
    }
    if (!res.findings.length) res.findings.push({ kind: "none", title: "No reconozco este formato", detail: "Pega texto cifrado clásico, una codificación (base64, hex, binario, morse...), un token o un archivo INV1 en base64." });
    return res;
  }

  // ---- passphrase guard
  const COMMON = "password contraseña 123456 12345678 qwerty abc123 letmein admin welcome iloveyou monkey dragon football 111111 123123 000000 secret secreto infinity thunder mexico".split(" ");
  function passphraseCheck(p) {
    const n = p.normalize("NFKC"), len = [...n].length;
    if (!len) return { level: 0, label: "vacía", bits: 0, advice: "Escribe una frase." };
    let pool = 0; if (/[a-z]/.test(n)) pool += 26; if (/[A-Z]/.test(n)) pool += 26; if (/\d/.test(n)) pool += 10; if (/[^A-Za-z0-9]/.test(n)) pool += 33;
    let bits = len * Math.log2(Math.max(pool, 2));
    const low = n.toLowerCase(); const hit = COMMON.find((w) => low.includes(w));
    if (hit) bits = Math.min(bits, 20);
    if (/(.)\1{3,}/.test(n) || /(012|123|234|345|456|567|678|789|abc|qwe)/i.test(n)) bits *= 0.6;
    const words = n.trim().split(/\s+/).length; if (words >= 4 && !hit) bits = Math.max(bits, Math.min(len * 2.2, 70));
    const level = bits < 30 ? 1 : bits < 50 ? 2 : bits < 70 ? 3 : 4;
    const label = ["", "débil", "regular", "buena", "fuerte"][level];
    const adv = len < 12 ? "Mínimo 12 caracteres." : hit ? `Contiene «${hit}», que está en las primeras listas que prueba un atacante.` : level < 3 ? "Usa 4 o más palabras al azar, o 16+ caracteres." : "Aceptable. Es una estimación; la seguridad real depende de que sea impredecible y solo tuya.";
    return { level, label, bits: Math.round(bits), advice: adv };
  }

  return { analyze, passphraseCheck, plainness, strip, solveCaesar, solveAtbash, solveAffine, solveVigenere, solveRail, solveColumnar, solveSubstitution, solveXor, peel, fingerprint, shiftText, vigDecrypt, affineDecrypt, railDecrypt, columnarDecrypt, entropy };
});
