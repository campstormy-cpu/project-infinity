# Demo de la bóveda y Thunder (navegador)

`template.html` + `inv1.js` + `thunder.js` -> `python3 build.py` -> `dist/index.html` (una sola página).

- `inv1.js`: modo frase de INV1 (Argon2id de hash-wasm 4.11.0 + WebCrypto). Compatible byte a byte con `packages/vault`
  (probado en ambos sentidos). No incluye el modo híbrido ni la compresión.
- `thunder.js`: motor de análisis determinista (sin red, sin modelo). Codificaciones, cifrados clásicos, reconocimiento
  de formatos modernos. No rompe cifrado moderno.
- Pruebas: `npm i hash-wasm@4.11.0 && node test.mjs` (35 pruebas; las de la bóveda se omiten si falta hash-wasm).
