# ADR-001 — Formato y primitivas de la bóveda INV1

Estado: **propuesto, prototipo sin revisión externa.** Fecha: 2026-10-27.

## Contexto
Hace falta almacenamiento cifrado (Fase 0) con integridad y una vía realista hacia criptografía poscuántica.
Restricción central: **no implementar primitivas criptográficas propias**. Todo viene de `cryptography` 50.0.1
(verificado en este entorno: AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305, Argon2id, HKDF, X25519, ML-KEM-768/1024, ML-DSA-44/65/87; ML-KEM-512 no está expuesto).

## Decisiones

| Tema | Decisión | Alternativas consideradas | Motivo |
|---|---|---|---|
| Cifrado de datos | AES-256-GCM, llave aleatoria nueva por archivo, nonce aleatorio de 96 bits | ChaCha20-Poly1305; AES-GCM-SIV (resistente al mal uso de nonce) | Con llave nueva por archivo y un solo mensaje por llave, el riesgo de repetir nonce es despreciable. GCM-SIV es una opción válida si luego se cifra por trozos con la misma llave |
| Derivación desde frase | Argon2id, 256 MiB, 3 pasadas, 4 carriles por defecto; parámetros en la cabecera y acotados al leer | scrypt, PBKDF2 | Argon2id es la opción actual recomendada hasta donde sé (RFC 9106). Medido en esta VM de 2 núcleos (2026-10-27): 64 MiB = 0.15 s, 256 MiB = 0.56 s, 512 MiB = 1.13 s por intento. Se eligió 256 MiB: cómodo para abrir tu propia bóveda y varias veces más caro para quien adivina. En un teléfono o equipo con poca memoria habrá que ajustarlo. El tiempo de un atacante con hardware especializado **no** se midió |
| Modo con llaves | Híbrido: X25519 + ML-KEM-768, secretos concatenados y combinados con HKDF-SHA256, ligando al KDF las dos llaves públicas, el valor efímero y el texto cifrado de ML-KEM | Solo ML-KEM; ML-KEM-1024 | El híbrido sigue protegiendo si fallara uno de los dos. 768 es el nivel intermedio habitual; 1024 es una decisión de coste/margen que queda abierta |
| PQC en el modo frase | **Ninguna.** Es simétrico | Añadir un KEM "por si acaso" | Un KEM no aporta nada cuando no hay intercambio de llaves entre partes. Añadirlo sería decoración |
| Autenticación de la cabecera | Todo lo previo a cada texto cifrado entra como dato asociado | Solo autenticar el cuerpo | Sin ello se podrían alterar bandera o modo. Hay una prueba específica |
| Compromiso de llave | `HKDF(KEK)` en la cabecera y `HKDF(DEK)` dentro de la llave envuelta | Confiar en GCM | GCM no ata un texto cifrado a una sola llave; el compromiso evita trucos con varias llaves |
| Compresión | Opcional, **desactivada por defecto**; se comprime antes de cifrar | Siempre comprimir; nunca | La longitud comprimida filtra información si un atacante controla parte de los datos (familia CRIME/BREACH) **[conocimiento general]**. Se reutiliza el descompresor acotado de las auditorías |
| Errores | Llave errónea y archivo dañado dan el mismo `DecryptError`; formato no válido da `FormatError` | Mensajes detallados | Reduce lo que un atacante aprende |
| Agilidad | Byte de versión y byte de modo en la cabecera | Formato fijo | Permite cambiar algoritmos sin romper lectores antiguos |

## Consecuencias
- El formato `INV1` **no** es compatible con el contenedor de compresión `INF1`; son productos distintos que solo comparten el descompresor.
- Hay que auditar la **composición** antes de uso real. Primitivas estándar no garantizan composición segura.
- Quedan abiertos: cifrado por trozos, firma de remitente, versiones firmadas, llaves en hardware.
