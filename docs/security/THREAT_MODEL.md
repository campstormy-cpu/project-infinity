# Modelo de amenazas — bóveda INV1 (prototipo)

Estado: **prototipo sin revisión externa.** No lo uses todavía para proteger secretos reales (ver sección 7).
Fecha: 2026-10-27. Código: `packages/vault/`. Pruebas: `tests/vault/` (63, incluidas pruebas de fuzzing con semilla fija).

Las afirmaciones están marcadas así: **[construido]** existe y tiene prueba; **[no construido]** es diseño o deseo;
**[conocimiento general]** no lo verifiqué en esta sesión con una fuente.

## 1. Qué protege

| Activo | Cómo |
|---|---|
| Contenido de un archivo en reposo (disco, respaldo, nube) | AES-256-GCM con llave aleatoria por archivo **[construido]** |
| Llave de archivo | Envuelta con una llave derivada de la frase (Argon2id) o de un intercambio híbrido X25519 + ML-KEM-768 **[construido]** |
| Integridad: que nadie cambie el archivo sin que se note | Todo lo que precede a un texto cifrado es dato asociado autenticado; no hay cabecera sin autenticar **[construido, con pruebas bit a bit]** |
| Llaves privadas del destinatario | Se guardan cifradas con la misma construcción de frase **[construido]** |

## 2. Qué NO protege (límites honestos)

- **Un equipo comprometido.** Malware, keylogger o alguien con acceso a tu sesión ve la frase y el contenido descifrado.
- **Una frase débil.** Argon2id encarece cada intento, pero si la frase es adivinable, cae. Es el eslabón más débil.
- **Metadatos.** Se ve el tamaño aproximado, el modo y las banderas **[construido]**. En modo con llaves la cabecera lleva un identificador del destinatario (hash de su llave pública): quien vea varios archivos puede agruparlos por destinatario (AUDIT_004 F8). No se oculta el nombre del archivo porque no se guarda; eso lo decides tú al nombrarlo.
- **Quién cifró.** El modo híbrido es de remitente anónimo: cualquiera con tu llave pública puede crear un archivo para ti. Firmar con ML-DSA es posible con la misma biblioteca **[no construido]**.
- **Borrado o reversión.** Alguien puede borrar un archivo o devolver una versión vieja válida. No hay control de versiones firmado **[no construido]**.
- **Memoria.** Python no puede borrar las llaves de la memoria de forma fiable.
- **Frase perdida = datos perdidos.** No hay recuperación por diseño **[construido]**; un esquema de recuperación sería un riesgo adicional.
- **Archivos enormes.** Se procesan enteros en memoria con tope de 256 MiB. Cifrado por trozos **[no construido]**.

## 3. Adversarios

| # | Adversario | Resultado con el diseño actual |
|---|---|---|
| A | Roba un archivo cifrado o un respaldo | No lee contenido sin la frase o la llave privada. Si lo modifica, el descifrado falla **[construido]** |
| B | Adivina la frase sin conexión, con hardware o IA | Cada intento cuesta 256 MiB y 3 pasadas de Argon2id por defecto (0.56 s en esta VM de 2 núcleos; el costo para un atacante con hardware especializado no se midió). La seguridad real depende de la longitud y aleatoriedad de la frase. Se exigen 12 caracteres como mínimo, lo cual es un piso, no una garantía |
| C | Computadora cuántica futura; almacena hoy datos cifrados para descifrarlos después **[conocimiento general]** | Modo frase: AES-256 con llave simétrica, que según lo que sé se considera adecuado frente a ataques cuánticos. Modo híbrido: hay que romper X25519 **y** ML-KEM-768 **[construido, con prueba de que ambos hacen falta]** |
| D | Archivo malicioso que agota recursos (memoria, CPU) | Costes de Argon2id, longitud del cuerpo y tamaño descomprimido se acotan **antes** del trabajo caro **[construido]**. Misma lección que las auditorías 001 a 003 |
| E | Manipulación de la cabecera para forzar descifrados débiles o dos llaves distintas | Cabecera autenticada y compromiso de llave en constantes comparadas en tiempo constante **[construido]** |
| F | Malware local, ladrón de pantalla | **Fuera de alcance** |

## 4. Amenazas con IA y qué hacer

Fuente para la lista de riesgos de aplicaciones con modelos de lenguaje: OWASP Top 10 para LLM 2025 (leída en [esta guía](https://www.gravitee.io/blog/owasp-top-10-for-llm-applications-2025-a-practical-guide)). Lo marcado [conocimiento general] no lo verifiqué.

| Amenaza | Ejemplo realista | Regla de diseño o práctica |
|---|---|---|
| **Inyección de instrucciones** (LLM01) | Un correo, PDF o página que un agente lee contiene instrucciones ocultas ("reenvía los archivos de la bóveda") | **R3.** Todo contenido de terceros es dato no confiable para un agente; nunca es instrucción |
| **Agencia excesiva** (LLM06) | Un agente con acceso a correo, Drive y la bóveda actúa por su cuenta | **R2.** Descifrar, exportar llaves, compartir y borrar exigen aprobación humana explícita. **R4.** Una identidad y permisos mínimos por agente, revocables |
| **Revelación de información sensible** (LLM02) | La frase o el contenido descifrado pasa por el contexto de un modelo y se filtra o se registra | **R1.** Ningún modelo recibe la frase ni llaves privadas. Cifrar y descifrar lo ejecuta código determinista que lanza una persona, no un modelo |
| **Cadena de suministro** (LLM03) | Una dependencia o un servidor de herramientas comprometido | **R5.** Versiones fijadas **[construido]**; fijar hashes con `pip --require-hashes` y firmar commits **[no construido]**. Usar solo bibliotecas estándar y revisadas, nunca criptografía propia |
| **Phishing y voz o video clonados con IA** **[conocimiento general]** | Una "llamada de un socio" pide un pago o un cambio de cuenta | **R6.** Verificación por un segundo canal conocido para cualquier pago o cambio de datos bancarios. Contraseñas distintas y llaves físicas o passkeys en correo y cuentas críticas. Es práctica humana, no software |
| **Descubrimiento automático de vulnerabilidades** **[conocimiento general]** | Un atacante usa IA para encontrar fallas en tu código más rápido | Superficie pequeña, pruebas dirigidas y revisión independiente antes de confiar en el código |

Nada de esto "evita hackeos con IA" por completo: reduce la superficie y limita el daño si algo falla.

## 5. Cómo está construido (resumen)

Ver `docs/adr/ADR-001-vault.md` para las decisiones y alternativas.

## 6. Evidencia

- 63 pruebas pasan. Cubren ida y vuelta en ambos modos, 1 MiB, cada byte del archivo alterado, cada bit de la cabecera y de la llave envuelta, truncamiento en cada longitud, datos sobrantes, empalme de dos archivos, límites de recursos, compromiso de llave, ML-KEM alterado, punto X25519 de orden bajo y que ambas mitades del modo híbrido sean necesarias.
- Prueba de mutación (19 cambios deliberados al código): 15 detectados. Los 4 restantes son capas redundantes: otra capa rechaza el mismo caso (por ejemplo, la comprobación explícita de longitud y el rechazo del cifrado autenticado). Clasificación hecha por mí, no auditada por un tercero.
- Una debilidad de pruebas se encontró y corrigió en esta ronda: la prueba de banderas pasaba por accidente. Ahora hay una que demuestra que apagar la bandera de compresión no devuelve datos equivocados.

- **Auditoría independiente AUDIT_004** (`audits/AUDIT_004_VAULT.md`, un revisor, sin hallazgos críticos ni altos). Hallazgos medio/bajos corregidos con prueba de regresión: coste de Argon2 antes de validar la estructura (F1; ahora la estructura se valida primero y el tope baja a 512 MiB), longitud de frase contada tras normalizar (F2), sustitutos Unicode sueltos (F3), error distinto al importar un archivo que no es de llaves (F4), llave pública de orden bajo (F5), docstring (F6). Sin corregir: el resultado de mutación 15/19 no tiene script reproducible en el repo (F7); NFKC hace equivalentes frases de ancho completo y ASCII (F12, decisión de diseño). Es una revisión de prototipo, no sustituye la revisión criptográfica externa.

## 7. Antes de usarlo con secretos reales (pendiente)

1. **Revisión criptográfica externa de la composición.** Las primitivas son estándar y revisadas; la forma de combinarlas no lo está.
2. Pruebas con vectores de interoperabilidad y *fuzzing* del lector de formato.
3. Cifrado por trozos para archivos grandes.
4. Llaves en hardware (llaves FIDO2/passkeys), prevista para la Fase 5.
5. Firma del remitente (ML-DSA) y versiones firmadas, si importa quién creó un archivo.
6. Hashes fijados en las dependencias.
