"""INV1: PROTOTYPE encrypted file container.  NOT REVIEWED.  Do not protect real secrets with it yet.

No cryptographic primitive is implemented here. Everything comes from the `cryptography` package
(AES-256-GCM, Argon2id, HKDF-SHA256, X25519, ML-KEM-768). What IS new, and therefore unreviewed, is
the composition of those primitives and the file format. That composition needs expert review
before this protects anything that matters (see docs/security/THREAT_MODEL.md).

Two modes
  1 PASSPHRASE  passphrase -> Argon2id -> KEK.   Symmetric only. AES-256 is considered adequate
                against quantum attacks, so no post-quantum algorithm is added here.
  2 HYBRID      sender encrypts TO a recipient key pair (X25519 + ML-KEM-768). Both shared secrets
                are combined with HKDF, so an attacker must break BOTH. This is the mode where
                post-quantum cryptography matters: key establishment over a public channel.

Layout (big endian)
  base      magic "INV1" | version u8 | mode u8 | flags u8                          7 bytes
  block     mode 1: salt[16] m_kib u32, t u32, lanes u8, kek_commit[32]
            mode 2: eph_x25519_pub[32], mlkem_ct[1088], kek_commit[32], recipient_id[32]
  wrap      nonce[12] | AES-GCM(KEK, DEK || dek_commit, aad=header)               12 + 80 bytes
  body      nonce[12] | length u64 | AES-GCM(DEK, plaintext, aad=everything before the ciphertext)

Design rules
  * One fresh random DEK per file; one fresh KEK per file (new salt or new ephemeral key), so random
    96-bit nonces are never reused under a key.
  * Everything before a ciphertext is authenticated as associated data (no unauthenticated header).
  * Key commitment: AES-GCM does not bind a ciphertext to one key, so the header carries
    HKDF(KEK, "commit") and the wrapped payload carries HKDF(DEK, "commit"). Both are checked in
    constant time, which stops multi-key ("partitioning oracle") tricks.
  * Header-supplied costs are bounded BEFORE any expensive work (Argon2 memory, body length), the
    lesson of the decompression-bomb findings in audits/AUDIT_001..003.
  * Wrong key and damaged ciphertext/wrapped key give the same DecryptError. Not-a-vault, wrong-mode, bad
    lengths and out-of-bounds KDF parameters give FormatError, checked BEFORE any key derivation (AUDIT_004 F6).

Known limits (also in the threat model): file size, mode and flags are visible; Python cannot wipe
keys from memory; the whole file is processed in memory (size capped); no authentication of WHO
encrypted a file (mode 2 is anonymous-sender: anyone with the public key can create one).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import unicodedata
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"INV1"
VERSION = 1
MODE_PASSPHRASE = 1
MODE_HYBRID = 2
FLAG_COMPRESSED = 1
KNOWN_FLAGS = FLAG_COMPRESSED

DEFAULT_MAX_PLAINTEXT = 256 * 1024 * 1024
MIN_PASSPHRASE_CHARS = 12
MAX_KDF_KIB = 512 * 1024  # 512 MiB ceiling on header-supplied Argon2 memory (2x the default)
MAX_KDF_T = 10
MAX_KDF_LANES = 16
MLKEM_CT_LEN = 1088
MLKEM_PK_LEN = 1184
OVERHEAD_SLACK = 4096  # compressed output can exceed the input slightly

_BASE = struct.Struct(">4sBBB")
_PASS = struct.Struct(">16sIIB32s")
_HYB = struct.Struct(f">32s{MLKEM_CT_LEN}s32s32s")
_LEN = struct.Struct(">Q")
_WRAP_PT = 64
_WRAP_CT = _WRAP_PT + 16


class VaultError(Exception):
    pass


class FormatError(VaultError):
    """Not an INV1 file, unsupported version or flags, wrong mode, malformed lengths."""


class DecryptError(VaultError):
    """Wrong key, wrong passphrase or damaged/tampered file (deliberately indistinguishable)."""


@dataclass(frozen=True)
class KdfParams:
    m_kib: int = 256 * 1024  # 256 MiB; measured 0.56 s per attempt on a 2-core VM (64 MiB was 0.15 s)
    t: int = 3
    lanes: int = 4

    @staticmethod
    def fast_for_tests() -> "KdfParams":
        return KdfParams(m_kib=8, t=1, lanes=1)

    def check(self, max_kib: int = MAX_KDF_KIB) -> None:
        if not (1 <= self.lanes <= MAX_KDF_LANES and 1 <= self.t <= MAX_KDF_T
                and 8 * self.lanes <= self.m_kib <= max_kib):
            raise FormatError("key-derivation parameters out of bounds")


# ---------------------------------------------------------------- primitives glue
def _hkdf(ikm: bytes, info: bytes, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def _commit(key: bytes, label: bytes) -> bytes:
    return _hkdf(key, b"INV1 commit " + label)


def _norm_passphrase(passphrase: str) -> bytes:
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be str")
    normalized = unicodedata.normalize("NFKC", passphrase)
    if len(normalized) < MIN_PASSPHRASE_CHARS:  # counted AFTER normalization (AUDIT_004 F2)
        raise ValueError(f"passphrase must have at least {MIN_PASSPHRASE_CHARS} characters")
    try:
        return normalized.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates (AUDIT_004 F3)
        raise ValueError("passphrase contains invalid Unicode") from None


def _kek_from_passphrase(passphrase: bytes, salt: bytes, p: KdfParams) -> bytes:
    return Argon2id(salt=salt, length=32, iterations=p.t, lanes=p.lanes, memory_cost=p.m_kib).derive(passphrase)


def _hybrid_kek(ss_x: bytes, ss_k: bytes, eph_pub: bytes, mlkem_ct: bytes, rx_pub: bytes, rk_pub: bytes) -> bytes:
    """Concatenate both shared secrets and bind every public value into the KDF input."""
    return _hkdf(ss_x + ss_k, b"INV1 hybrid KEK" + eph_pub + mlkem_ct + rx_pub + rk_pub, salt=b"INV1")


# ---------------------------------------------------------------- sealing / opening
def _seal(plaintext: bytes, kek: bytes, header_prefix_builder, flags: int, max_plaintext: int) -> bytes:
    """header_prefix_builder(kek_commit) -> header bytes (base + block)."""
    if len(plaintext) > max_plaintext:
        raise ValueError("plaintext larger than max_plaintext")
    header = header_prefix_builder(_commit(kek, b"kek"))
    dek = os.urandom(32)
    wrap_nonce = os.urandom(12)
    wrapped = AESGCM(kek).encrypt(wrap_nonce, dek + _commit(dek, b"dek"), header)
    body_nonce = os.urandom(12)
    pre = header + wrap_nonce + wrapped + body_nonce
    body = AESGCM(dek).encrypt(body_nonce, plaintext, pre + _LEN.pack(len(plaintext) + 16))
    return pre + _LEN.pack(len(body)) + body


def _precheck(blob: bytes, header_len: int, max_plaintext: int) -> tuple[int, int]:
    """Cheap structural checks. Called BEFORE any key derivation so a malformed file never costs Argon2
    time or memory (AUDIT_004 F1). Returns (need, body_len)."""
    need = header_len + 12 + _WRAP_CT + 12 + _LEN.size
    if len(blob) < need:
        raise FormatError("file truncated")
    (body_len,) = _LEN.unpack(blob[need - _LEN.size:need])
    if body_len < 16 or body_len > max_plaintext + OVERHEAD_SLACK + 16:
        raise FormatError("body length out of bounds")
    if len(blob) != need + body_len:
        raise FormatError("file truncated or has trailing data")
    return need, body_len


def _open(blob: bytes, header_len: int, kek: bytes, max_plaintext: int) -> tuple[bytes, int]:
    """Validate commitments, unwrap DEK, decrypt body. Returns (payload, flags)."""
    pos = header_len
    need, body_len = _precheck(blob, header_len, max_plaintext)
    header = blob[:header_len]
    wrap_nonce = blob[pos:pos + 12]
    wrapped = blob[pos + 12:pos + 12 + _WRAP_CT]
    body_nonce = blob[pos + 12 + _WRAP_CT:pos + 24 + _WRAP_CT]
    kek_commit = header[-32:] if header[5] == MODE_PASSPHRASE else header[_BASE.size + 32 + MLKEM_CT_LEN:_BASE.size + 64 + MLKEM_CT_LEN]
    if not hmac.compare_digest(kek_commit, _commit(kek, b"kek")):
        raise DecryptError("cannot decrypt (wrong key or damaged file)")
    try:
        unwrapped = AESGCM(kek).decrypt(wrap_nonce, wrapped, header)
        dek, dek_commit = unwrapped[:32], unwrapped[32:]
        if not hmac.compare_digest(dek_commit, _commit(dek, b"dek")):
            raise DecryptError("cannot decrypt (wrong key or damaged file)")
        body = blob[need:]
        pre = blob[:need - _LEN.size]
        payload = AESGCM(dek).decrypt(body_nonce, body, pre + _LEN.pack(body_len))
    except InvalidTag:
        raise DecryptError("cannot decrypt (wrong key or damaged file)") from None
    return payload, header[6]


def _finish(payload: bytes, flags: int, max_plaintext: int) -> bytes:
    if flags & FLAG_COMPRESSED:
        from infinity_core import IntegrityError, decompress_bytes  # bounded, audited decoder
        try:
            return decompress_bytes(payload, max_output=max_plaintext)
        except IntegrityError:
            raise DecryptError("cannot decrypt (wrong key or damaged file)") from None
    if len(payload) > max_plaintext:
        raise FormatError("plaintext larger than max_plaintext")
    return payload


def _prepare(data: bytes, compress: bool, max_plaintext: int) -> tuple[bytes, int]:
    if len(data) > max_plaintext:  # limit applies to the ORIGINAL data, before any compression
        raise ValueError("plaintext larger than max_plaintext")
    if not compress:
        return data, 0
    from infinity_core import compress_bytes
    return compress_bytes("zstd-19", data), FLAG_COMPRESSED


# ---------------------------------------------------------------- mode 1: passphrase
def encrypt_with_passphrase(data: bytes, passphrase: str, *, kdf: KdfParams | None = None,
                            compress: bool = False, max_plaintext: int = DEFAULT_MAX_PLAINTEXT) -> bytes:
    """compress=True compresses BEFORE encrypting. Off by default: compressed length leaks information
    about content, which is dangerous if an attacker can influence part of the data (CRIME/BREACH style)."""
    pw = _norm_passphrase(passphrase)
    kdf = kdf or KdfParams()
    kdf.check()
    payload, flags = _prepare(data, compress, max_plaintext)
    salt = os.urandom(16)
    kek = _kek_from_passphrase(pw, salt, kdf)
    build = lambda commit: _BASE.pack(MAGIC, VERSION, MODE_PASSPHRASE, flags) + _PASS.pack(salt, kdf.m_kib, kdf.t, kdf.lanes, commit)  # noqa: E731
    return _seal(payload, kek, build, flags, max_plaintext + OVERHEAD_SLACK)


def _parse_base(blob: bytes, mode: int):
    if len(blob) < _BASE.size:
        raise FormatError("not an INV1 file")
    magic, version, m, flags = _BASE.unpack(blob[:_BASE.size])
    if magic != MAGIC:
        raise FormatError("not an INV1 file")
    if version != VERSION:
        raise FormatError(f"unsupported version {version}")
    if m != mode:
        raise FormatError("file was created in a different mode")
    if flags & ~KNOWN_FLAGS:
        raise FormatError("unknown flags")
    return flags


def decrypt_with_passphrase(blob: bytes, passphrase: str, *, max_plaintext: int = DEFAULT_MAX_PLAINTEXT,
                            max_kdf_kib: int = MAX_KDF_KIB) -> bytes:
    flags = _parse_base(blob, MODE_PASSPHRASE)
    hl = _BASE.size + _PASS.size
    if len(blob) < hl:
        raise FormatError("file truncated")
    salt, m_kib, t, lanes, _ = _PASS.unpack(blob[_BASE.size:hl])
    params = KdfParams(m_kib, t, lanes)
    params.check(max_kdf_kib)  # bounded BEFORE any expensive work
    _precheck(blob, hl, max_plaintext + OVERHEAD_SLACK)  # structure before Argon2 (AUDIT_004 F1)
    pw = _norm_passphrase(passphrase)
    kek = _kek_from_passphrase(pw, salt, params)
    payload, flags = _open(blob, hl, kek, max_plaintext + OVERHEAD_SLACK)
    return _finish(payload, flags, max_plaintext)


# ---------------------------------------------------------------- mode 2: hybrid (X25519 + ML-KEM-768)
@dataclass(frozen=True)
class RecipientPublic:
    x25519: bytes  # 32
    mlkem768: bytes  # 1184

    def __post_init__(self):
        if len(self.x25519) != 32 or len(self.mlkem768) != MLKEM_PK_LEN:
            raise ValueError("bad public key lengths")

    def to_bytes(self) -> bytes:
        return self.x25519 + self.mlkem768

    @staticmethod
    def from_bytes(b: bytes) -> "RecipientPublic":
        if len(b) != 32 + MLKEM_PK_LEN:
            raise ValueError("bad public key length")
        return RecipientPublic(b[:32], b[32:])

    def key_id(self) -> bytes:
        return hashlib.sha256(b"INV1 recipient id" + self.to_bytes()).digest()


class RecipientKeys:
    """Private half. Holds an X25519 key and an ML-KEM-768 seed. Persist only via export_private()."""

    def __init__(self, x_priv: x25519.X25519PrivateKey, k_priv: mlkem.MLKEM768PrivateKey):
        self._x, self._k = x_priv, k_priv

    @staticmethod
    def generate() -> "RecipientKeys":
        return RecipientKeys(x25519.X25519PrivateKey.generate(), mlkem.MLKEM768PrivateKey.generate())

    def public(self) -> RecipientPublic:
        return RecipientPublic(self._x.public_key().public_bytes_raw(), self._k.public_key().public_bytes_raw())

    def export_private(self, passphrase: str, *, kdf: KdfParams | None = None) -> bytes:
        """Private keys are stored as a mode-1 vault file: Argon2id + AES-256-GCM."""
        return encrypt_with_passphrase(self._x.private_bytes_raw() + self._k.private_bytes_raw(), passphrase, kdf=kdf)

    @staticmethod
    def import_private(blob: bytes, passphrase: str, *, max_kdf_kib: int = MAX_KDF_KIB) -> "RecipientKeys":
        raw = decrypt_with_passphrase(blob, passphrase, max_plaintext=4096, max_kdf_kib=max_kdf_kib)
        if len(raw) != 96:  # same error as a wrong passphrase: no oracle (AUDIT_004 F4)
            raise DecryptError("cannot decrypt (wrong key or damaged file)")
        return RecipientKeys(x25519.X25519PrivateKey.from_private_bytes(raw[:32]),
                             mlkem.MLKEM768PrivateKey.from_seed_bytes(raw[32:]))


def encrypt_for_recipient(data: bytes, recipient: RecipientPublic, *, compress: bool = False,
                          max_plaintext: int = DEFAULT_MAX_PLAINTEXT) -> bytes:
    payload, flags = _prepare(data, compress, max_plaintext)
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    try:
        ss_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(recipient.x25519))
    except ValueError:  # low-order / invalid public key (AUDIT_004 F5)
        raise VaultError("invalid recipient public key") from None
    ss_k, mlkem_ct = mlkem.MLKEM768PublicKey.from_public_bytes(recipient.mlkem768).encapsulate()
    kek = _hybrid_kek(ss_x, ss_k, eph_pub, mlkem_ct, recipient.x25519, recipient.mlkem768)
    rid = recipient.key_id()
    build = lambda commit: _BASE.pack(MAGIC, VERSION, MODE_HYBRID, flags) + _HYB.pack(eph_pub, mlkem_ct, commit, rid)  # noqa: E731
    return _seal(payload, kek, build, flags, max_plaintext + OVERHEAD_SLACK)


def decrypt_for_recipient(blob: bytes, keys: RecipientKeys, *, max_plaintext: int = DEFAULT_MAX_PLAINTEXT) -> bytes:
    _parse_base(blob, MODE_HYBRID)
    hl = _BASE.size + _HYB.size
    if len(blob) < hl:
        raise FormatError("file truncated")
    eph_pub, mlkem_ct, _commit_stored, rid = _HYB.unpack(blob[_BASE.size:hl])
    _precheck(blob, hl, max_plaintext + OVERHEAD_SLACK)
    pub = keys.public()
    if not hmac.compare_digest(rid, pub.key_id()):
        raise DecryptError("cannot decrypt (wrong key or damaged file)")
    try:
        ss_x = keys._x.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))
    except ValueError:  # low-order or invalid point
        raise DecryptError("cannot decrypt (wrong key or damaged file)") from None
    ss_k = keys._k.decapsulate(mlkem_ct)  # implicit rejection: a bad ciphertext yields an unrelated secret
    kek = _hybrid_kek(ss_x, ss_k, eph_pub, mlkem_ct, pub.x25519, pub.mlkem768)
    payload, flags = _open(blob, hl, kek, max_plaintext + OVERHEAD_SLACK)
    return _finish(payload, flags, max_plaintext)
