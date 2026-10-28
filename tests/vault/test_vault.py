"""Tests for the INV1 prototype. They assert on outcomes (plaintext equality, specific exceptions),
and every security property has a test that would fail if the property were removed."""
import struct
import time
import unicodedata

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

import infinity_vault.vault as V
from infinity_vault import (
    DecryptError, FormatError, KdfParams, RecipientKeys, RecipientPublic, decrypt_for_recipient,
    decrypt_with_passphrase, encrypt_for_recipient, encrypt_with_passphrase,
)

FAST = KdfParams.fast_for_tests()
PW = "frase de prueba larga y unica"
PW2 = "otra frase de prueba distinta!"
LOW_KDF_CAP = 64  # KiB: keeps tampered Argon2 parameters from costing real memory in tests


def enc(data=b"contenido secreto", **kw):
    return encrypt_with_passphrase(data, PW, kdf=FAST, **kw)


def dec(blob, pw=PW, **kw):
    return decrypt_with_passphrase(blob, pw, max_kdf_kib=LOW_KDF_CAP, **kw)


@pytest.fixture(scope="module")
def keys():
    return RecipientKeys.generate()


# ------------------------------------------------------------------ round trips
@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1000, 1 << 20])
@pytest.mark.parametrize("compress", [False, True])
def test_passphrase_roundtrip(size, compress):
    data = (b"abc" * (size // 3 + 1))[:size]
    assert dec(enc(data, compress=compress)) == data


@pytest.mark.parametrize("compress", [False, True])
def test_hybrid_roundtrip(keys, compress):
    data = b"para el destinatario " * 500
    assert decrypt_for_recipient(encrypt_for_recipient(data, keys.public(), compress=compress), keys) == data


def test_randomized_output_same_input():
    a, b = enc(), enc()
    assert a != b
    assert a[7:23] != b[7:23]  # fresh salt each time


def test_plaintext_not_visible_in_blob():
    marker = b"MARCADOR-UNICO-1234567890"
    assert marker not in enc(marker * 4)
    assert marker not in enc(marker * 4, compress=True)


# ------------------------------------------------------------------ wrong key
def test_wrong_passphrase_fails_generically():
    with pytest.raises(DecryptError, match="wrong key or damaged"):
        dec(enc(), PW2)


def test_wrong_recipient_fails(keys):
    blob = encrypt_for_recipient(b"x" * 100, keys.public())
    with pytest.raises(DecryptError):
        decrypt_for_recipient(blob, RecipientKeys.generate())


def test_hybrid_needs_both_halves(keys):
    """If either KEM half is wrong the file must not open: an attacker must break BOTH."""
    blob = encrypt_for_recipient(b"x" * 100, keys.public())
    other = RecipientKeys.generate()
    for mixed in (RecipientKeys(keys._x, other._k), RecipientKeys(other._x, keys._k)):
        # keep the recipient id consistent with the real recipient so the id check cannot be what rejects it
        mixed.public = lambda p=keys.public(): p
        with pytest.raises(DecryptError):
            decrypt_for_recipient(blob, mixed)


# ------------------------------------------------------------------ tampering
def flip(blob, i, bit=0):
    b = bytearray(blob)
    b[i] ^= 1 << bit
    return bytes(b)


def test_every_byte_of_a_passphrase_file_is_protected():
    blob = enc(b"datos importantes " * 5)
    for i in range(len(blob)):
        with pytest.raises((DecryptError, FormatError)):
            dec(flip(blob, i))


def test_every_bit_of_the_fixed_header_and_wrap_is_protected():
    blob = enc(b"datos importantes " * 5)
    for i in range(0, 7 + V._PASS.size + 12 + V._WRAP_CT):
        for bit in range(8):
            with pytest.raises((DecryptError, FormatError)):
                dec(flip(blob, i, bit))


def test_hybrid_tampering_is_detected(keys):
    blob = encrypt_for_recipient(b"datos importantes " * 5, keys.public())
    positions = list(range(0, 7 + V._HYB.size + 24 + V._WRAP_CT + 8, 13)) + list(range(len(blob) - 40, len(blob)))
    for i in positions:
        with pytest.raises((DecryptError, FormatError)):
            decrypt_for_recipient(flip(blob, i), keys)


def test_mlkem_ciphertext_tamper_is_rejected(keys):
    blob = encrypt_for_recipient(b"x" * 50, keys.public())
    start = 7 + 32
    for off in (0, 100, V.MLKEM_CT_LEN - 1):
        with pytest.raises(DecryptError):
            decrypt_for_recipient(flip(blob, start + off), keys)


def test_truncation_at_every_length_fails():
    blob = enc(b"datos " * 20)
    for n in range(len(blob)):
        with pytest.raises((DecryptError, FormatError)):
            dec(blob[:n])


@pytest.mark.parametrize("tail", [b"\x00", b"junk", b"\x00" * 100])
def test_trailing_data_fails(tail):
    with pytest.raises((DecryptError, FormatError)):
        dec(enc() + tail)


def test_splicing_parts_of_two_files_fails():
    a = encrypt_with_passphrase(b"A" * 64, PW, kdf=FAST)
    b = encrypt_with_passphrase(b"B" * 64, PW, kdf=FAST)
    hl = 7 + V._PASS.size
    with pytest.raises((DecryptError, FormatError)):
        dec(a[:hl] + b[hl:])  # header of a, rest of b
    with pytest.raises((DecryptError, FormatError)):
        dec(b[:hl + 12 + V._WRAP_CT] + a[hl + 12 + V._WRAP_CT:])  # a's body under b's wrapped key


def test_header_is_authenticated_not_just_the_body():
    """Changing only the (non-secret) KDF cost fields must be caught, not silently accepted."""
    blob = bytearray(enc())
    t_offset = 7 + 16 + 4
    blob[t_offset + 3] = 2  # t: 1 -> 2
    with pytest.raises(DecryptError):
        dec(bytes(blob))


def test_flags_are_authenticated():
    blob = bytearray(enc())
    blob[6] = V.FLAG_COMPRESSED
    with pytest.raises((DecryptError, FormatError)):
        dec(bytes(blob))


# ------------------------------------------------------------------ key commitment
def test_key_commitment_rejects_before_any_decryption(monkeypatch):
    blob = bytearray(enc())
    blob[7 + V._PASS.size - 1] ^= 1  # last byte of kek_commit
    calls = []
    real = V.AESGCM.decrypt
    monkeypatch.setattr(V.AESGCM, "decrypt", lambda *a, **k: calls.append(1) or real(*a, **k))
    with pytest.raises(DecryptError):
        dec(bytes(blob))
    assert calls == [], "AEAD decryption must not run when the key commitment already failed"


def test_dek_commitment_is_enforced():
    """Build a file whose wrapped payload carries a wrong dek_commit: GCM alone would accept it."""
    kek = bytes(range(32))
    salt = bytes(16)
    p = FAST
    from infinity_vault.vault import _BASE, _PASS, _LEN, _commit, MAGIC, VERSION, MODE_PASSPHRASE
    pw = PW
    real_kek = V._kek_from_passphrase(V._norm_passphrase(pw), salt, p)
    header = _BASE.pack(MAGIC, VERSION, MODE_PASSPHRASE, 0) + _PASS.pack(salt, p.m_kib, p.t, p.lanes, _commit(real_kek, b"kek"))
    dek = bytes(32)
    wn, bn = bytes(12), bytes(12)
    wrapped = AESGCM(real_kek).encrypt(wn, dek + bytes(32), header)  # wrong dek_commit (zeros)
    pre = header + wn + wrapped + bn
    body = AESGCM(dek).encrypt(bn, b"hola", pre + _LEN.pack(20))
    with pytest.raises(DecryptError):
        dec(pre + _LEN.pack(len(body)) + body)


# ------------------------------------------------------------------ resource bounds (no header-driven DoS)
def test_huge_argon2_memory_in_header_is_rejected_fast():
    blob = bytearray(enc())
    struct.pack_into(">I", blob, 7 + 16, 2 ** 31 - 1)  # m_kib ~ 2 TiB
    t0 = time.perf_counter()
    with pytest.raises(FormatError):
        decrypt_with_passphrase(bytes(blob), PW)  # default cap, not the test cap
    assert time.perf_counter() - t0 < 1


@pytest.mark.parametrize("field,val", [(7 + 20, 11), (7 + 20, 0), (7 + 24, 17), (7 + 24, 0)])
def test_other_kdf_bounds(field, val):
    blob = bytearray(enc())
    if field == 7 + 20:
        struct.pack_into(">I", blob, field, val)
    else:
        blob[field] = val
    with pytest.raises(FormatError):
        dec(bytes(blob))


def test_body_length_bound_checked_before_allocation():
    blob = bytearray(enc())
    off = 7 + V._PASS.size + 12 + V._WRAP_CT + 12
    struct.pack_into(">Q", blob, off, 2 ** 62)
    with pytest.raises(FormatError):
        dec(bytes(blob))


def test_max_plaintext_enforced_on_encrypt_and_decrypt():
    with pytest.raises(ValueError):
        encrypt_with_passphrase(b"x" * 101, PW, kdf=FAST, max_plaintext=100)
    with pytest.raises(ValueError):  # limit applies to the original, not the compressed size
        encrypt_with_passphrase(bytes(101), PW, kdf=FAST, max_plaintext=100, compress=True)
    blob = enc(b"x" * 5000)
    with pytest.raises(FormatError):
        dec(blob, max_plaintext=100)


def test_compression_bomb_inside_a_valid_file_is_bounded():
    """An authenticated file can still contain a hostile compressed payload: the decoder cap applies."""
    from infinity_core import compress_bytes
    bomb = compress_bytes("zlib-9", bytes(50 * 1024 * 1024))
    kek = V._kek_from_passphrase(V._norm_passphrase(PW), bytes(16), FAST)
    from infinity_vault.vault import _BASE, _PASS, MAGIC, VERSION, MODE_PASSPHRASE, _commit
    sealed = V._seal(bomb, kek, lambda c: _BASE.pack(MAGIC, VERSION, MODE_PASSPHRASE, V.FLAG_COMPRESSED)
                     + _PASS.pack(bytes(16), FAST.m_kib, FAST.t, FAST.lanes, c), V.FLAG_COMPRESSED, 1 << 30)
    with pytest.raises((DecryptError, FormatError)):
        dec(sealed, max_plaintext=1024 * 1024)


# ------------------------------------------------------------------ format errors
def test_not_a_vault_and_wrong_mode(keys):
    with pytest.raises(FormatError):
        dec(b"")
    with pytest.raises(FormatError):
        dec(b"NOPE" + bytes(100))
    with pytest.raises(FormatError):
        dec(encrypt_for_recipient(b"x", keys.public()))
    with pytest.raises(FormatError):
        decrypt_for_recipient(enc(), keys)


def test_unknown_version_and_flags_rejected():
    blob = bytearray(enc())
    blob[4] = 2
    with pytest.raises(FormatError):
        dec(bytes(blob))
    blob = bytearray(enc())
    blob[6] = 0x80
    with pytest.raises(FormatError):
        dec(bytes(blob))


# ------------------------------------------------------------------ passphrase handling
def test_short_passphrase_rejected():
    with pytest.raises(ValueError):
        encrypt_with_passphrase(b"x", "corta", kdf=FAST)
    with pytest.raises(ValueError):
        dec(enc(), "corta")


def test_unicode_normalization_equivalence():
    composed = "contraseña-café-larga-1"
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed
    assert dec(encrypt_with_passphrase(b"ok", composed, kdf=FAST), decomposed) == b"ok"


# ------------------------------------------------------------------ key export
def test_private_key_export_import_roundtrip(keys):
    blob = keys.export_private(PW, kdf=FAST)
    back = RecipientKeys.import_private(blob, PW, max_kdf_kib=LOW_KDF_CAP)
    assert back.public() == keys.public()
    msg = encrypt_for_recipient(b"mensaje", keys.public())
    assert decrypt_for_recipient(msg, back) == b"mensaje"
    with pytest.raises(DecryptError):
        RecipientKeys.import_private(blob, PW2, max_kdf_kib=LOW_KDF_CAP)


def test_exported_private_keys_are_not_in_plaintext(keys):
    blob = keys.export_private(PW, kdf=FAST)
    assert keys._x.private_bytes_raw() not in blob and keys._k.private_bytes_raw() not in blob


def test_public_key_serialization(keys):
    pub = keys.public()
    assert RecipientPublic.from_bytes(pub.to_bytes()) == pub
    with pytest.raises(ValueError):
        RecipientPublic.from_bytes(b"short")


def test_low_order_ephemeral_point_is_rejected_cleanly(keys):
    blob = bytearray(encrypt_for_recipient(b"x", keys.public()))
    blob[7:39] = bytes(32)  # all-zero X25519 public value
    with pytest.raises(DecryptError):
        decrypt_for_recipient(bytes(blob), keys)


def test_decrypt_limit_applies_even_within_the_overhead_slack():
    """2000 bytes with a 1000-byte cap is below the loose length bound, so only the plaintext check can reject it."""
    blob = enc(b"x" * 2000)
    with pytest.raises(FormatError):
        dec(blob, max_plaintext=1000)
    assert len(dec(blob, max_plaintext=2000)) == 2000


def test_clearing_the_compressed_flag_cannot_return_wrong_data():
    """Without header authentication, flipping flag 1 -> 0 would silently return the still-compressed
    bytes as if they were the file. This is the property the header AAD exists for."""
    original = b"contenido muy repetido " * 200
    blob = bytearray(enc(original, compress=True))
    assert blob[6] == V.FLAG_COMPRESSED
    blob[6] = 0
    with pytest.raises((DecryptError, FormatError)):
        dec(bytes(blob))


def test_clearing_the_compressed_flag_in_hybrid_mode(keys):
    blob = bytearray(encrypt_for_recipient(b"repetido " * 300, keys.public(), compress=True))
    blob[6] = 0
    with pytest.raises((DecryptError, FormatError)):
        decrypt_for_recipient(bytes(blob), keys)


def test_mode_mismatch_gives_a_clear_error(keys):
    with pytest.raises(FormatError, match="different mode"):
        dec(encrypt_for_recipient(b"x", keys.public()))
    with pytest.raises(FormatError, match="different mode"):
        decrypt_for_recipient(enc(), keys)


# ------------------------------------------------------------------ AUDIT_004 regressions
def test_malformed_file_with_huge_kdf_params_is_rejected_before_argon2():  # F1
    hdr = struct.pack(">4sBBB", b"INV1", 1, 1, 0) + struct.pack(">16sIIB32s", b"s" * 16, V.MAX_KDF_KIB, 10, 16, b"c" * 32)
    t = time.monotonic()
    with pytest.raises(FormatError):
        decrypt_with_passphrase(hdr + b"x" * 8, PW)
    assert time.monotonic() - t < 0.2


def test_passphrase_length_counted_after_normalization():  # F2
    with pytest.raises(ValueError):
        encrypt_with_passphrase(b"x", "é" * 6, kdf=FAST)  # 12 code points, 6 after NFKC


def test_lone_surrogate_passphrase_is_a_clean_error():  # F3
    with pytest.raises(ValueError):
        encrypt_with_passphrase(b"x", "abcdefghijkl\ud800", kdf=FAST)


def test_low_order_recipient_key_is_a_vault_error(keys):  # F5
    bad = RecipientPublic(b"\x00" * 32, keys.public().mlkem768)
    with pytest.raises(V.VaultError):
        encrypt_for_recipient(b"x", bad)


def test_non_key_vault_imported_as_keys_gives_same_error_as_wrong_passphrase():  # F4
    blob = encrypt_with_passphrase(b"not a key", PW, kdf=FAST)
    with pytest.raises(DecryptError):
        RecipientKeys.import_private(blob, PW, max_kdf_kib=LOW_KDF_CAP)
    with pytest.raises(DecryptError):
        RecipientKeys.import_private(blob, PW2, max_kdf_kib=LOW_KDF_CAP)
