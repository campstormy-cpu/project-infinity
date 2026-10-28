"""Seeded, deterministic fuzzing of the INV1 reader. Property: for ANY input the decoders either return
the original plaintext (only for the untouched blob) or raise VaultError. Never another exception type,
never wrong plaintext, never a hang."""
import random
import time

import pytest

from infinity_vault import (
    KdfParams, RecipientKeys, VaultError, decrypt_for_recipient, decrypt_with_passphrase,
    encrypt_for_recipient, encrypt_with_passphrase,
)

FAST = KdfParams.fast_for_tests()
PW = "frase de prueba larga y unica"
DATA = b"contenido secreto " * 20
CAP = 64  # KiB cap so mutated KDF params stay cheap


@pytest.fixture(scope="module")
def keys():
    return RecipientKeys.generate()


def mutate(rng: random.Random, blob: bytes) -> bytes:
    b = bytearray(blob)
    k = rng.choice(["flip", "set", "trunc", "extend", "splice", "dup"])
    if k == "flip":
        for _ in range(rng.randint(1, 4)):
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
    elif k == "set":
        b[rng.randrange(len(b))] = rng.choice([0, 0xFF, 0x7F, 0x80])
    elif k == "trunc":
        b = b[: rng.randrange(len(b))]
    elif k == "extend":
        b += rng.randbytes(rng.randint(1, 64))
    elif k == "splice":
        i = rng.randrange(len(b))
        b[i:i] = rng.randbytes(rng.randint(1, 16))
    else:
        i = rng.randrange(len(b))
        b[i:i + 8] = b[:8]
    return bytes(b)


def check(fn, blob, original_blob):
    t = time.monotonic()
    try:
        out = fn(blob)
    except VaultError:
        out = None
    assert time.monotonic() - t < 5, "decoder too slow on mutated input"
    if out is not None:
        assert blob == original_blob and out == DATA, "mutated blob decrypted"


@pytest.mark.parametrize("compress", [False, True])
def test_fuzz_passphrase(compress):
    rng = random.Random(1234)
    blob = encrypt_with_passphrase(DATA, PW, kdf=FAST, compress=compress)
    dec = lambda x: decrypt_with_passphrase(x, PW, max_kdf_kib=CAP)
    check(dec, blob, blob)
    for _ in range(400):
        check(dec, mutate(rng, blob), blob)


def test_fuzz_hybrid(keys):
    rng = random.Random(4321)
    blob = encrypt_for_recipient(DATA, keys.public())
    dec = lambda x: decrypt_for_recipient(x, keys)
    check(dec, blob, blob)
    for _ in range(300):
        check(dec, mutate(rng, blob), blob)


def test_fuzz_random_garbage():
    rng = random.Random(7)
    for n in [0, 1, 4, 5, 8, 40, 200, 2000]:
        for _ in range(20):
            junk = rng.randbytes(n)
            with pytest.raises(VaultError):
                decrypt_with_passphrase(junk, PW, max_kdf_kib=CAP)
