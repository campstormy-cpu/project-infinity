"""Integrity tests. Success is asserted on hashes and bytes, never inferred from
the absence of errors."""
import hashlib
import random

import pytest

from infinity_core import (
    CODECS, HEADER_SIZE, IntegrityError, check_recovery, compress_bytes,
    compress_file, decompress_bytes, decompress_file, files_byte_identical,
    sha256_bytes, sha256_file, verify_exact_recovery,
)

rng = random.Random(7)
SAMPLES = {
    "empty": b"",
    "one_byte": b"\x00",
    "zeros": bytes(100_000),
    "random": rng.randbytes(50_000),
    "text": (b"hello infinity, lossless means bit exact. " * 2000),
    "all_byte_values": bytes(range(256)) * 50,
}


def test_sha256_known_vector():
    # NIST test vector for "abc"
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_file_matches_hashlib(tmp_path):
    p = tmp_path / "f.bin"
    data = rng.randbytes(3 * 1024 * 1024 + 17)  # crosses chunk boundaries
    p.write_bytes(data)
    assert sha256_file(p) == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("codec", sorted(CODECS))
@pytest.mark.parametrize("sample", sorted(SAMPLES))
def test_roundtrip_bytes(codec, sample):
    data = SAMPLES[sample]
    out = decompress_bytes(compress_bytes(codec, data))
    assert out == data
    assert sha256_bytes(out) == sha256_bytes(data)


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_roundtrip_files_and_verify(codec, tmp_path):
    src = tmp_path / "orig.bin"
    src.write_bytes(SAMPLES["text"])
    before = sha256_file(src)
    blob = tmp_path / "x.inf"
    out = tmp_path / "recovered.bin"
    compress_file(codec, src, blob)
    decompress_file(blob, out)
    res = check_recovery(src, out)
    assert res.ok and res.hash_match and res.byte_identical
    assert res.size_original == res.size_reconstructed == len(SAMPLES["text"])
    assert verify_exact_recovery(src, out) is True
    assert sha256_file(src) == before  # original preserved


def test_verify_detects_single_bit_difference(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    data = bytearray(rng.randbytes(10_000))
    a.write_bytes(bytes(data))
    data[5000] ^= 0x01
    b.write_bytes(bytes(data))
    assert verify_exact_recovery(a, b) is False
    assert files_byte_identical(a, b) is False


def test_verify_detects_truncation_and_extension(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"abcdef")
    b.write_bytes(b"abcde")
    assert verify_exact_recovery(a, b) is False
    b.write_bytes(b"abcdefg")
    assert verify_exact_recovery(a, b) is False


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_tampered_payload_is_rejected(codec):
    blob = bytearray(compress_bytes(codec, SAMPLES["text"]))
    blob[-5] ^= 0xFF
    with pytest.raises(IntegrityError):
        decompress_bytes(bytes(blob))


def test_tampered_hash_header_is_rejected():
    blob = bytearray(compress_bytes("zlib-9", SAMPLES["text"]))
    blob[20] ^= 0x01  # inside the stored SHA-256
    with pytest.raises(IntegrityError):
        decompress_bytes(bytes(blob))


def test_bad_magic_and_short_blob_rejected():
    with pytest.raises(IntegrityError):
        decompress_bytes(b"short")
    blob = bytearray(compress_bytes("zlib-9", b"x"))
    blob[0] ^= 1
    with pytest.raises(IntegrityError):
        decompress_bytes(bytes(blob))


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_compression_is_deterministic(codec):
    a = compress_bytes(codec, SAMPLES["text"])
    b = compress_bytes(codec, SAMPLES["text"])
    assert a == b


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_incompressible_data_does_not_shrink_FP01(codec):
    """THEORY FP-01: random data cannot shrink; the container header makes it grow."""
    data = SAMPLES["random"]
    assert len(compress_bytes(codec, data)) >= len(data) + HEADER_SIZE - 1  # codecs may add tiny framing, never save


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_redundant_data_does_shrink(codec):
    data = SAMPLES["zeros"]
    assert len(compress_bytes(codec, data)) < len(data) // 10
