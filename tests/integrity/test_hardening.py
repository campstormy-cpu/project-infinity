"""Hardening tests added after AUDIT_REPORT.md findings F-02, F-04, F-07.
They were written to FAIL against the pre-fix code where applicable."""
import bz2
import lzma
import struct
import time
import tracemalloc
import zlib

import brotli
import pytest
import zstandard

import infinity_core.integrity as integ
from infinity_core import CODECS, IntegrityError, compress_bytes, decompress_bytes, verify_exact_recovery
from infinity_core.container import MAGIC, _HEADER

SAMPLE = b"hardening sample text, lossless means bit exact. " * 500


def forged(codec_name: str, payload: bytes, declared_len: int) -> bytes:
    return _HEADER.pack(MAGIC, CODECS[codec_name].codec_id, declared_len, bytes(32)) + payload


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_decompression_bomb_is_bounded_F02(codec):
    bomb_payload = CODECS[codec].compress(bytes(8 * 1024 * 1024))  # tiny payload, 8 MiB of output
    blob = forged(codec, bomb_payload, 1000)  # header lies: claims 1000 bytes
    tracemalloc.start()
    t0 = time.perf_counter()
    with pytest.raises(IntegrityError):
        decompress_bytes(blob)
    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    # lzma legitimately allocates its 64 MiB dictionary (preset 9); output itself must stay tiny.
    # zstd keeps its 8 MiB window plus at most one input chunk's worth of output.
    allowance = {"lzma-9e": 70, "zstd-19": 24}.get(codec, 2) * 1024 * 1024
    assert peak < allowance, f"decoder allocated {peak} bytes for a 1000-byte declaration"
    assert elapsed < 5


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_absurd_declared_length_rejected_without_allocation_F02(codec):
    blob = forged(codec, CODECS[codec].compress(b"x"), 2 ** 40)
    tracemalloc.start()
    with pytest.raises(IntegrityError):
        decompress_bytes(blob)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 1024 * 1024


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_max_output_parameter_enforced(codec):
    blob = compress_bytes(codec, SAMPLE)
    with pytest.raises(IntegrityError):
        decompress_bytes(blob, max_output=len(SAMPLE) - 1)
    assert decompress_bytes(blob, max_output=len(SAMPLE)) == SAMPLE


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_trailing_bytes_rejected_F07(codec):
    blob = compress_bytes(codec, SAMPLE)
    with pytest.raises(IntegrityError):
        decompress_bytes(blob + b"JUNK")


@pytest.mark.parametrize("codec", sorted(CODECS))
@pytest.mark.parametrize("cut", [1, 3, 20])
def test_truncated_payload_rejected(codec, cut):
    blob = compress_bytes(codec, SAMPLE)
    with pytest.raises(IntegrityError):
        decompress_bytes(blob[:-cut])


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_empty_input_roundtrip_still_strict(codec):
    blob = compress_bytes(codec, b"")
    assert decompress_bytes(blob) == b""
    with pytest.raises(IntegrityError):
        decompress_bytes(blob + b"X")


def test_byte_compare_sees_difference_after_first_chunk_F04(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    data = bytearray(3 * 1024 * 1024)
    a.write_bytes(bytes(data))
    data[-1] = 1  # differs only in the last byte, beyond the 1 MiB chunk
    b.write_bytes(bytes(data))
    assert integ.files_byte_identical(a, b) is False
    data[1024 * 1024 + 5] = 9
    b.write_bytes(bytes(data))
    assert integ.files_byte_identical(a, b) is False
    assert integ.files_byte_identical(a, a) is True


def test_verify_byte_leg_works_independently_of_hash_F04(tmp_path, monkeypatch):
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"AAAA")
    b.write_bytes(b"AAAB")
    monkeypatch.setattr(integ, "sha256_file", lambda p: "same")  # hash leg is fooled
    assert verify_exact_recovery(a, b) is False


def test_verify_hash_leg_works_independently_of_bytes_F04(tmp_path, monkeypatch):
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"AAAA")
    b.write_bytes(b"AAAB")
    monkeypatch.setattr(integ, "files_byte_identical", lambda x, y: True)  # byte leg is fooled
    assert verify_exact_recovery(a, b) is False


def test_verify_size_leg_works_independently_F04(tmp_path, monkeypatch):
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"AAAA")
    b.write_bytes(b"AAAAA")
    monkeypatch.setattr(integ, "sha256_file", lambda p: "same")
    monkeypatch.setattr(integ, "files_byte_identical", lambda x, y: True)
    assert verify_exact_recovery(a, b) is False


def test_codec_parameters_are_pinned_F04():
    """Each baseline must equal an independent library call with its documented parameters
    and differ from a weaker setting, so a silent downgrade (e.g. zstd 19 -> 3) fails."""
    hdr = 45
    data = SAMPLE * 20
    payload = lambda name: compress_bytes(name, data)[hdr:]  # noqa: E731
    assert payload("zstd-19") == zstandard.ZstdCompressor(level=19, threads=0).compress(data)
    assert payload("zstd-19") != zstandard.ZstdCompressor(level=3, threads=0).compress(data)
    assert payload("zlib-9") == zlib.compress(data, 9)
    assert payload("zlib-9") != zlib.compress(data, 1)
    assert payload("bz2-9") == bz2.compress(data, 9)
    assert payload("bz2-9") != bz2.compress(data, 1)
    assert payload("lzma-9e") == lzma.compress(data, format=lzma.FORMAT_XZ, preset=9 | lzma.PRESET_EXTREME)
    assert payload("lzma-9e") != lzma.compress(data, format=lzma.FORMAT_XZ, preset=0)
    assert payload("brotli-11") == brotli.compress(data, quality=11)
    assert payload("brotli-11") != brotli.compress(data, quality=1)


def test_brotli_external_dependency_is_disclosed_FP07():
    assert CODECS["brotli-11"].external_dependency
    for name in ("zlib-9", "bz2-9", "lzma-9e", "zstd-19"):
        assert CODECS[name].external_dependency is None


def test_lzma_dictionary_memory_request_is_refused_F02():
    big = lzma.compress(b"x" * 1000, format=lzma.FORMAT_XZ,
                        filters=[{"id": lzma.FILTER_LZMA2, "preset": 1, "dict_size": 200 * 1024 * 1024}])
    with pytest.raises(IntegrityError):
        decompress_bytes(forged("lzma-9e", big, 1000))


def test_zstd_oversized_window_request_is_refused_F02():
    params = zstandard.ZstdCompressionParameters.from_level(1, window_log=27)
    cobj = zstandard.ZstdCompressor(compression_params=params).compressobj()
    big = cobj.compress(b"x" * 1000) + cobj.flush()
    with pytest.raises(IntegrityError):
        decompress_bytes(forged("zstd-19", big, 1000))
