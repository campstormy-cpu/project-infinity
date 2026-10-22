"""Second hardening round (AUDIT_002 N-05, N06, N07, N09, N10, N20).

AUDIT_002 showed that several first-round tests could not fail: they forged a zero SHA-256 (so the
decode was rejected for that reason alone) or used tracemalloc, which cannot see C-library allocations.
Here:
  * limit tests use a header with the TRUE hash and length, so the only thing that can reject the
    container is the limit under test;
  * memory is measured as peak RSS growth in a fresh subprocess.
"""
import bz2
import functools
import lzma
import random
import subprocess
import sys
import zlib
from pathlib import Path

import brotli
import pytest
import zstandard

from infinity_core import CODECS, IntegrityError, compress_bytes, decompress_bytes, sha256_bytes
from infinity_core.container import MAGIC, _HEADER

PKG = Path(__file__).resolve().parents[2] / "packages" / "compression-core"
BOMB_MIB = 128
RSS_LIMIT_MB = 64  # bounded decoders stay far below this; unbounded ones need >= BOMB_MIB


def real_header(codec_name: str, data: bytes) -> bytes:
    return _HEADER.pack(MAGIC, CODECS[codec_name].codec_id, len(data), bytes.fromhex(sha256_bytes(data)))


def fast_payload(codec: str, data: bytes) -> bytes:
    """Cheap-to-build payloads: the decoder does not care how a stream was produced."""
    return {
        "zlib-9": lambda: zlib.compress(data, 1),
        "bz2-9": lambda: bz2.compress(data, 1),
        "lzma-9e": lambda: lzma.compress(data, format=lzma.FORMAT_XZ, preset=1),
        "zstd-19": lambda: zstandard.ZstdCompressor(level=3).compress(data),
        "brotli-11": lambda: brotli.compress(data, quality=5),
    }[codec]()


def rss_growth_mb(blob_path: Path) -> tuple[str, float]:
    # VmHWM is the process's own peak RSS and starts fresh at exec. ru_maxrss is inherited from the
    # parent across exec, which hid all growth when the parent was already large (AUDIT_003 A3-01).
    code = f"""
import sys
sys.path.insert(0, {str(PKG)!r})
from infinity_core import decompress_bytes, IntegrityError
def hwm_mb():
    for line in open('/proc/self/status'):
        if line.startswith('VmHWM:'):
            return int(line.split()[1]) / 1024
blob = open({str(blob_path)!r}, 'rb').read()
base = hwm_mb()
try:
    decompress_bytes(blob); res = 'accepted'
except IntegrityError:
    res = 'rejected'
print(res, hwm_mb() - base)
"""
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True).stdout.split()
    return out[0], float(out[1])


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_bomb_rejected_with_bounded_rss(codec, tmp_path):
    payload = fast_payload(codec, bytes(BOMB_MIB * 1024 * 1024))
    assert len(payload) < 4 * 1024 * 1024  # it really is a small container for a huge output
    blob = tmp_path / "bomb.inf"
    blob.write_bytes(_HEADER.pack(MAGIC, CODECS[codec].codec_id, 1000, bytes(32)) + payload)  # header claims 1000 B
    verdict, growth = rss_growth_mb(blob)
    assert verdict == "rejected"
    assert growth < RSS_LIMIT_MB, f"{codec}: peak RSS grew {growth:.0f} MB on a 1000-byte declaration"


def test_default_output_cap_blocks_huge_declarations():
    blob = _HEADER.pack(MAGIC, CODECS["zlib-9"].codec_id, 2 ** 40, bytes(32)) + zlib.compress(b"x")
    with pytest.raises(IntegrityError, match="exceeds max_output"):
        decompress_bytes(blob)


def test_lzma_huge_dictionary_refused_with_valid_hash():
    data = b"x" * 1000
    big = lzma.compress(data, format=lzma.FORMAT_XZ,
                        filters=[{"id": lzma.FILTER_LZMA2, "preset": 1, "dict_size": 200 * 1024 * 1024}])
    assert lzma.decompress(big) == data  # the stream itself is perfectly valid
    with pytest.raises(IntegrityError):
        decompress_bytes(real_header("lzma-9e", data) + big)


def test_zstd_huge_window_refused_with_valid_hash():
    data = b"x" * 1000
    params = zstandard.ZstdCompressionParameters.from_level(1, window_log=27)
    cobj = zstandard.ZstdCompressor(compression_params=params).compressobj()
    big = cobj.compress(data) + cobj.flush()
    assert zstandard.ZstdDecompressor(max_window_size=1 << 28).decompressobj().decompress(big) == data
    with pytest.raises(IntegrityError):
        decompress_bytes(real_header("zstd-19", data) + big)


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_valid_stream_is_accepted_when_limits_are_not_hit(codec):
    data = b"limits must not reject honest data. " * 100
    assert decompress_bytes(compress_bytes(codec, data)) == data


@functools.lru_cache(maxsize=None)
def aligned_container(codec: str) -> bytes:
    """A container whose payload length is exactly 2048 bytes (a multiple of every decoder feed size)."""
    for n in range(1400, 2100):
        data = random.Random(n).randbytes(n)
        payload = CODECS[codec].compress(data)
        if len(payload) == 2048:
            return real_header(codec, data) + payload
    pytest.skip(f"no input size gave a 2048-byte payload for {codec}")


@pytest.mark.parametrize("codec", sorted(CODECS))
@pytest.mark.parametrize("tail", [b"J", b"\x00", b"\x00" * 5000, b"JUNK" * 300])
def test_trailing_data_rejected_even_when_chunk_aligned(codec, tail):
    blob = aligned_container(codec)
    assert len(blob) - 45 == 2048
    assert decompress_bytes(blob)  # untouched container is fine
    with pytest.raises(IntegrityError):
        decompress_bytes(blob + tail)


@pytest.mark.parametrize("codec", sorted(CODECS))
def test_second_valid_stream_appended_is_rejected(codec):
    data = b"stream" * 50
    blob = compress_bytes(codec, data)
    with pytest.raises(IntegrityError):
        decompress_bytes(blob + blob[45:])


def test_memoryerror_is_reported_as_integrity_error(monkeypatch):
    import infinity_core.container as c

    def boom(payload, n):
        raise MemoryError

    monkeypatch.setitem(c.CODECS_BY_ID, 1, c.CODECS_BY_ID[1].__class__(**{**c.CODECS_BY_ID[1].__dict__, "decompress": boom}))
    with pytest.raises(IntegrityError, match="out of memory"):
        decompress_bytes(compress_bytes("zlib-9", b"abc"))


def test_container_hash_is_integrity_not_authentication():
    """Documents the limit stated in container.py: a forger who recomputes the hash is accepted."""
    forged = b"attacker chosen content"
    blob = real_header("zlib-9", forged) + zlib.compress(forged, 9)
    assert decompress_bytes(blob) == forged


def test_default_output_cap_is_256_mib():
    from infinity_core.container import DEFAULT_MAX_OUTPUT
    assert DEFAULT_MAX_OUTPUT == 256 * 1024 * 1024
