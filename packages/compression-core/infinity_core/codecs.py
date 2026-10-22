"""Baseline lossless codecs.

All codecs here are standard, deterministic, single-threaded, and lossless.
They are the baselines that any experimental method must beat on
*complete stored bytes*.
"""
from __future__ import annotations

import bz2
import lzma
import zlib
from dataclasses import dataclass
from typing import Callable

import brotli
import zstandard


@dataclass(frozen=True)
class Codec:
    name: str
    codec_id: int
    params: str
    compress: Callable[[bytes], bytes]
    # decompress(payload, original_length)
    decompress: Callable[[bytes, int], bytes]


def _zstd_c(data: bytes) -> bytes:
    return zstandard.ZstdCompressor(level=19, threads=0).compress(data)


def _zstd_d(payload: bytes, n: int) -> bytes:
    return zstandard.ZstdDecompressor().decompress(payload, max_output_size=max(n, 1))


def _lzma_c(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_XZ, preset=9 | lzma.PRESET_EXTREME)


CODECS: dict[str, Codec] = {
    c.name: c
    for c in [
        Codec("zlib-9", 1, "level=9", lambda d: zlib.compress(d, 9), lambda p, n: zlib.decompress(p)),
        Codec("bz2-9", 2, "level=9", lambda d: bz2.compress(d, 9), lambda p, n: bz2.decompress(p)),
        Codec("lzma-9e", 3, "xz preset=9|extreme", _lzma_c, lambda p, n: lzma.decompress(p)),
        Codec("zstd-19", 4, "level=19", _zstd_c, _zstd_d),
        Codec("brotli-11", 5, "quality=11", lambda d: brotli.compress(d, quality=11), lambda p, n: brotli.decompress(p)),
    ]
}

CODECS_BY_ID = {c.codec_id: c for c in CODECS.values()}
