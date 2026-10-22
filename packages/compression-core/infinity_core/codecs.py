"""Baseline lossless codecs.

All codecs here are standard, deterministic, single-threaded, and lossless.
They are the baselines that any experimental method must beat on
*complete stored bytes*.

Decoders are strict and bounded: they reject truncated payloads and trailing
bytes after the compressed stream, and they stop once the output exceeds the
original length n declared in the container header (n + 1 bytes for zlib, bz2,
lzma and brotli). zstd is fed in small input chunks, so it can overshoot n by at
most one chunk's expansion (FEED_ZSTD bytes of input; measured, not zero). The
container also caps n itself (see container.DEFAULT_MAX_OUTPUT), so a crafted
header cannot request unbounded memory.

`external_dependency` records data a decoder needs that is NOT inside the stream
(THEORY FP-07). It is disclosed in every benchmark record.
"""
from __future__ import annotations

import bz2
import lzma
import zlib
from dataclasses import dataclass
from typing import Callable

import brotli
import zstandard

FEED = 1024  # input chunk size for the brotli streaming decoder (output is limited per call)
FEED_ZSTD = 64  # zstd has no output limit per call, so feed little input at a time


class DecodeError(Exception):
    pass


@dataclass(frozen=True)
class Codec:
    name: str
    codec_id: int
    params: str
    compress: Callable[[bytes], bytes]
    decompress: Callable[[bytes, int], bytes]  # (payload, original_length)
    external_dependency: str | None = None
    external_dependency_bytes: int | None = None  # size of embedded decoder data, if known


def _check_tail(n: int, out: bytes, eof: bool, unused: bytes) -> bytes:
    if not eof:
        raise DecodeError("truncated or unterminated stream")
    if unused:
        raise DecodeError("trailing bytes after compressed stream")
    if len(out) > n:
        raise DecodeError("output exceeds declared length")
    return out


def _zlib_d(p: bytes, n: int) -> bytes:
    d = zlib.decompressobj()
    out = d.decompress(p, n + 1)
    return _check_tail(n, out, d.eof, d.unused_data + d.unconsumed_tail)


def _bz2_d(p: bytes, n: int) -> bytes:
    d = bz2.BZ2Decompressor()
    out = d.decompress(p, max_length=n + 1)
    return _check_tail(n, out, d.eof, d.unused_data)


LZMA_MEMLIMIT = 128 * 1024 * 1024  # preset 9 needs ~65 MiB; a stream asking for more is refused


def _lzma_d(p: bytes, n: int) -> bytes:
    d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=LZMA_MEMLIMIT)
    out = d.decompress(p, max_length=n + 1)
    return _check_tail(n, out, d.eof, d.unused_data)


def _zstd_c(data: bytes) -> bytes:
    return zstandard.ZstdCompressor(level=19, threads=0).compress(data)


ZSTD_MAX_WINDOW = 32 * 1024 * 1024  # level 19 uses an 8 MiB window; larger requests are refused


def _zstd_d(p: bytes, n: int) -> bytes:
    d = zstandard.ZstdDecompressor(max_window_size=ZSTD_MAX_WINDOW).decompressobj()
    out = bytearray()
    for i in range(0, max(len(p), 1), FEED_ZSTD):
        if d.eof:
            return _check_tail(n, bytes(out), True, d.unused_data + p[i:])
        out += d.decompress(p[i:i + FEED_ZSTD])
        if len(out) > n:
            raise DecodeError("output exceeds declared length")
    return _check_tail(n, bytes(out), d.eof, d.unused_data)


def _brotli_d(p: bytes, n: int) -> bytes:
    d = brotli.Decompressor()
    out = bytearray()
    pos = 0
    while not d.is_finished():
        if d.can_accept_more_data():
            chunk = p[pos:pos + FEED]
            pos += len(chunk)
        else:
            chunk = b""
        if not chunk and pos >= len(p) and d.can_accept_more_data():
            raise DecodeError("truncated or unterminated stream")
        out += d.process(chunk, output_buffer_limit=max(n + 1 - len(out), 1))
        if len(out) > n:
            raise DecodeError("output exceeds declared length")
    # Input never fed to the decoder after the stream ended counts as trailing data.
    # (Junk inside the last fed chunk is rejected by brotli itself, as verified in tests.)
    return _check_tail(n, bytes(out), True, p[pos:])


def _lzma_c(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_XZ, preset=9 | lzma.PRESET_EXTREME)


CODECS: dict[str, Codec] = {
    c.name: c
    for c in [
        Codec("zlib-9", 1, "level=9", lambda d: zlib.compress(d, 9), _zlib_d),
        Codec("bz2-9", 2, "level=9", lambda d: bz2.compress(d, 9), _bz2_d),
        Codec("lzma-9e", 3, "xz preset=9|extreme", _lzma_c, _lzma_d),
        Codec("zstd-19", 4, "level=19", _zstd_c, _zstd_d),
        Codec("brotli-11", 5, "quality=11", lambda d: brotli.compress(d, quality=11), _brotli_d,
              external_dependency=("brotli static dictionary, built into the decoder library and not counted in "
                                   "stored bytes; shared by all files, so amortisation is not applied here"),
              external_dependency_bytes=122784),  # measured in brotli 1.2.1 by the independent auditor (AUDIT_002)
    ]
}

CODECS_BY_ID = {c.codec_id: c for c in CODECS.values()}
