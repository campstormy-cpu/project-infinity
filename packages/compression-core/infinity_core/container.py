"""Self-describing container, format INF1.

Layout (big endian), 45 bytes of header then the codec payload:

    magic        4  bytes  b"INF1"
    codec_id     1  byte
    orig_length  8  bytes  unsigned
    sha256       32 bytes  of the ORIGINAL data
    payload      N  bytes

The header is part of `complete_storage_bytes`. Decoding verifies length and
SHA-256 and raises IntegrityError on any mismatch, so a corrupted or tampered
container can never be returned as if it were the original.
"""
from __future__ import annotations

import struct

from .codecs import CODECS, CODECS_BY_ID
from .integrity import sha256_bytes

MAGIC = b"INF1"
_HEADER = struct.Struct(">4sBQ32s")
HEADER_SIZE = _HEADER.size  # 45


class IntegrityError(Exception):
    pass


def compress_bytes(codec_name: str, data: bytes) -> bytes:
    codec = CODECS[codec_name]
    payload = codec.compress(data)
    header = _HEADER.pack(MAGIC, codec.codec_id, len(data), bytes.fromhex(sha256_bytes(data)))
    return header + payload


DEFAULT_MAX_OUTPUT = 1 << 30  # 1 GiB; callers may raise or lower it


def decompress_bytes(blob: bytes, max_output: int = DEFAULT_MAX_OUTPUT) -> bytes:
    if len(blob) < HEADER_SIZE:
        raise IntegrityError("container shorter than header")
    magic, codec_id, orig_len, sha = _HEADER.unpack(blob[:HEADER_SIZE])
    if magic != MAGIC:
        raise IntegrityError("bad magic")
    codec = CODECS_BY_ID.get(codec_id)
    if codec is None:
        raise IntegrityError(f"unknown codec id {codec_id}")
    if orig_len > max_output:
        raise IntegrityError(f"declared length {orig_len} exceeds max_output {max_output}")
    try:
        data = codec.decompress(blob[HEADER_SIZE:], orig_len)
    except MemoryError as exc:
        raise IntegrityError("out of memory while decoding") from exc
    except Exception as exc:  # codec-specific errors on corrupt payloads
        raise IntegrityError(f"payload failed to decode: {type(exc).__name__}: {exc}") from exc
    if len(data) != orig_len:
        raise IntegrityError("length mismatch after decode")
    if bytes.fromhex(sha256_bytes(data)) != sha:
        raise IntegrityError("SHA-256 mismatch after decode")
    return data


def compress_file(codec_name: str, src, dst) -> int:
    """Reads src fully into memory (documented limit: datasets here are small)."""
    with open(src, "rb") as fh:
        data = fh.read()
    blob = compress_bytes(codec_name, data)
    with open(dst, "wb") as fh:
        fh.write(blob)
    return len(blob)


def decompress_file(src, dst) -> int:
    with open(src, "rb") as fh:
        blob = fh.read()
    data = decompress_bytes(blob)
    with open(dst, "wb") as fh:
        fh.write(data)
    return len(data)
