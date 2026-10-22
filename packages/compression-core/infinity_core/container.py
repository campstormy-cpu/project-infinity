"""Self-describing container, format INF1.

Layout (big endian), 45 bytes of header then the codec payload:

    magic        4  bytes  b"INF1"
    codec_id     1  byte
    orig_length  8  bytes  unsigned
    sha256       32 bytes  of the ORIGINAL data
    payload      N  bytes

The header is part of `complete_storage_bytes`. Decoding verifies length and
SHA-256 and raises IntegrityError on any mismatch. This detects corruption and
accidental damage. It is NOT authentication: someone who rewrites both the
payload and the stored hash produces a container that decodes without error.
Authentication needs a keyed MAC or signature, which belongs to the encryption
layer (Phase 0, not built).

Memory bound: decoding refuses any container declaring more than `max_output`
bytes (default 256 MiB). A hostile container that declares exactly that much can
still force a peak of roughly twice `max_output` (measured 250-593 MB RSS across
the five codecs on this VM, 2026-10-22, two independent measurements: output buffer plus its returned copy). Callers
with a smaller memory budget must pass a smaller `max_output`.
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


DEFAULT_MAX_OUTPUT = 256 * 1024 * 1024  # 256 MiB; callers handling larger files must raise it explicitly


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
