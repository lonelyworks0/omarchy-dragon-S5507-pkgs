#!/usr/bin/env python3
"""Print the SoC hardware ids a Qualcomm MBN or ELF is signed for.

Qualcomm signs an ELF image in its hash segment (the program header whose
flags are 0x02000000). MBN header v6 and v7 store, in the QTI and OEM
signature metadata, up to twelve SoC hardware versions. TrustZone accepts
the image only when the fused id is one of those. On Snapdragon X that id
is 0xa009 for the X Elite (X1E80100, Hamoa) and 0xa016 for the X1P42100
(Purwa).

This is the same hash-segment walk as tools/mbn-socs.py, which the Vivobook
firmware recipe uses when that script is in the repo. The recipe helper is
not installed on the machine, so qcom-firmware-extract ships this copy and
calls it with --ids. Keep the two parsers in step.

SPDX-License-Identifier: GPL-2.0-or-later
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path


HASH_SEGMENT_FLAGS = 0x02000000
METADATA_V6_SIZE = 120
METADATA_V7_SIZE = 224


def _program_headers(data: bytes):
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF image")
    elf_class = data[4]
    elf_data = data[5]
    if elf_data != 1:
        raise ValueError("ELF is not little-endian")
    if elf_class == 1:
        e_phoff = struct.unpack_from("<I", data, 28)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
        for index in range(e_phnum):
            off = e_phoff + index * e_phentsize
            p_type, p_offset, _, _, p_filesz, _, p_flags, _ = struct.unpack_from(
                "<IIIIIIII", data, off
            )
            yield p_type, p_flags, p_offset, p_filesz
    elif elf_class == 2:
        e_phoff = struct.unpack_from("<Q", data, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
        for index in range(e_phnum):
            off = e_phoff + index * e_phentsize
            p_type, p_flags = struct.unpack_from("<II", data, off)
            p_offset, _, _, p_filesz, _ = struct.unpack_from("<QQQQQ", data, off + 8)
            yield p_type, p_flags, p_offset, p_filesz
    else:
        raise ValueError(f"unknown ELF class {elf_class}")


def _soc_versions(metadata: bytes) -> list[int]:
    """Non-zero soc_version entries from a 120-byte (v6) or 224-byte (v7) blob."""
    if len(metadata) == METADATA_V6_SIZE:
        # major, minor, sw_id, hw_id, oem_id, model_id, app_id, flags, then 12 ids.
        versions = struct.unpack_from("<12I", metadata, 32)
    elif len(metadata) == METADATA_V7_SIZE:
        # major, minor, anti-rollback, root index, then 12 ids.
        versions = struct.unpack_from("<12I", metadata, 16)
    else:
        return []
    return [value for value in versions if value]


def _metadata_blobs(segment: bytes) -> list[bytes]:
    if len(segment) < 8:
        return []
    _image_id, version = struct.unpack_from("<II", segment, 0)
    blobs: list[bytes] = []
    if version == 6 and len(segment) >= 48:
        (
            _image_id,
            _version,
            _qti_sig,
            _qti_cert,
            _image_size,
            _code_size,
            _sig_ptr,
            _oem_sig,
            _cert_ptr,
            _oem_cert,
            qti_size,
            oem_size,
        ) = struct.unpack_from("<12I", segment, 0)
        offset = 48
    elif version == 7 and len(segment) >= 40:
        (
            _image_id,
            _version,
            common_size,
            qti_size,
            oem_size,
            _code_size,
            _qti_sig,
            _qti_cert,
            _oem_sig,
            _oem_cert,
        ) = struct.unpack_from("<10I", segment, 0)
        offset = 40 + common_size
    else:
        return []
    for size in (qti_size, oem_size):
        if offset + size > len(segment):
            return []
        if size:
            blobs.append(segment[offset : offset + size])
        offset += size
    return blobs


def soc_hw_ids(data: bytes) -> list[int]:
    """SoC hardware ids from every hash-segment metadata block, in order."""
    found: list[int] = []
    for _p_type, p_flags, p_offset, p_filesz in _program_headers(data):
        if p_flags != HASH_SEGMENT_FLAGS or not p_filesz:
            continue
        if p_offset + p_filesz > len(data):
            continue
        for blob in _metadata_blobs(data[p_offset : p_offset + p_filesz]):
            for soc in _soc_versions(blob):
                if soc not in found:
                    found.append(soc)
    if not found:
        raise ValueError("no SoC hardware id in the hash-segment metadata")
    return found


def main(argv: list[str]) -> int:
    args = argv[1:]
    ids_only = False
    if args and args[0] == "--ids":
        ids_only = True
        args = args[1:]
    if not args:
        print(f"usage: {argv[0]} [--ids] image.mbn [image.mbn ...]", file=sys.stderr)
        return 2
    status = 0
    for name in args:
        path = Path(name)
        try:
            ids = soc_hw_ids(path.read_bytes())
        except (OSError, ValueError) as exc:
            if not ids_only:
                print(f"{name}: {exc}", file=sys.stderr)
            status = 1
            continue
        formatted = " ".join(f"0x{soc:x}" for soc in ids)
        if ids_only:
            print(formatted)
        else:
            print(f"{path.name}: {formatted}")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
