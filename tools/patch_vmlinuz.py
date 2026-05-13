#!/usr/bin/env python3
import argparse
import sys
import os
import struct
import lzma

# Linux x86 boot header field offsets
HDRMAGIC = b"HdrS"
HDRMAGIC_OFFSET = 0x202
SETUP_SECTS_OFFSET = 0x1F1
HEADER_VERSION_OFFSET = 0x20E
PAYLOAD_OFFSET_FIELD = 0x248   # payload offset relative to setup_end (4-byte LE)
PAYLOAD_SIZE_FIELD = 0x24C     # compressed payload size (4-byte LE)
MIN_VERSION_FOR_PAYLOAD = 0x020A  # boot protocol 2.10+


# ---------------------------------------------------------------------------
# XZ parameter extraction helpers
# ---------------------------------------------------------------------------

def _read_vli(buf: bytes, pos: int) -> tuple[int, int]:
    """Read a variable-length integer from an XZ stream; return (value, next_pos)."""
    val = 0
    for i in range(9):
        b = buf[pos + i]
        val |= (b & 0x7F) << (i * 7)
        if not (b & 0x80):
            return val, pos + i + 1
    raise ValueError("VLI too long")


def _decode_lzma2_dict_size(props_byte: int) -> int:
    """Decode LZMA2 dict_size from the single properties byte in the XZ block header."""
    if props_byte == 40:
        return 0xFFFFFFFF
    if props_byte < 40:
        return (2 + (props_byte & 1)) << (props_byte // 2 + 11)
    raise ValueError(f"invalid LZMA2 dict props byte: {props_byte}")


def _read_lclppb(data: bytes, lzma2_stream_start: int) -> tuple[int, int, int]:
    """
    Scan the raw LZMA2 stream (after the XZ block header) for the first chunk
    that carries new LZMA properties (control byte >= 0xC0) and extract lc/lp/pb.
    """
    pos = lzma2_stream_start
    limit = min(pos + 1 << 20, len(data))  # scan at most 1 MiB
    while pos < limit:
        ctrl = data[pos]
        if ctrl >= 0xC0:  # LZMA chunk with new properties
            pb_byte = data[pos + 5]
            pb = pb_byte // 45
            lp = (pb_byte - pb * 45) // 9
            lc = (pb_byte - pb * 45) - lp * 9
            return lc, lp, pb
        elif ctrl >= 0x80:  # LZMA chunk without new properties -- skip it
            comp_size = ((data[pos + 3] << 8) | data[pos + 4]) + 1
            pos += 5 + comp_size
        elif ctrl in (0x01, 0x02):  # uncompressed chunk
            uncomp_size = ((data[pos + 1] << 8) | data[pos + 2]) + 1
            pos += 3 + uncomp_size
        else:
            break
    raise ValueError("no LZMA2 chunk with new properties found in first 1 MiB")


def parse_xz_params(data: bytes, payload_start: int) -> dict:
    """
    Parse an XZ stream starting at *payload_start* in *data* and return a dict:
      {
        "check"  : lzma.CHECK_* constant,
        "filters": list of filter dicts suitable for lzma.compress(filters=...),
      }
    Supports BCJ filters (0x04-0x09), DELTA (0x03), and LZMA2 (0x21).
    lc/lp/pb are read from the first LZMA2 chunk header (not the block header,
    which only stores dict_size).
    """
    # Stream header: magic(6) + stream_flags(2) + CRC32(4)
    check_type = data[payload_start + 7] & 0x0F
    check_map = {0: lzma.CHECK_NONE, 1: lzma.CHECK_CRC32, 4: lzma.CHECK_CRC64}
    check = check_map.get(check_type, lzma.CHECK_CRC32)

    # Block header immediately follows stream header
    bh = payload_start + 12
    block_hdr_size_byte = data[bh]
    block_hdr_len = (block_hdr_size_byte + 1) * 4
    block_flags = data[bh + 1]
    num_filters = (block_flags & 0x03) + 1

    offset = bh + 2
    if block_flags & 0x40:  # compressed size present
        _, offset = _read_vli(data, offset)
    if block_flags & 0x80:  # uncompressed size present
        _, offset = _read_vli(data, offset)

    # BCJ filter IDs that Python's lzma module exposes directly
    bcj_ids = {
        lzma.FILTER_X86, lzma.FILTER_POWERPC, lzma.FILTER_IA64,
        lzma.FILTER_ARM, lzma.FILTER_ARMTHUMB, lzma.FILTER_SPARC,
    }

    filters = []
    lzma2_stream_start = bh + block_hdr_len  # raw LZMA2 data starts here
    for _ in range(num_filters):
        fid, offset = _read_vli(data, offset)
        props_size, offset = _read_vli(data, offset)
        props = data[offset:offset + props_size]
        offset += props_size

        if fid == lzma.FILTER_LZMA2:
            dict_size = _decode_lzma2_dict_size(props[0])
            lc, lp, pb = _read_lclppb(data, lzma2_stream_start)
            filters.append({
                "id": lzma.FILTER_LZMA2,
                "dict_size": dict_size,
                "lc": lc, "lp": lp, "pb": pb,
            })
        elif fid in bcj_ids:
            f: dict = {"id": fid}
            if props_size == 4:  # optional 32-bit start offset
                f["start_offset"] = struct.unpack_from("<I", props)[0]
            filters.append(f)
        elif fid == lzma.FILTER_DELTA:
            filters.append({"id": lzma.FILTER_DELTA, "dist": props[0] + 1})
        else:
            raise ValueError(f"unsupported XZ filter id 0x{fid:02x}")

    return {"check": check, "filters": filters}


# ---------------------------------------------------------------------------


def pem_to_der(pem_path: str) -> bytes:
    """Load a PEM public key and return its PKCS#1 RSAPublicKey DER encoding."""
    try:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, load_pem_public_key
        )
    except ImportError:
        sys.exit("error: 'cryptography' package required -- pip install cryptography")

    with open(pem_path, "rb") as f:
        pem_data = f.read()
    key = load_pem_public_key(pem_data)
    # The kernel stores a raw PKCS#1 RSAPublicKey (no AlgorithmIdentifier wrapper)
    return key.public_bytes(Encoding.DER, PublicFormat.PKCS1)


def find_payload(data: bytes) -> tuple[int, int]:
    """
    Parse the Linux x86 boot header and return (payload_start, payload_size).
    payload_start : byte offset of the compressed payload inside vmlinuz
    payload_size  : byte count of the compressed payload (excluding EFI stub tail)
    """
    if len(data) < 0x250:
        sys.exit("error: vmlinuz too small to contain a valid boot header")

    if data[HDRMAGIC_OFFSET:HDRMAGIC_OFFSET + 4] != HDRMAGIC:
        sys.exit("error: 'HdrS' magic not found -- is this an x86 bzImage?")

    setup_sects = data[SETUP_SECTS_OFFSET]
    if setup_sects == 0:
        setup_sects = 4  # kernel default when field is zero

    version = struct.unpack_from("<H", data, HEADER_VERSION_OFFSET)[0]
    if version < MIN_VERSION_FOR_PAYLOAD:
        sys.exit(f"error: boot protocol 0x{version:04x} too old (need >= 0x{MIN_VERSION_FOR_PAYLOAD:04x})")

    setup_end = (setup_sects + 1) * 512
    payload_rel_offset = struct.unpack_from("<I", data, PAYLOAD_OFFSET_FIELD)[0]
    payload_size = struct.unpack_from("<I", data, PAYLOAD_SIZE_FIELD)[0]
    payload_start = setup_end + payload_rel_offset

    if payload_start + payload_size > len(data):
        sys.exit(
            f"error: payload extends beyond end of file "
            f"(start=0x{payload_start:x}, size={payload_size}, file={len(data)})"
        )

    xz_magic = b"\xfd7zXZ\x00"
    if data[payload_start:payload_start + 6] != xz_magic:
        actual = data[payload_start:payload_start + 6].hex()
        sys.exit(
            f"error: payload does not start with XZ magic (expected fd377a585a00, got {actual})\n"
            "only XZ-compressed vmlinuz is supported"
        )

    return payload_start, payload_size


def xz_decompress(data: bytes) -> tuple[bytes, int]:
    """
    Decompress an XZ stream, returning (decompressed_bytes, bytes_consumed).
    Feeds the full buffer and uses unused_data to find the exact stream boundary,
    avoiding any mismatch between the boot header payload_size field and the
    actual XZ stream length.
    """
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    decompressed = dec.decompress(data)
    consumed = len(data) - len(dec.unused_data)
    return decompressed, consumed


def xz_compress(data: bytes, check: int, filters: list) -> bytes:
    """
    Compress *data* using the supplied *filters* and *check* type.
    Both are obtained from parse_xz_params() so they exactly match the
    original XZ stream -- no parameters are hardcoded here.
    """
    return lzma.compress(data, format=lzma.FORMAT_XZ, check=check, filters=filters)


def patch_vmlinuz(input_path: str, output_path: str, old_key_pem: str, new_key_pem: str) -> None:
    print("[*] Loading keys...")
    old_der = pem_to_der(old_key_pem)
    new_der = pem_to_der(new_key_pem)
    print(f"    old DER: {len(old_der)} bytes  ({old_key_pem})")
    print(f"    new DER: {len(new_der)} bytes  ({new_key_pem})")

    if len(old_der) != len(new_der):
        sys.exit(
            f"error: old and new DER sizes differ "
            f"(old={len(old_der)}, new={len(new_der)}) -- equal-length replacement required"
        )

    # Show the single differing byte between the two keys
    diffs = [i for i in range(len(old_der)) if old_der[i] != new_der[i]]
    print(f"    key diff: {len(diffs)} byte(s) changed: " +
          ", ".join(f"offset {i}: 0x{old_der[i]:02x}->0x{new_der[i]:02x}" for i in diffs))

    print(f"\n[*] Reading vmlinuz: {input_path}")
    with open(input_path, "rb") as f:
        vmlinuz = bytearray(f.read())
    print(f"    size: {len(vmlinuz)} bytes")

    print("\n[*] Parsing boot header...")
    payload_start, payload_size = find_payload(bytes(vmlinuz))
    payload_end = payload_start + payload_size
    tail_size = len(vmlinuz) - payload_end
    print(f"    payload_start : 0x{payload_start:x}")
    print(f"    payload_size  : {payload_size} bytes (0x{payload_size:x})")
    print(f"    EFI stub tail : {tail_size} bytes")

    print("\n[*] Parsing XZ stream parameters...")
    xz_params = parse_xz_params(bytes(vmlinuz), payload_start)
    check = xz_params["check"]
    filters = xz_params["filters"]
    check_name = {lzma.CHECK_CRC32: "CRC32", lzma.CHECK_CRC64: "CRC64",
                  lzma.CHECK_NONE: "none"}.get(check, str(check))
    print(f"    integrity check : {check_name}")
    for i, f in enumerate(filters):
        fid = f["id"]
        fname = {lzma.FILTER_X86: "BCJ-x86", lzma.FILTER_LZMA2: "LZMA2",
                 lzma.FILTER_DELTA: "DELTA"}.get(fid, f"0x{fid:02x}")
        extras = {k: v for k, v in f.items() if k != "id"}
        print(f"    filter[{i}]      : {fname}  {extras}")

    print("\n[*] Decompressing XZ payload...")
    try:
        vmlinux, xz_actual_size = xz_decompress(bytes(vmlinuz[payload_start:]))
    except Exception as e:
        sys.exit(f"error: XZ decompression failed: {e}")
    print(f"    decompressed : {len(vmlinux)} bytes")
    print(f"    XZ stream    : {xz_actual_size} bytes (header payload_size={payload_size}, delta={xz_actual_size-payload_size:+d})")

    # Split the original file into three regions:
    #   prefix   -- everything before the XZ stream
    #   gap      -- bytes between XZ stream end and payload_size boundary
    #               (typically 4 zero bytes left by the kernel build; preserved verbatim)
    #   suffix   -- EFI stub and anything after payload_end
    prefix   = bytes(vmlinuz[:payload_start])
    gap      = bytes(vmlinuz[payload_start + xz_actual_size : payload_start + payload_size])
    suffix   = bytes(vmlinuz[payload_start + payload_size:])
    if gap:
        print(f"    gap bytes    : {len(gap)}  {gap.hex()}")

    print("\n[*] Searching for old DER public key...")
    count = vmlinux.count(old_der)
    if count == 0:
        print("    warning: old DER key not found in decompressed kernel!")
        print("    hint: kernel version may not match the key file")
        print("    old DER first 16 bytes:", old_der[:16].hex())
        pos = vmlinux.find(old_der[:16])
        if pos != -1:
            print(f"    partial match (16 bytes) at offset 0x{pos:x} but full key differs")
        sys.exit("aborted: cannot replace key that was not found")

    print(f"    found {count} occurrence(s), replacing...")
    vmlinux_patched = vmlinux.replace(old_der, new_der)

    if vmlinux_patched.count(old_der) != 0:
        sys.exit("error: old key still present after replacement")
    print(f"    replaced OK -- new key appears {vmlinux_patched.count(new_der)} time(s)")

    print("\n[*] Recompressing (this may take a few minutes)...")
    new_compressed = xz_compress(vmlinux_patched, check=check, filters=filters)
    size_diff = len(new_compressed) - xz_actual_size
    print(f"    original XZ : {xz_actual_size} bytes")
    print(f"    new XZ      : {len(new_compressed)} bytes  (delta={size_diff:+d})")

    print("\n[*] Rebuilding vmlinuz...")
    # Preserve the original gap so payload_size only changes if the XZ stream
    # actually grew or shrank.
    new_payload_size = len(new_compressed) + len(gap)
    new_vmlinuz = bytearray(prefix + new_compressed + gap + suffix)
    if new_payload_size != payload_size:
        struct.pack_into("<I", new_vmlinuz, PAYLOAD_SIZE_FIELD, new_payload_size)
        print(f"    payload_size : 0x{payload_size:x} -> 0x{new_payload_size:x}  ({payload_size} -> {new_payload_size})")
    else:
        print(f"    payload_size : 0x{payload_size:x} unchanged")
    print(f"    new vmlinuz size : {len(new_vmlinuz)} bytes")

    print(f"\n[*] Writing: {output_path}")
    with open(output_path, "wb") as f:
        f.write(new_vmlinuz)

    print(f"\n[+] Done. Patched kernel written to: {output_path}")


def main():

    parser = argparse.ArgumentParser(
        description="Patch a Linux vmlinuz by replacing an embedded RSA public key."
    )
    parser.add_argument(
        "input_vmlinuz",
        nargs="?",
        help=f"input vmlinuz path",
    )
    parser.add_argument(
        "output_vmlinuz",
        nargs="?",
        help="output vmlinuz path (default: <input>.patched, or the built-in default when input is omitted)",
    )
    parser.add_argument(
        "--old-key",
        dest="old_key_pem",
        required=True,
        help="path to the original PEM public key embedded in the kernel",
    )
    parser.add_argument(
        "--new-key",
        dest="new_key_pem",
        required=True,
        help="path to the replacement PEM public key",
    )
    args = parser.parse_args()

    input_vmlinuz = args.input_vmlinuz
    if args.output_vmlinuz:
        output_vmlinuz = args.output_vmlinuz
    else:
        output_vmlinuz = input_vmlinuz + ".patched"

    if not os.path.exists(input_vmlinuz):
        sys.exit(f"error: input file not found: {input_vmlinuz}")
    if not os.path.exists(args.old_key_pem):
        sys.exit(f"error: old key file not found: {args.old_key_pem}")
    if not os.path.exists(args.new_key_pem):
        sys.exit(f"error: new key file not found: {args.new_key_pem}")

    patch_vmlinuz(input_vmlinuz, output_vmlinuz, args.old_key_pem, args.new_key_pem)


if __name__ == "__main__":
    main()
