from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import xml.etree.ElementTree as ET
    from vendor.twofish import Twofish


BLOCK_SIZE = 16
TAG_LEN = 16
NEW_KEY = bytes([0x89]) * 16
NEW_IV = bytes([0x10]) * 16


_TWOFISH_CLS: type["Twofish"] | None = None
_TWOFISH_BACKEND = ""


def _twofish_cls() -> type["Twofish"]:
    """Resolve a Twofish engine.

    The compiled ctypes bridge is preferred when present because it is ~12x
    faster, but it is optional: the vendored pure-Python implementation is
    always available, so decode/edit/generate work on a clean checkout with no
    binaries and no environment variables.
    """
    global _TWOFISH_CLS, _TWOFISH_BACKEND
    if _TWOFISH_CLS is not None:
        return _TWOFISH_CLS

    try:
        from vendor.twofish import Twofish  # compiled accelerator

        _TWOFISH_BACKEND = "compiled"
    except Exception:
        from vendor.twofish_pure import Twofish  # always-available fallback

        _TWOFISH_BACKEND = "pure_python"

    _TWOFISH_CLS = Twofish
    return Twofish


def twofish_backend() -> str:
    """Return `compiled` or `pure_python` for the engine actually in use."""
    if _TWOFISH_CLS is None:
        _twofish_cls()
    return _TWOFISH_BACKEND


def qcompress(xml_bytes: bytes) -> bytes:
    if not isinstance(xml_bytes, bytes):
        raise TypeError("xml_bytes must be bytes")
    return struct.pack(">I", len(xml_bytes)) + zlib.compress(xml_bytes, 9)


def quncompress(blob: bytes) -> bytes:
    if len(blob) < 4:
        raise ValueError("qCompress blob is too short")
    size = struct.unpack(">I", blob[:4])[0]
    out = zlib.decompress(blob[4:])
    return out[:size]


def stage2_xor(data: bytes) -> bytes:
    length = len(data)
    return bytes(byte ^ ((length - index) & 0xFF) for index, byte in enumerate(data))


def stage1_obfuscate(clear: bytes) -> bytes:
    length = len(clear)
    out = bytearray(length)
    for index, byte in enumerate(clear):
        out[length - 1 - index] = byte ^ ((length - index * length) & 0xFF)
    return bytes(out)


def stage1_deobfuscate(obfuscated: bytes) -> bytes:
    length = len(obfuscated)
    return bytes(
        obfuscated[length - 1 - index] ^ ((length - index * length) & 0xFF)
        for index in range(length)
    )


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _gf_double(block: bytes) -> bytes:
    value = int.from_bytes(block, "big")
    carry = (value >> 127) & 1
    value = ((value << 1) & ((1 << 128) - 1))
    if carry:
        value ^= 0x87
    return value.to_bytes(16, "big")


def _pad_cmac(block: bytes) -> bytes:
    return block + b"\x80" + b"\x00" * (BLOCK_SIZE - len(block) - 1)


def _iterate_blocks(data: bytes) -> list[bytes]:
    return [data[index : index + BLOCK_SIZE] for index in range(0, len(data), BLOCK_SIZE)]


def _cmac(cipher: "Twofish", data: bytes) -> bytes:
    zero = b"\x00" * BLOCK_SIZE
    l_val = cipher.encrypt(zero)
    k1 = _gf_double(l_val)
    k2 = _gf_double(k1)

    blocks = _iterate_blocks(data)
    if not blocks:
        blocks = [b""]

    if len(blocks[-1]) == BLOCK_SIZE:
        last = _xor_bytes(blocks[-1], k1)
    else:
        last = _xor_bytes(_pad_cmac(blocks[-1]), k2)
    blocks[-1] = last

    state = zero
    for block in blocks:
        if len(block) != BLOCK_SIZE:
            raise ValueError("CMAC internal block must be 16 bytes")
        state = cipher.encrypt(_xor_bytes(state, block))
    return state


def _omac(cipher: "Twofish", domain: int, data: bytes) -> bytes:
    prefix = b"\x00" * 15 + bytes([domain & 0xFF])
    return _cmac(cipher, prefix + data)


def _ctr_crypt(cipher: "Twofish", initial_counter: bytes, data: bytes) -> bytes:
    counter = int.from_bytes(initial_counter, "big")
    out = bytearray()
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        keystream = cipher.encrypt(counter.to_bytes(16, "big"))
        out.extend(bytes(a ^ b for a, b in zip(block, keystream)))
        counter = (counter + 1) % (1 << 128)
    return bytes(out)


def eax_twofish_encrypt(plaintext: bytes, nonce: bytes = NEW_IV, header: bytes = b"") -> tuple[bytes, bytes]:
    cipher = _twofish_cls()(NEW_KEY)
    nonce_mac = _omac(cipher, 0, nonce)
    header_mac = _omac(cipher, 1, header)
    ciphertext = _ctr_crypt(cipher, nonce_mac, plaintext)
    body_mac = _omac(cipher, 2, ciphertext)
    tag = _xor_bytes(_xor_bytes(nonce_mac, header_mac), body_mac)
    return ciphertext, tag


def eax_twofish_decrypt(ciphertext: bytes, tag: bytes, nonce: bytes = NEW_IV, header: bytes = b"") -> bytes:
    if len(tag) != TAG_LEN:
        raise ValueError("invalid EAX tag length")
    cipher = _twofish_cls()(NEW_KEY)
    nonce_mac = _omac(cipher, 0, nonce)
    header_mac = _omac(cipher, 1, header)
    body_mac = _omac(cipher, 2, ciphertext)
    expected_tag = _xor_bytes(_xor_bytes(nonce_mac, header_mac), body_mac)
    if expected_tag != tag:
        raise ValueError("EAX authentication tag verification failed")
    return _ctr_crypt(cipher, nonce_mac, ciphertext)


def encode_pkt_modern(xml_bytes: bytes) -> bytes:
    payload = qcompress(xml_bytes)
    stage2 = stage2_xor(payload)
    ciphertext, tag = eax_twofish_encrypt(stage2)
    return stage1_obfuscate(ciphertext + tag)


def decode_pkt_modern(pkt_bytes: bytes) -> bytes:
    if len(pkt_bytes) < TAG_LEN:
        raise ValueError("pkt blob is too short")
    stage1 = stage1_deobfuscate(pkt_bytes)
    ciphertext = stage1[:-TAG_LEN]
    tag = stage1[-TAG_LEN:]
    stage2 = eax_twofish_decrypt(ciphertext, tag)
    payload = stage2_xor(stage2)
    return quncompress(payload)


# Packet Tracer writes raw control bytes into element text — a Cisco banner
# delimiter is literally `banner motd \x03`. XML 1.0 forbids those, so a strict
# parser rejects the whole document even though Packet Tracer reads it happily.
# Map them into the Unicode private use area for parsing and map them back on
# the way out, so the round trip is faithful rather than lossy.
_XML_SAFE_CONTROL_BYTES = {0x09, 0x0A, 0x0D}
_CONTROL_PLACEHOLDER_BASE = 0xE000


def xml_escape_control_bytes(xml_bytes: bytes) -> bytes:
    """Replace XML-forbidden control bytes with private-use placeholders."""
    if not any(byte < 0x20 and byte not in _XML_SAFE_CONTROL_BYTES for byte in xml_bytes):
        return xml_bytes
    out = bytearray()
    for byte in xml_bytes:
        if byte < 0x20 and byte not in _XML_SAFE_CONTROL_BYTES:
            out.extend(chr(_CONTROL_PLACEHOLDER_BASE + byte).encode("utf-8"))
        else:
            out.append(byte)
    return bytes(out)


def xml_restore_control_bytes(xml_bytes: bytes) -> bytes:
    """Inverse of `xml_escape_control_bytes`."""
    text = xml_bytes.decode("utf-8", "surrogatepass")
    if not any(_CONTROL_PLACEHOLDER_BASE <= ord(char) < _CONTROL_PLACEHOLDER_BASE + 0x20 for char in text):
        return xml_bytes
    restored = "".join(
        chr(ord(char) - _CONTROL_PLACEHOLDER_BASE)
        if _CONTROL_PLACEHOLDER_BASE <= ord(char) < _CONTROL_PLACEHOLDER_BASE + 0x20
        else char
        for char in text
    )
    return restored.encode("utf-8", "surrogatepass")


def parse_pkt_xml(xml_bytes: bytes) -> "ET.Element":
    """Parse Packet Tracer XML, tolerating the control bytes it really writes."""
    import xml.etree.ElementTree as ET

    return ET.fromstring(xml_escape_control_bytes(xml_bytes))


def serialize_pkt_xml(root: "ET.Element") -> bytes:
    """Serialize a tree parsed by `parse_pkt_xml`, restoring control bytes."""
    import xml.etree.ElementTree as ET

    return xml_restore_control_bytes(ET.tostring(root, encoding="utf-8", xml_declaration=False))


def legacy_xor(data: bytes) -> bytes:
    """The pre-Twofish `.pkt` obfuscation, which is its own inverse.

    Packet Tracer 5.x and 6.x wrote saves as qCompress output XORed byte-wise
    with `(length - index)`. No Twofish, no EAX tag, no reversal. 18 of the 292
    samples bundled with Packet Tracer 9.0 are still in this format, including
    the QoS, SNMP, NAT, TFTP, IPsec, AAA, CBAC, ZFW and VoIP labs.
    """
    length = len(data)
    return bytes(byte ^ ((length - index) & 0xFF) for index, byte in enumerate(data))


def decode_pkt_legacy(pkt_bytes: bytes) -> bytes:
    """Decode a pre-Twofish `.pkt`."""
    return quncompress(legacy_xor(pkt_bytes))


def encode_pkt_legacy(xml_bytes: bytes) -> bytes:
    return legacy_xor(qcompress(xml_bytes))


def detect_pkt_format(pkt_bytes: bytes) -> str:
    """Return `modern`, `legacy`, or `unknown` without raising."""
    try:
        decode_pkt_modern(pkt_bytes)
        return "modern"
    except Exception:
        pass
    try:
        decode_pkt_legacy(pkt_bytes)
        return "legacy"
    except Exception:
        return "unknown"


def decode_pkt_auto(pkt_bytes: bytes) -> tuple[bytes, str]:
    """Decode either container variant, reporting which one matched."""
    try:
        return decode_pkt_modern(pkt_bytes), "modern"
    except Exception as modern_error:
        try:
            return decode_pkt_legacy(pkt_bytes), "legacy"
        except Exception:
            raise ValueError(
                f"not a readable Packet Tracer save: modern decode failed ({modern_error}), "
                "and the legacy container did not match either"
            ) from modern_error


def peek_pkt_header(pkt_bytes: bytes, max_xml_bytes: int = 8192) -> bytes:
    """Decrypt just enough of a `.pkt` to read the start of its XML.

    Donor scanning reads `<VERSION>` from dozens of files per run. Doing that
    with `decode_pkt_modern` costs a full EAX pass over every byte plus three
    OMACs, which measured at ~3 s per file and dominated the runtime.

    CTR mode is seekable and the header sits at the front, so only the first few
    blocks need decrypting. The zlib stream is fed incrementally and abandoned
    as soon as enough plaintext is out.

    This intentionally skips tag verification: it is a read-only probe used to
    decide whether a file is worth considering, and it never produces content
    that is written back out. Anything that matters goes through
    `decode_pkt_modern`, which does authenticate.
    """
    if len(pkt_bytes) < TAG_LEN + BLOCK_SIZE:
        raise ValueError("pkt blob is too short")

    blob_length = len(pkt_bytes)
    total_length = blob_length - TAG_LEN

    # 4 bytes of qCompress header + a compressed prefix that is generously
    # larger than the plaintext we want back out.
    wanted = 4 + max_xml_bytes
    prefix_len = min(total_length, ((wanted + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE)

    # Stage 1 reverses the buffer, so the prefix we need comes from the *tail* of
    # the file. Computing only those bytes keeps this O(prefix) rather than
    # O(file), which matters because the largest labs are several megabytes.
    stage1_prefix = bytes(
        pkt_bytes[blob_length - 1 - index] ^ ((blob_length - index * blob_length) & 0xFF)
        for index in range(prefix_len)
    )

    cipher = _twofish_cls()(NEW_KEY)
    nonce_mac = _omac(cipher, 0, NEW_IV)
    stage2_prefix = _ctr_crypt(cipher, nonce_mac, stage1_prefix)

    # stage2_xor's key stream depends on the *full* payload length, which is
    # known from the blob size without decrypting the rest.
    payload_prefix = bytes(
        byte ^ ((total_length - index) & 0xFF) for index, byte in enumerate(stage2_prefix)
    )

    decompressor = zlib.decompressobj()
    try:
        return decompressor.decompress(payload_prefix[4:], max_xml_bytes)
    except zlib.error as exc:
        raise ValueError(f"could not decompress pkt header: {exc}") from exc


def encode_xml_file(xml_path: str | Path, output_path: str | Path) -> Path:
    xml_path = Path(xml_path)
    output_path = Path(output_path)
    pkt_bytes = encode_pkt_modern(xml_path.read_bytes())
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(pkt_bytes)
    return output_path


def decode_pkt_file(pkt_path: str | Path, xml_out_path: str | Path) -> Path:
    pkt_path = Path(pkt_path)
    xml_out_path = Path(xml_out_path)
    xml_bytes = decode_pkt_modern(pkt_path.read_bytes())
    xml_out_path.parent.mkdir(parents=True, exist_ok=True)
    xml_out_path.write_bytes(xml_bytes)
    return xml_out_path
