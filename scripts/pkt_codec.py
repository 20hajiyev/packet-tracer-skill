from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vendor.twofish import Twofish


BLOCK_SIZE = 16
TAG_LEN = 16
NEW_KEY = bytes([0x89]) * 16
NEW_IV = bytes([0x10]) * 16


def _twofish_cls() -> type["Twofish"]:
    try:
        from vendor.twofish import Twofish
    except ImportError as exc:
        raise ImportError(
            "Packet Tracer modern codec requires a local Twofish bridge. "
            "Set PKT_TWOFISH_LIBRARY or place a local _twofish binary next to scripts/vendor/twofish.py."
        ) from exc
    return Twofish


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
