# Packet Tracer 9.0 Format Notes

This skill targets the modern Packet Tracer `.pkt` format described in the
research notes supplied alongside the skill update request.

## High-Level Pipeline

1. Packet Tracer XML bytes
2. qCompress wrapper
3. Stage-2 XOR obfuscation
4. Twofish/EAX encryption with a 16-byte authentication tag
5. Stage-1 reverse/XOR obfuscation

## qCompress Wrapper

The qCompress-compatible wrapper used here is:

- 4-byte big-endian uncompressed length
- zlib-compressed payload

## Modern Codec Constants

- Twofish key: `0x89` repeated 16 times
- EAX nonce seed: `0x10` repeated 16 times
- Tag length: `16`

## Stage-2 XOR

Stage-2 XOR is symmetric:

```text
out[i] = in[i] XOR ((L - i) & 0xFF)
```

where `L` is the input length.

## Stage-1 Obfuscation

For output:

```text
out[L - 1 - i] = in[i] XOR ((L - i * L) & 0xFF)
```

For decode:

```text
clear[i] = obf[L - 1 - i] XOR ((L - i * L) & 0xFF)
```

## Compatibility Notes

- The XML root should be `PACKETTRACER5`
- The targeted version field is `9.0.0.0810`
- Cross-version compatibility is not assumed
- The template library in this skill is a controlled starter set, not a complete
  reverse-engineered clone of all Packet Tracer internals
