#!/usr/bin/env python3
"""Runtime diagnostics for Packet Tracer donor compatibility."""

from __future__ import annotations

import json
import os
import sys

from packet_tracer_env import _pkt_version, get_packet_tracer_target_version


def main() -> int:
    donor_path = os.getenv("PACKET_TRACER_COMPAT_DONOR") or ""
    target_version = get_packet_tracer_target_version()
    result = {
        "target_version": target_version,
        "donor_path": donor_path,
        "donor_version": "",
        "status": "not_set",
        "message": "",
    }

    if not donor_path:
        result["message"] = "not set"
    elif not os.path.exists(donor_path):
        result["status"] = "missing"
        result["message"] = f"set but missing: {donor_path}"
    else:
        try:
            donor_version = _pkt_version(donor_path)
            result["donor_version"] = donor_version
            if donor_version == target_version:
                result["status"] = "ok"
                result["message"] = f"{donor_path} (version {donor_version})"
            else:
                result["status"] = "version_mismatch"
                result["message"] = (
                    f"{donor_path} (version {donor_version}, expected {target_version})"
                )
        except Exception as exc:  # pragma: no cover - runtime diagnostics
            result["status"] = "decode_error"
            result["message"] = str(exc)

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
