#!/usr/bin/env python3
"""Runtime diagnostics for Packet Tracer donor compatibility."""

from __future__ import annotations

import json
from packet_tracer_env import inspect_packet_tracer_compatibility_donor


def main() -> int:
    details = inspect_packet_tracer_compatibility_donor()
    result = {
        "target_version": details.target_version,
        "resolved_donor_path": str(details.resolved_path) if details.resolved_path else "",
        "donor_path": str(details.resolved_path) if details.resolved_path else "",
        "donor_version": details.donor_version or "",
        "donor_source": details.donor_source or "",
        "status": details.status,
        "message": (
            f"{details.resolved_path} (version {details.donor_version})"
            if details.status == "ok" and details.resolved_path and details.donor_version
            else details.blocking_reason or details.status
        ),
        "blocking_reason": details.blocking_reason,
        "candidate_paths": [
            {"source": source, "path": str(path)}
            for source, path in details.candidate_paths[:10]
        ],
    }
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
