# Industrial Programming Proof

This proof covers the narrow Packet Tracer programming surface promoted after the `0.2.2` baseline. It is intentionally edit-first, not generate-first.

## What This Proves

- Real HTTP and Real WebSocket samples expose stable existing script files in Packet Tracer XML.
- Inventory can report programming apps without dumping full source code.
- Explicit quoted commands can replace an existing script file when device, app, and file names are unique.
- Real HTTP and Real WebSocket can be treated as `edit_proven` for deterministic script-file edits.

## What This Does Not Prove

- It does not claim broad Industrial IoT topology generation.
- It does not create new apps, new files, MQTT brokers, WebSocket servers, or Real HTTP services.
- It does not claim MQTT protocol mutation, Profinet, PTP, L2NAT, CyberObserver, or industrial firewall edit support.
- It does not make any industrial programming feature `generate_ready`.

## Explicit Edit Command Shape

```text
set "Py: real http server 2" script app "New Project (Python)" file "main.py" content "from realhttp import *\nprint(\"ok\")"
set "WebSockets Client" script app "ws client (Python)" file "main.py" content "from realhttp import *\nclient = RealWSClient()\nprint(\"ok\")"
```

The command is quoted on purpose. Packet Tracer app and device names often contain spaces, punctuation, and parentheses. Unquoted script mutation is not supported.

## Public Contract

- `real_http`, `real_websocket`, `python_programming`, and `javascript_programming` can report `edit_supported=true` only for explicit existing-file edits.
- `generate_supported=false` remains the expected result.
- `generate_mismatch_reason=supported_in_edit_only` is the intended parity wording.
- `mqtt`, `visual_scripting`, `ptp`, `profinet`, `l2nat`, `cyberobserver`, and `industrial_firewall` remain report-only until separate roundtrip proof exists.
