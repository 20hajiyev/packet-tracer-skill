# Industrial Programming Proof

This proof covers the narrow Packet Tracer programming surface promoted after the `0.2.2` baseline. It is intentionally donor-backed edit readiness, not generate-first support.

## What This Proves

- Real HTTP and Real WebSocket samples expose stable existing script files in Packet Tracer XML.
- Inventory can report programming apps without dumping full source code.
- Explicit quoted commands can replace an existing script file when device, app, and file names are unique.
- Real HTTP and Real WebSocket can be treated as `edit_proven` for deterministic script-file edits.
- Real HTTP and Real WebSocket are the first `donor_backed_ready` atlas entries because they pass a validated proof gate: sample-backed inventory, decode evidence, explicit target resolution, and editor roundtrip proof.

## What This Does Not Prove

- It does not claim broad Industrial IoT topology generation.
- It does not create new apps, new files, MQTT brokers, WebSocket servers, or Real HTTP services.
- It does not claim MQTT protocol mutation, Profinet, PTP, L2NAT, CyberObserver, or industrial firewall edit support.
- It does not make any industrial programming feature `generate_ready`.
- It does not create a new app or file when a donor lacks the named script target.

## Explicit Edit Command Shape

```text
set "Py: real http server 2" script app "New Project (Python)" file "main.py" content "from realhttp import *\nprint(\"ok\")"
set "WebSockets Client" script app "ws client (Python)" file "main.py" content "from realhttp import *\nclient = RealWSClient()\nprint(\"ok\")"
```

The command is quoted on purpose. Packet Tracer app and device names often contain spaces, punctuation, and parentheses. Unquoted script mutation is not supported.

## Donor-Backed Readiness Boundary

`donor_backed_ready` means the skill can safely apply an explicit existing-file script edit when the donor already contains the named device, app, and file. It does not mean broad prompt generation is ready.

Readiness requires all of these to be true:

- the feature is `real_http` or `real_websocket`
- the command quotes a device name, app name, existing file name, and replacement content
- inventory resolves exactly one matching target
- the editor roundtrip test proves the file content can be replaced and decoded again
- no new app, new file, MQTT broker, HTTP service, or WebSocket service is synthesized

## Public Contract

- `real_http`, `real_websocket`, `python_programming`, and `javascript_programming` can report `edit_supported=true` only for explicit existing-file edits.
- `real_http` and `real_websocket` can report `donor_backed_ready=true` for explicit existing-file edits.
- `generate_supported=false` remains the expected result.
- `generate_mismatch_reason=supported_in_edit_only` is the intended parity wording.
- `mqtt`, `visual_scripting`, `ptp`, `profinet`, `l2nat`, `cyberobserver`, and `industrial_firewall` remain report-only until separate roundtrip proof exists.
