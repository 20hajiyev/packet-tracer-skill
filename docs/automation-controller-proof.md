# Automation Controller Proof

This proof covers the narrow automation/controller wave for Packet Tracer programming surfaces. It is explicit script-file edit proof, not Network Controller GUI synthesis or broad automation topology generation.

## What This Proves

- Inventory can report existing Python, JavaScript, Blockly, and TCP/UDP app files without dumping full source code.
- Existing Python and JavaScript script files can be replaced when the prompt quotes the device name, app name, and file name.
- TCP/UDP test app JavaScript files can be edited through the same deterministic existing-file path.
- `python_programming`, `javascript_programming`, and `tcp_udp_app` can be treated as `edit_proven` for explicit script-file edits.
- `python_programming`, `javascript_programming`, and `tcp_udp_app` are `donor_backed_ready` for explicit existing-file edits because the proof gate has sample, decode, parser, and editor roundtrip evidence.

## What This Does Not Prove

- It does not create Network Controller projects, apps, or files.
- It does not mutate Blockly visual graphs beyond inventory/report truth.
- It does not create or run VM/IOx workloads.
- It does not synthesize controller policies, REST workflows, or TCP/UDP applications from a broad prompt.
- It does not make any automation/controller feature `generate_ready`.

## Explicit Edit Shape

```text
set "python" script app "New Project (Python)" file "main.py" content "print(\"ok\")"
set "javascript" script app "New Project (JavaScript)" file "main.js" content "console.log(\"ok\")"
set "PC0" script app "tcpServer" file "tcpServer.js" content "console.log(\"tcp\")"
```

The editor refuses ambiguous or missing device/app/file targets. It replaces only existing file content and does not guess app names or create new programming surfaces.

## Product Contract

- `python_programming`, `javascript_programming`, and `tcp_udp_app` can report `edit_supported=true` and `donor_backed_ready=true` only for explicit existing-file edit commands.
- `network_controller`, `blockly_programming`, and `vm_iox` remain report-only.
- All automation/controller features keep `generate_supported=false` until separate donor-backed acceptance evidence exists.
