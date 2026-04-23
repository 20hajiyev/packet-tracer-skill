# Home IoT Donor Proof

## Proof Goal

Show one honest public proof artifact for the canonical `home_iot` family without claiming broad synthetic smart-home generation.

## Real Donor-Backed Artifacts

- registry entry: `home_iot_cli_edit_v1.pkt`
- proof sources:
  - local inventory from the ignored donor-backed showcase lab
  - checked-in edit roundtrip tests for `iot_registration_server.pkt`, `iot_home_gateway.pkt`, and wireless association donors
- runtime mode used for the proof: Windows Packet Tracer 9.0 with an external bridge override

## Inventory and Edit Proof

Observed Home IoT proof facts:

- a Home Gateway donor path exists
- IoT thing inventory is visible
- gateway-backed registration state is visible in inventory
- edit roundtrip preserves:
  - IoT registration to Home Gateway
  - IoT registration to registration server
  - IoT rule enable/disable state
  - donor-backed wireless association

## Donor-Backed Generate Interpretation

The current product contract for Home IoT is intentionally narrow:

- `iot_registration`, `iot_control`, and `wireless_client_association` are only considered generate-ready when a selected donor exists
- the selected donor must match `IoT/home gateway` or a compatible `wireless-heavy` shape
- the prompt must name deterministic targets such as the thing, gateway/server, client, AP/router, and SSID

This is why the public wording uses `donor-backed constrained-generate` rather than broad `smart home generate-ready`.

## What This Proves

- Home IoT inventory proof exists
- edit roundtrip proof exists for registration, control, and wireless association
- donor-backed Home IoT readiness can be raised without guessed output
- the intended blocker split remains explicit: donor selection vs acceptance vs runtime

## What This Does Not Prove

- it does not prove free-form smart-home topology generation is solved
- it does not prove every prompt mentioning IoT registration is generate-ready
- it does not remove the need for a selected donor and deterministic target resolution
- it does not promote WAN/security features ahead of the next wave

## Public Message Guardrail

Say:

- donor-backed Home IoT proof exists
- registration/control and wireless association are integrated only inside a constrained donor-backed path
- explicit target naming still matters

Do not say:

- all IoT support is solved
- any smart-home prompt can now generate a correct `.pkt`
- donor-backed proof makes runtime or selector constraints disappear
