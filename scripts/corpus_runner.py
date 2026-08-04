#!/usr/bin/env python3
"""Run a set of prompts end to end and record what actually happened.

Capability claims in this repo were hand-maintained for a long time, which is
how it ended up asserting things no one had measured. This runner produces the
evidence instead: prompt in, `.pkt` out, structural check, and optionally a real
Packet Tracer open. The result file is the input for any readiness claim.

    python scripts/corpus_runner.py                 # structural tier only
    python scripts/corpus_runner.py --open          # also open each file in PT
    python scripts/corpus_runner.py --case campus   # one case

Results land in `output/corpus-results.json`, which is gitignored: this is
evidence about *this* machine's Packet Tracer, not a portable claim.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

import pkt_verify  # noqa: E402
from pkt_codec import decode_pkt_auto  # noqa: E402

DEFAULT_RESULTS = SKILL_ROOT / "output" / "corpus-results.json"


@dataclass(frozen=True)
class CorpusCase:
    name: str
    prompt: str
    expects: str = "generate"  # generate | refuse | donor_limited | capability_gap
    note: str = ""
    # Markers that must appear in the generated lab for the request to have been
    # honoured. Without this, "verified" meant only that Packet Tracer opened the
    # file -- which a donor-shaped lab does whether or not the prompt's
    # capability was applied. Two cases passed that way: they asked for router
    # DHCP and for server DNS/HTTP, produced neither, and were still counted as
    # verified because the file opened.
    requires_content: tuple[str, ...] = ()


# Deliberately spans the shapes the donor cannot supply directly, because that
# is where `PACKET_TRACER_LINK_STRATEGY=create` is actually exercised.
CORPUS: tuple[CorpusCase, ...] = (
    CorpusCase("minimal", "1 router 1 switch ve 3 komputer qur"),
    CorpusCase("two_switch_chain", "2 switch 1 router ve 4 komputer qur"),
    CorpusCase(
        "hosts_across_switches",
        "3 switch 1 router ve 4 komputer qur",
        requires_content=("switchport mode trunk",),
        note=(
            "hosts on more than one access switch. No case did this, which is why "
            "cloned switches sharing one bridge address went unnoticed: they "
            "announced themselves as a single bridge and only one could reach the "
            "core, so anything behind the others was cut off"
        ),
    ),
    CorpusCase(
        "campus_star_vlan",
        "3 dene switch ve 6 komputer ve 1 router vlanlarda 10,20,30",
        requires_content=("vlan 10", "vlan 20", "vlan 30"),
        note="star target on a chain donor; needs a created link",
    ),
    CorpusCase(
        "four_switch",
        "4 switch 1 router 8 komputer qur",
        note="four switches on a three-switch donor; needs group duplication",
    ),
    CorpusCase("server_lan", "1 router 1 switch 2 komputer 1 server qur"),
    CorpusCase(
        "hosts_only",
        "1 switch ve 5 komputer qur",
        note="more hosts on one switch than the donor group has; needs host duplication",
    ),
    CorpusCase(
        "vlan_uneven",
        "2 switch 1 router 7 komputer vlanlarda 10,20",
        requires_content=("vlan 10", "vlan 20"),
        note="uneven split; the busier switch needs more hosts than the donor gives",
    ),
    CorpusCase(
        "no_devices",
        "sebeke haqqinda melumat ver",
        expects="refuse",
        note="not a topology request; must not invent one",
    ),
    # Beyond plain topology: the capability surface the skill advertises but the
    # corpus has never exercised end to end.
    CorpusCase(
        "vlan_explicit_split",
        "2 switch 1 router 6 komputer vlan 10 da 4 pc vlan 20 de 2 pc",
        requires_content=("vlan 10", "vlan 20"),
        note="explicit host-to-VLAN counts rather than an even default",
    ),
    CorpusCase(
        "router_dhcp",
        "1 router 1 switch 3 komputer qur dhcp routerden verilsin",
        requires_content=("ip dhcp pool",),
        note="router DHCP pool on a flat network, the case the VLAN path misses",
    ),
    CorpusCase(
        "server_services",
        "1 router 1 switch 2 komputer 1 server qur serverde dns ve http olsun",
        # `www.local` is the record this skill writes. A bare `<DNS_SERVER>`
        # marker would pass on donor content alone and prove nothing.
        requires_content=("www.local",),
        note="server service enablement plus a DNS record",
    ),
    CorpusCase(
        "management_telnet",
        "2 switch 1 router 4 komputer qur management vlan 99 ve telnet olsun",
        # `username admin secret cisco` is what enable_telnet writes; the donor's
        # own vty lines would satisfy a looser marker without proving anything.
        requires_content=("interface vlan99", "username admin secret cisco"),
        note="management SVI plus telnet credentials on every switch",
    ),
    CorpusCase(
        "two_routers",
        "2 router 2 switch 4 pc qur",
        # The device name is the proof: R2 exists only if the second router was
        # actually created. This silently produced one router for a long time --
        # the file opened, so nothing reported the loss. The closing tag is
        # matched without the opening one because Packet Tracer writes
        # `<NAME translate="true">`.
        requires_content=(">R2</NAME>",),
        note="more routers than the donor has; needs router duplication",
    ),
    CorpusCase(
        "bare_device_names",
        "router switch pc qur",
        note="devices named with no counts; one of each is the only sensible reading",
    ),
    CorpusCase(
        "hosts_without_a_switch",
        "bir sebeke lazimdir 10 kompyuter ucun",
        note="hosts named with nothing to plug into; a switch has to be inferred",
    ),
    CorpusCase(
        "named_model",
        "2911 router ve 2960 switch ile 3 pc qur",
        # The model number sits exactly where a count goes; this asked for two
        # thousand nine hundred and eleven routers and planned for minutes.
        note="device models named in the prompt must not be read as counts",
    ),
    CorpusCase(
        "ospf_routing",
        "2 router 3 switch 6 komputer qur vlanlarda 10,20 ospf olsun",
        requires_content=("router ospf",),
        note="routing was refused by a hand-maintained acceptance table until measured",
    ),
    CorpusCase(
        "eigrp_routing",
        "2 router 2 switch 4 komputer qur eigrp olsun",
        requires_content=("router eigrp",),
        note="the same emission path as OSPF, different protocol",
    ),
    CorpusCase(
        "nat_internet",
        "1 router 1 switch 4 komputer qur nat olsun",
        requires_content=("ip nat",),
        note="NAT overload plus the ACL that feeds it",
    ),
    CorpusCase(
        "acl_security",
        "2 router 2 switch 6 komputer qur acl olsun",
        requires_content=("access-list",),
        note="named standard ACL with a permit rule",
    ),
    CorpusCase(
        "stp_hardening",
        "2 switch 1 router 4 komputer qur stp olsun",
        requires_content=("spanning-tree",),
        note="rapid-pvst with the core as root",
    ),
    CorpusCase(
        "hsrp_redundancy",
        "2 router 2 switch 6 komputer qur hsrp olsun",
        requires_content=("standby",),
        note="first-hop redundancy; needs a virtual address or it configures nothing",
    ),
    CorpusCase(
        "ipv6_dual_stack",
        "2 router 2 switch 6 komputer qur ipv6 ve ospfv3 olsun",
        requires_content=("ipv6 unicast-routing", "2001:db8"),
        note="plain `ipv6` was not even a capability until measured",
    ),
    CorpusCase(
        "voip_telephony",
        "1 router 2 switch 4 komputer qur voip olsun",
        requires_content=("telephony-service",),
        note="Call Manager Express with a directory number per phone",
    ),
    CorpusCase(
        "server_farm_services",
        "1 router 1 switch 2 komputer 1 server qur serverde ftp ve tftp olsun",
        requires_content=("ftp",),
        note="the services beyond dns/http that the enable map already knew",
    ),
    CorpusCase(
        "management_services",
        "1 router 1 switch 1 server qur ntp ve syslog olsun",
        requires_content=("ntp", "syslog"),
        note="refused for a wiring preference nobody expressed; blocked four capabilities",
    ),
    CorpusCase(
        "gre_tunnel",
        "2 router 2 switch 4 komputer qur gre tunnel olsun",
        requires_content=("interface tunnel",),
        note="refused by a coverage table while the lab it would build opened fine",
    ),
    CorpusCase(
        "multiarea_ospf",
        "3 router 2 switch 6 komputer qur multi area ospf olsun vlanlarda 10,20,30",
        requires_content=("area 1",),
        note="every OSPF lab was single-area whatever the prompt asked",
    ),
    CorpusCase(
        "dhcp_snooping",
        "2 switch 1 router 4 komputer qur dhcp snooping olsun",
        requires_content=("ip dhcp snooping",),
        note="recognised by the parser, emitted by nobody",
    ),
    CorpusCase(
        "wireless_ssid",
        "1 wireless router 2 laptop qur ssid EvSebeke wpa2 sifre Gizli123",
        # The network name and secret are the proof. Without the wireless ops the
        # lab keeps whatever network the donor was configured with.
        requires_content=("EvSebeke", "Gizli123"),
        note="names the wireless network and puts the clients on it",
    ),
    CorpusCase(
        "wireless_home",
        "1 wireless router 2 laptop qur",
        # Was reported as a donor limitation for weeks. It was a donor
        # *selection* limitation: the base pool held one lab, and this machine
        # had wireless-capable labs all along.
        requires_content=(">WRT1</NAME>", ">Laptop2</NAME>"),
        note="needs a donor the primary pool does not contain; exercises local-lab widening",
    ),
)


@dataclass
class CaseResult:
    name: str
    prompt: str
    expects: str
    note: str = ""
    generated: bool = False
    structural_passed: bool | None = None
    device_count: int = 0
    link_count: int = 0
    version: str = ""
    container: str = ""
    open_status: str = ""
    seconds: float = 0.0
    outcome: str = ""
    detail: str = ""
    failures: list[str] = field(default_factory=list)


def _missing_content(pkt_path: Path, required: tuple[str, ...]) -> list[str]:
    """Markers the prompt asked for that the generated lab does not contain."""
    try:
        decoded = decode_pkt_auto(pkt_path.read_bytes())
    except Exception as error:  # noqa: BLE001 - reported, not raised
        return [f"could not decode to check content ({error})"]
    payload = decoded[0] if isinstance(decoded, tuple) else decoded
    text = payload.decode("utf-8", "replace").lower()
    return [marker for marker in required if marker.lower() not in text]


def run_case(case: CorpusCase, output_dir: Path, do_open: bool, timeout: int) -> CaseResult:
    result = CaseResult(name=case.name, prompt=case.prompt, expects=case.expects, note=case.note)
    output_path = output_dir / f"corpus_{case.name}.pkt"
    output_path.unlink(missing_ok=True)

    started = time.monotonic()
    completed = subprocess.run(
        [sys.executable, str(SKILL_ROOT / "scripts" / "generate_pkt.py"),
         "--prompt", case.prompt, "--output", str(output_path)],
        capture_output=True,
        text=True,
        cwd=str(SKILL_ROOT),
    )
    result.seconds = round(time.monotonic() - started, 1)
    result.generated = output_path.exists()

    if not result.generated:
        result.detail = (completed.stdout or completed.stderr or "").strip()[-400:]
        if case.expects == "refuse":
            result.outcome = "refused_as_expected"
        elif case.expects == "capability_gap":
            # Recognised in the prompt, not implemented for generation. Distinct
            # from a donor limit: a richer donor would not help.
            result.outcome = "refused_capability_gap"
        elif case.expects == "donor_limited":
            # Not a defect: the request is sound and the local donor cannot serve
            # it. Kept visible rather than folded into "expected" so the gap stays
            # countable, but it does not fail the run.
            result.outcome = "refused_donor_limited"
        else:
            result.outcome = "unexpected_refusal"
        return result

    if case.expects == "refuse":
        result.outcome = "unexpected_generation"

    report = pkt_verify.structural_check(output_path)
    result.structural_passed = report.passed
    result.device_count = report.device_count
    result.link_count = report.link_count
    result.version = report.version
    result.container = report.container
    result.failures = report.failures

    if not report.passed:
        result.outcome = result.outcome or "structural_failed"
        return result

    if case.requires_content:
        missing = _missing_content(output_path, case.requires_content)
        if missing:
            # The file opens, but it does not do what was asked. Counting this as
            # verified is how two capability gaps hid in plain sight.
            result.failures.append(
                "generated lab is missing what the prompt asked for: " + ", ".join(missing)
            )
            result.outcome = result.outcome or (
                "refused_capability_gap" if case.expects == "capability_gap" else "content_missing"
            )
            return result
        if case.expects == "capability_gap":
            result.outcome = "unexpected_capability"

    if do_open:
        open_report = pkt_verify.open_check(output_path, timeout_seconds=timeout)
        result.open_status = open_report.status
        result.outcome = result.outcome or ("verified" if open_report.opened else "generated_unverified")
    else:
        result.outcome = result.outcome or "generated_unverified"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--open", action="store_true", help="launch Packet Tracer for each generated file")
    parser.add_argument("--case", action="append", help="run only these cases (repeatable)")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    args = parser.parse_args()

    selected = [case for case in CORPUS if not args.case or case.name in args.case]
    if not selected:
        print(f"no cases matched {args.case}", file=sys.stderr)
        return 2

    output_dir = SKILL_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for case in selected:
        result = run_case(case, output_dir, args.open, args.timeout)
        results.append(result)
        flag = {
            "verified": "OK  ",
            "generated_unverified": "GEN ",
            "refused_as_expected": "REF ",
            "refused_donor_limited": "GAP ",
            "refused_capability_gap": "CAP ",
        }.get(result.outcome, "FAIL")
        print(
            f"{flag} {result.name:20} {result.outcome:22} "
            f"devices={result.device_count:<3} links={result.link_count:<3} "
            f"open={result.open_status or '-':16} {result.seconds}s"
        )
        if result.failures:
            for failure in result.failures[:3]:
                print(f"       {failure}")

    payload = {
        "cases": [asdict(item) for item in results],
        "verified": sum(1 for item in results if item.outcome == "verified"),
        "donor_limited": sum(1 for item in results if item.outcome == "refused_donor_limited"),
        "capability_gap": sum(1 for item in results if item.outcome == "refused_capability_gap"),
        "generated": sum(1 for item in results if item.generated),
        "unexpected": sum(
            1
            for item in results
            if item.outcome
            in {
                "unexpected_refusal",
                "unexpected_generation",
                "structural_failed",
                "content_missing",
                "unexpected_capability",
            }
        ),
        "total": len(results),
    }
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(
        f"\n{payload['generated']}/{payload['total']} generated, "
        f"{payload['verified']} opened in Packet Tracer, "
        f"{payload['unexpected']} unexpected. Results: {args.results}"
    )
    return 1 if payload["unexpected"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
