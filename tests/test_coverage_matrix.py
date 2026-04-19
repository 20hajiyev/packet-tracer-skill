from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from coverage_matrix import (  # noqa: E402
    build_blueprint_plan,
    build_capability_matrix,
    build_coverage_gap_report,
    build_donor_graph_fit,
    build_inventory_capability_report,
    select_capability_matrix_hits,
)
from intent_parser import parse_intent  # noqa: E402
from sample_catalog import SampleDescriptor  # noqa: E402


def _sample(origin: str, *, donor_eligible: bool, prototype_eligible: bool, relative_path: str = "sample.pkt") -> SampleDescriptor:
    return SampleDescriptor(
        path=relative_path,
        relative_path=relative_path,
        version="9.0.0.0810",
        device_count=4,
        link_count=3,
        devices=[
            {"name": "R1", "type": "Router", "model": "ISR4331"},
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
            {"name": "AP1", "type": "LightWeightAccessPoint", "model": "AccessPoint-PT"},
            {"name": "Server1", "type": "Server", "model": "Server-PT"},
        ],
        links=[{"from": "R1", "to": "SW1", "media": "eStraightThrough"}],
        capability_tags=["vlan", "wireless_ap", "server_dns"],
        topology_tags=["department_lan", "wireless_edge"],
        preferred_roles=["preferred_vlan", "preferred_wireless"],
        trust_level="trusted" if origin == "cisco-local" else "curated",
        origin=origin,
        role="primary",
        prototype_eligible=prototype_eligible,
        donor_eligible=donor_eligible,
        service_support=["dns"],
        wireless_mode_tags=["ap_bridge"],
        device_families=["routers", "switches", "access points", "servers"],
        model_families=["ISR4331", "2960-24TT", "AccessPoint-PT", "Server-PT"],
        port_media_types=["eStraightThrough"],
        runtime_features=["service_runtime", "wireless_runtime"],
        donor_graph_fingerprint={"link_count": 1, "named_pairs": ["R1 <-> SW1"], "media_types": ["eStraightThrough"]},
        apply_safety_level="acceptance-verified" if origin == "cisco-local" else "safe-open-generate-supported",
    )


def test_build_capability_matrix_tracks_best_maturity() -> None:
    entries = build_capability_matrix(
        [
            _sample("external-curated", donor_eligible=True, prototype_eligible=True, relative_path="curated.pkt"),
            _sample("cisco-local", donor_eligible=True, prototype_eligible=True, relative_path="cisco.pkt"),
        ]
    )
    vlan_router_entry = next(entry for entry in entries if entry.device_family == "routers" and entry.capability == "vlan")
    assert vlan_router_entry.maturity_level == "acceptance-verified"
    assert "cisco.pkt" in vlan_router_entry.accepted_donors


def test_build_capability_matrix_maps_advanced_server_service_support() -> None:
    sample = SampleDescriptor(
        path="advanced_services.pkt",
        relative_path="advanced_services.pkt",
        version="9.0.0.0810",
        device_count=1,
        link_count=0,
        devices=[{"name": "Server0", "type": "Server", "model": "Server-PT"}],
        links=[],
        capability_tags=[],
        topology_tags=["server_services"],
        preferred_roles=["preferred_services"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        service_support=["email", "syslog", "aaa"],
        device_families=["servers"],
        apply_safety_level="acceptance-verified",
    )
    entries = build_capability_matrix([sample])
    entry_map = {(entry.device_family, entry.capability): entry for entry in entries}
    assert ("servers", "server_email") in entry_map
    assert ("servers", "server_syslog") in entry_map
    assert ("servers", "server_aaa") in entry_map


def test_build_coverage_gap_report_supports_advanced_server_service_capabilities() -> None:
    plan = parse_intent("enable email on Server0 enable syslog on Server0 enable aaa on Server0")
    sample = SampleDescriptor(
        path="advanced_services.pkt",
        relative_path="advanced_services.pkt",
        version="9.0.0.0810",
        device_count=1,
        link_count=0,
        devices=[{"name": "Server0", "type": "Server", "model": "Server-PT"}],
        links=[],
        capability_tags=[],
        topology_tags=["server_services"],
        preferred_roles=["preferred_services"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        service_support=["email", "syslog", "aaa"],
        device_families=["servers"],
        apply_safety_level="acceptance-verified",
    )
    report = build_coverage_gap_report(plan, [sample])
    assert {"server_email", "server_syslog", "server_aaa"} <= set(report.supported_capabilities)
    status_by_capability = {status["capability"]: status for status in report.capability_statuses}
    assert status_by_capability["server_email"]["acceptance_verified"] is True
    assert status_by_capability["server_syslog"]["acceptance_verified"] is True
    assert status_by_capability["server_aaa"]["acceptance_verified"] is True


def test_build_capability_matrix_derives_iot_registration_and_control() -> None:
    sample = SampleDescriptor(
        path="iot_capabilities.pkt",
        relative_path="iot_capabilities.pkt",
        version="9.0.0.0810",
        device_count=3,
        link_count=1,
        devices=[
            {"name": "Server0", "type": "Server", "model": "Server-PT"},
            {"name": "Home Gateway0", "type": "HomeGateway", "model": "HomeGateway-PT"},
            {"name": "Door0", "type": "MCUComponent", "model": "Door"},
        ],
        links=[],
        capability_tags=["iot"],
        topology_tags=["general"],
        preferred_roles=["preferred_iot"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        device_families=["servers", "home/wireless routers", "iot devices"],
        iot_roles=["server", "gateway", "thing"],
        apply_safety_level="acceptance-verified",
    )
    entries = build_capability_matrix([sample])
    entry_map = {(entry.device_family, entry.capability): entry for entry in entries}
    assert ("iot devices", "iot") in entry_map
    assert ("iot devices", "iot_registration") in entry_map
    assert ("iot devices", "iot_control") in entry_map


def test_build_coverage_gap_report_keeps_iot_capabilities_manual_acceptance_gated() -> None:
    plan = parse_intent("iot smart home qur register CO2 to Server0 and control Garage through Home Gateway0")
    sample = SampleDescriptor(
        path="iot_capabilities.pkt",
        relative_path="iot_capabilities.pkt",
        version="9.0.0.0810",
        device_count=3,
        link_count=1,
        devices=[
            {"name": "Server0", "type": "Server", "model": "Server-PT"},
            {"name": "Home Gateway0", "type": "HomeGateway", "model": "HomeGateway-PT"},
            {"name": "Door0", "type": "MCUComponent", "model": "Door"},
        ],
        links=[],
        capability_tags=["iot"],
        topology_tags=["general"],
        preferred_roles=["preferred_iot"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        device_families=["servers", "home/wireless routers", "iot devices"],
        iot_roles=["server", "gateway", "thing"],
        apply_safety_level="acceptance-verified",
    )
    report = build_coverage_gap_report(plan, [sample])
    status_by_capability = {status["capability"]: status for status in report.capability_statuses}
    assert {"iot", "iot_registration", "iot_control"} <= set(report.supported_capabilities)
    assert {"iot", "iot_registration", "iot_control"} <= set(report.requires_manual_acceptance)
    assert status_by_capability["iot_registration"]["acceptance_verified"] is False
    assert status_by_capability["iot_registration"]["requires_manual_acceptance"] is True
    assert status_by_capability["iot_control"]["acceptance_verified"] is False


def test_build_inventory_capability_report_derives_iot_registration_and_control() -> None:
    payload = {
        "topology_summary": {"device_counts": {"HomeGateway": 1, "MCUComponent": 2, "Server": 1}},
        "iot": {
            "Home Gateway0": {"role": "gateway"},
            "Server0": {"role": "server"},
            "Door0": {"role": "thing"},
            "Garage0": {"role": "thing"},
        },
    }
    report = build_inventory_capability_report(payload)
    assert {"iot", "iot_registration", "iot_control"} <= set(report["capabilities"])


def test_build_capability_matrix_derives_phase_a_switching_capabilities() -> None:
    sample = SampleDescriptor(
        path="phase_a.pkt",
        relative_path="phase_a.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=1,
        devices=[
            {"name": "R1", "type": "Router", "model": "ISR4331"},
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
        ],
        links=[],
        capability_tags=["vlan", "management_vlan"],
        topology_tags=["router_on_a_stick"],
        preferred_roles=["preferred_vlan", "preferred_management"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        apply_safety_level="acceptance-verified",
    )
    entries = build_capability_matrix([sample])
    entry_map = {(entry.device_family, entry.capability): entry for entry in entries}
    assert ("switches", "trunk") in entry_map
    assert ("switches", "access_port") in entry_map
    assert ("switches", "management_vlan") in entry_map
    assert ("switches", "telnet") in entry_map
    assert ("routers", "router_on_a_stick") in entry_map


def test_build_capability_matrix_derives_printer_and_verification() -> None:
    sample = SampleDescriptor(
        path="printer_lab.pkt",
        relative_path="printer_lab.pkt",
        version="9.0.0.0810",
        device_count=3,
        link_count=2,
        devices=[
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
            {"name": "PC1", "type": "PC", "model": "PC-PT"},
            {"name": "PRN1", "type": "Printer", "model": "Printer-PT"},
        ],
        links=[],
        capability_tags=["host_server"],
        topology_tags=["department_lan"],
        preferred_roles=["preferred_general"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        apply_safety_level="acceptance-verified",
    )
    entries = build_capability_matrix([sample])
    entry_map = {(entry.device_family, entry.capability): entry for entry in entries}
    assert ("end devices", "printer") in entry_map
    assert ("end devices", "verification") in entry_map
    assert ("switches", "verification") in entry_map


def test_build_capability_matrix_derives_end_device_mutation_and_wireless_client() -> None:
    sample = SampleDescriptor(
        path="wireless_clients.pkt",
        relative_path="wireless_clients.pkt",
        version="9.0.0.0810",
        device_count=3,
        link_count=1,
        devices=[
            {"name": "AP1", "type": "LightWeightAccessPoint", "model": "AccessPoint-PT"},
            {"name": "TAB1", "type": "Tablet", "model": "TabletPC-PT"},
            {"name": "LAP1", "type": "Laptop", "model": "Laptop-PT"},
        ],
        links=[],
        capability_tags=["wireless_ap"],
        topology_tags=["wireless_edge"],
        preferred_roles=["preferred_wireless"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        wireless_mode_tags=["ap_bridge"],
        apply_safety_level="acceptance-verified",
    )
    entries = build_capability_matrix([sample])
    entry_map = {(entry.device_family, entry.capability): entry for entry in entries}
    assert ("end devices", "end_device_mutation") in entry_map
    assert ("access points", "wireless_mutation") in entry_map
    assert ("end devices", "wireless_client") in entry_map
    assert ("end devices", "wireless_client_association") in entry_map


def test_build_capability_matrix_uses_apply_safety_for_end_device_mutation() -> None:
    sample = SampleDescriptor(
        path="safe_end_devices.pkt",
        relative_path="safe_end_devices.pkt",
        version="8.2.1.4208",
        device_count=2,
        link_count=1,
        devices=[
            {"name": "PC1", "type": "PC", "model": "PC-PT"},
            {"name": "PRN1", "type": "Printer", "model": "Printer-PT"},
        ],
        links=[],
        capability_tags=["host_server"],
        topology_tags=["department_lan"],
        preferred_roles=["preferred_general"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        apply_safety_level="safe-open-generate-supported",
    )
    entries = build_capability_matrix([sample])
    end_device_entry = next(
        entry for entry in entries if entry.device_family == "end devices" and entry.capability == "end_device_mutation"
    )
    assert end_device_entry.maturity_level == "safe-open-generate-supported"


def test_build_coverage_gap_report_marks_curated_and_manual_acceptance() -> None:
    plan = parse_intent("6 sobeli sebeke qur, vlan, dns, ap olsun")
    plan.capabilities = ["vlan", "wireless_ap", "dns", "iot"]
    plan.device_requirements = {"Router": 1, "Switch": 2, "LightWeightAccessPoint": 2}
    report = build_coverage_gap_report(
        plan,
        [
            _sample("cisco-local", donor_eligible=True, prototype_eligible=True, relative_path="cisco.pkt"),
            SampleDescriptor(
                path="iot_ref.pkt",
                relative_path="iot_ref.pkt",
                version="9.0.0.0810",
                device_count=2,
                link_count=1,
                devices=[{"name": "IoT1", "type": "IoT", "model": "Thing"}],
                links=[],
                capability_tags=["iot"],
                topology_tags=["general"],
                preferred_roles=["preferred_iot"],
                trust_level="reference-only",
                origin="external-reference",
                role="reference",
                prototype_eligible=False,
                donor_eligible=False,
                device_families=["iot devices"],
                apply_safety_level="reference-known",
            ),
        ],
    )
    assert "vlan" in report.supported_capabilities
    assert "iot" in report.supported_capabilities
    assert "iot" in report.requires_manual_acceptance
    assert any(status["capability"] == "wireless_ap" for status in report.capability_statuses)
    assert report.recommended_next_actions


def test_build_coverage_gap_report_uses_best_entry_for_manual_acceptance() -> None:
    plan = parse_intent("campus sebekesi qur wifi")
    plan.capabilities = ["wireless_ap"]
    plan.device_requirements = {"LightWeightAccessPoint": 2, "Tablet": 2}
    report = build_coverage_gap_report(
        plan,
        [
            _sample("external-curated", donor_eligible=True, prototype_eligible=True, relative_path="curated_wireless.pkt"),
            _sample("cisco-local", donor_eligible=True, prototype_eligible=True, relative_path="cisco_wireless.pkt"),
        ],
    )
    status_by_capability = {status["capability"]: status for status in report.capability_statuses}
    assert "wireless_ap" not in report.requires_curated_donor
    assert "wireless_ap" not in report.requires_manual_acceptance
    assert status_by_capability["wireless_ap"]["requires_curated_donor"] is False
    assert status_by_capability["wireless_ap"]["requires_manual_acceptance"] is False
    assert status_by_capability["wireless_ap"]["best_maturity_level"] == "acceptance-verified"


def test_build_coverage_gap_report_promotes_end_device_mutation_to_safe_open() -> None:
    plan = parse_intent("set Tablet0 dns 192.168.10.20 set PC1 ipv4 dhcp")
    report = build_coverage_gap_report(
        plan,
        [
            SampleDescriptor(
                path="safe_end_devices.pkt",
                relative_path="safe_end_devices.pkt",
                version="8.2.1.4208",
                device_count=2,
                link_count=1,
                devices=[
                    {"name": "PC1", "type": "PC", "model": "PC-PT"},
                    {"name": "TAB1", "type": "Tablet", "model": "TabletPC-PT"},
                ],
                links=[],
                capability_tags=["host_server"],
                topology_tags=["department_lan"],
                preferred_roles=["preferred_general"],
                trust_level="trusted",
                origin="cisco-local",
                role="primary",
                prototype_eligible=True,
                donor_eligible=True,
                apply_safety_level="safe-open-generate-supported",
            )
        ],
    )
    status_by_capability = {status["capability"]: status for status in report.capability_statuses}
    assert status_by_capability["end_device_mutation"]["best_maturity_level"] == "safe-open-generate-supported"
    assert status_by_capability["end_device_mutation"]["safe_open_generate_supported"] is True
    assert status_by_capability["end_device_mutation"]["requires_manual_acceptance"] is True


def test_build_coverage_gap_report_supports_wireless_client_association_when_best_donor_is_verified() -> None:
    plan = parse_intent("associate Tablet0 to AP1 ssid FIN_WIFI dhcp")
    report = build_coverage_gap_report(
        plan,
        [
            _sample("external-curated", donor_eligible=True, prototype_eligible=True, relative_path="curated_wireless_assoc.pkt"),
            _sample("cisco-local", donor_eligible=True, prototype_eligible=True, relative_path="cisco_wireless_assoc.pkt"),
        ],
    )
    status_by_capability = {status["capability"]: status for status in report.capability_statuses}
    assert "wireless_client_association" in report.supported_capabilities
    assert "wireless_client_association" not in report.requires_manual_acceptance
    assert status_by_capability["wireless_client_association"]["acceptance_verified"] is True
    assert status_by_capability["wireless_client_association"]["requires_manual_acceptance"] is False


def test_build_coverage_gap_report_supports_wireless_mutation_when_best_donor_is_verified() -> None:
    plan = parse_intent("set AP1 ssid FIN_WIFI security wpa2-psk passphrase fin12345 channel 6")
    report = build_coverage_gap_report(
        plan,
        [
            _sample("external-curated", donor_eligible=True, prototype_eligible=True, relative_path="curated_wireless_mutation.pkt"),
            _sample("cisco-local", donor_eligible=True, prototype_eligible=True, relative_path="cisco_wireless_mutation.pkt"),
        ],
    )
    status_by_capability = {status["capability"]: status for status in report.capability_statuses}
    assert "wireless_mutation" in report.supported_capabilities
    assert "wireless_mutation" not in report.requires_manual_acceptance
    assert status_by_capability["wireless_mutation"]["acceptance_verified"] is True
    assert status_by_capability["wireless_mutation"]["requires_manual_acceptance"] is False


def test_select_capability_matrix_hits_filters_to_requested_capabilities_and_provider_families() -> None:
    plan = parse_intent("3 dene switch ve 6 komputer ve 1 router vlanlarda 10,20,30")
    plan.capabilities = ["vlan", "trunk", "router_on_a_stick"]
    plan.device_requirements = {"Router": 1, "Switch": 3, "PC": 6}
    hits = select_capability_matrix_hits(
        plan,
        [
            _sample("cisco-local", donor_eligible=True, prototype_eligible=True, relative_path="cisco.pkt"),
            SampleDescriptor(
                path="server_only.pkt",
                relative_path="server_only.pkt",
                version="9.0.0.0810",
                device_count=1,
                link_count=0,
                devices=[{"name": "Server1", "type": "Server", "model": "Server-PT"}],
                links=[],
                capability_tags=["server_http", "host_server"],
                topology_tags=["general"],
                preferred_roles=[],
                trust_level="trusted",
                origin="cisco-local",
                role="primary",
                prototype_eligible=True,
                donor_eligible=True,
                device_families=["servers"],
                apply_safety_level="acceptance-verified",
            ),
        ],
    )
    assert hits
    assert {entry.capability for entry in hits} == {"vlan", "trunk", "router_on_a_stick"}
    assert all(entry.device_family in {"routers", "switches", "multilayer switches"} for entry in hits)


def test_build_coverage_gap_report_tracks_best_maturity_per_capability() -> None:
    plan = parse_intent("campus sebekesi qur dns dhcp wifi")
    plan.capabilities = ["dhcp_pool", "server_dns", "wireless_ap"]
    report = build_coverage_gap_report(
        plan,
        [
            _sample("cisco-local", donor_eligible=True, prototype_eligible=True, relative_path="cisco.pkt"),
            _sample("external-curated", donor_eligible=True, prototype_eligible=True, relative_path="curated.pkt"),
        ],
    )
    status_by_capability = {status["capability"]: status for status in report.capability_statuses}
    assert status_by_capability["wireless_ap"]["acceptance_verified"] is True
    assert status_by_capability["wireless_ap"]["best_maturity_level"] == "acceptance-verified"
    assert status_by_capability["wireless_ap"]["edit_supported"] is True
    assert status_by_capability["server_dns"]["config_mutation_supported"] is True


def test_build_coverage_gap_report_classifies_campus_readiness() -> None:
    plan = parse_intent("campus sebekesi qur vlan management telnet acl")
    plan.capabilities = ["router_on_a_stick", "trunk", "access_port", "management_vlan", "telnet", "acl"]
    plan.device_requirements = {"Router": 1, "Switch": 2}
    sample = SampleDescriptor(
        path="campus_ready.pkt",
        relative_path="campus_ready.pkt",
        version="9.0.0.0810",
        device_count=3,
        link_count=2,
        devices=[
            {"name": "R1", "type": "Router", "model": "ISR4331"},
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
            {"name": "SW2", "type": "Switch", "model": "2960-24TT"},
        ],
        links=[],
        capability_tags=["vlan", "management_vlan", "acl"],
        topology_tags=["router_on_a_stick", "department_lan"],
        preferred_roles=["preferred_vlan", "preferred_management"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        apply_safety_level="acceptance-verified",
    )
    report = build_coverage_gap_report(plan, [sample])
    assert report.scenario_family == "campus"
    assert report.scenario_generate_readiness["status"] == "ready"
    assert "router_on_a_stick" in report.scenario_generate_readiness["critical_capabilities"]


def test_build_coverage_gap_report_classifies_service_heavy_as_donor_limited() -> None:
    plan = parse_intent("dns dhcp ftp email syslog aaa server sebekesi qur")
    plan.capabilities = ["server_dns", "server_dhcp", "server_ftp", "server_email", "server_syslog", "server_aaa"]
    plan.device_requirements = {"Server": 1, "PC": 1}
    sample = SampleDescriptor(
        path="service_curated.pkt",
        relative_path="service_curated.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=1,
        devices=[
            {"name": "Server0", "type": "Server", "model": "Server-PT"},
            {"name": "PC0", "type": "PC", "model": "PC-PT"},
        ],
        links=[],
        capability_tags=[],
        topology_tags=["server_services"],
        preferred_roles=["preferred_services"],
        trust_level="curated",
        origin="external-curated",
        role="secondary",
        prototype_eligible=True,
        donor_eligible=True,
        service_support=["dns", "dhcp", "ftp", "email", "syslog", "aaa"],
        device_families=["servers", "end devices"],
        apply_safety_level="safe-open-generate-supported",
    )
    report = build_coverage_gap_report(plan, [sample])
    assert report.scenario_family == "service_heavy"
    assert report.scenario_generate_readiness["status"] == "donor_limited"
    assert "server_email" in report.scenario_generate_readiness["critical_capabilities"]


def test_build_coverage_gap_report_classifies_home_iot_as_acceptance_gated() -> None:
    plan = parse_intent("home iot sebekesi qur register qapi cihazlarini gatewaye qos")
    plan.capabilities = ["iot", "iot_registration", "iot_control", "wireless_ap"]
    plan.device_requirements = {"HomeGateway": 1, "MCUComponent": 2}
    sample = SampleDescriptor(
        path="home_iot_ready.pkt",
        relative_path="home_iot_ready.pkt",
        version="9.0.0.0810",
        device_count=3,
        link_count=2,
        devices=[
            {"name": "Home Gateway0", "type": "HomeGateway", "model": "HomeGateway-PT"},
            {"name": "Door0", "type": "MCUComponent", "model": "Door"},
            {"name": "Door1", "type": "MCUComponent", "model": "Door"},
        ],
        links=[],
        capability_tags=["iot", "wireless_ap"],
        topology_tags=["wireless_edge"],
        preferred_roles=["preferred_iot"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        wireless_mode_tags=["home_router_edge"],
        iot_roles=["gateway", "thing"],
        device_families=["home/wireless routers", "iot devices"],
        apply_safety_level="acceptance-verified",
    )
    report = build_coverage_gap_report(plan, [sample])
    assert report.scenario_family == "home_iot"
    assert report.scenario_generate_readiness["status"] == "acceptance_gated"
    assert "iot_registration" in report.scenario_generate_readiness["critical_capabilities"]
    assert report.scenario_generate_readiness["reasons"]


def test_build_coverage_gap_report_supports_phase_a_switching_capabilities() -> None:
    plan = parse_intent("router-on-a-stick trunk access management telnet")
    plan.capabilities = ["router_on_a_stick", "trunk", "access_port", "management_vlan", "telnet"]
    plan.device_requirements = {"Router": 1, "Switch": 1}
    sample = SampleDescriptor(
        path="phase_a.pkt",
        relative_path="phase_a.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=1,
        devices=[
            {"name": "R1", "type": "Router", "model": "ISR4331"},
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
        ],
        links=[],
        capability_tags=["vlan", "management_vlan"],
        topology_tags=["router_on_a_stick"],
        preferred_roles=["preferred_vlan", "preferred_management"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        apply_safety_level="acceptance-verified",
    )
    report = build_coverage_gap_report(plan, [sample])
    assert not report.unsupported_capabilities
    status_by_capability = {status["capability"]: status for status in report.capability_statuses}
    assert status_by_capability["router_on_a_stick"]["acceptance_verified"] is True
    assert status_by_capability["trunk"]["safe_open_generate_supported"] is True
    assert status_by_capability["access_port"]["edit_supported"] is True
    assert status_by_capability["management_vlan"]["acceptance_verified"] is True
    assert status_by_capability["telnet"]["acceptance_verified"] is True


def test_build_coverage_gap_report_supports_printer_and_verification() -> None:
    plan = parse_intent("printer verification")
    plan.capabilities = ["printer", "verification"]
    plan.device_requirements = {"Switch": 1, "PC": 1, "Printer": 1}
    sample = SampleDescriptor(
        path="printer_lab.pkt",
        relative_path="printer_lab.pkt",
        version="9.0.0.0810",
        device_count=3,
        link_count=2,
        devices=[
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
            {"name": "PC1", "type": "PC", "model": "PC-PT"},
            {"name": "PRN1", "type": "Printer", "model": "Printer-PT"},
        ],
        links=[],
        capability_tags=["host_server"],
        topology_tags=["department_lan"],
        preferred_roles=["preferred_general"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        apply_safety_level="acceptance-verified",
    )
    report = build_coverage_gap_report(plan, [sample])
    assert not report.unsupported_capabilities
    status_by_capability = {status["capability"]: status for status in report.capability_statuses}
    assert status_by_capability["printer"]["acceptance_verified"] is True
    assert status_by_capability["verification"]["safe_open_generate_supported"] is True


def test_build_donor_graph_fit_detects_media_and_port_conflicts() -> None:
    sample = SampleDescriptor(
        path="sample.pkt",
        relative_path="sample.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=1,
        devices=[
            {"name": "R1", "type": "Router", "model": "ISR4331"},
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
        ],
        links=[
            {
                "from": "R1",
                "to": "SW1",
                "media": "eStraightThrough",
                "ports": ["GigabitEthernet0/0/1", "GigabitEthernet0/1"],
            }
        ],
        capability_tags=["vlan"],
        topology_tags=["department_lan"],
        preferred_roles=[],
    )
    blueprint = {
        "topology_archetype": "chain",
        "devices": [{"name": "R1"}, {"name": "SW1"}],
        "links": [
            {
                "a": {"dev": "R1", "port": "GigabitEthernet0/0/0"},
                "b": {"dev": "SW1", "port": "GigabitEthernet0/1"},
                "media": "crossover",
            }
        ]
    }
    fit = build_donor_graph_fit(sample, blueprint)
    assert fit.matched_pairs == ["R1 <-> SW1"]
    assert fit.port_media_conflicts
    assert fit.layout_reuse_score > 0
    assert any("media mismatch" in conflict for conflict in fit.port_media_conflicts)
    assert any("port mismatch" in conflict for conflict in fit.port_media_conflicts)


def test_build_blueprint_plan_uses_plan_links_when_blueprint_missing() -> None:
    plan = parse_intent("set SW1 vlan 10 name Finance")
    plan.device_requirements = {"Switch": 1, "Router": 1}
    plan.capabilities = ["vlan"]
    plan.links = [
        {
            "a": {"dev": "SW1", "port": "GigabitEthernet0/1"},
            "b": {"dev": "R1", "port": "GigabitEthernet0/0/0"},
            "media": "straight-through",
        }
    ]
    blueprint_plan = build_blueprint_plan(plan)
    assert blueprint_plan.required_link_pairs == ["R1 <-> SW1"]
    assert blueprint_plan.required_donor_capacity["Switch"] == 1


def test_build_inventory_capability_report_infers_basic_features() -> None:
    payload = {
        "services": {"Server1": ["dns_server", "http_server"]},
        "wireless": {"AP1": {"mode": "ap", "ssid": "FIN"}},
        "vlans": {"SW1": [{"id": "10", "name": "FIN"}]},
        "dhcp_pools": {"R1": ["FIN"]},
        "acl_names": {"R1": ["ADMIN_ONLY"]},
        "topology_summary": {"device_counts": {"Router": 1, "Switch": 1, "LightWeightAccessPoint": 1}},
    }
    report = build_inventory_capability_report(payload)
    assert "routers" in report["device_families"]
    assert "dns" in report["capabilities"]
    assert "wireless_ap" in report["capabilities"]
    assert "end_device_mutation" not in report["capabilities"]


def test_build_inventory_capability_report_infers_end_device_mutation() -> None:
    payload = {
        "services": {},
        "wireless": {},
        "vlans": {},
        "dhcp_pools": {},
        "acl_names": {},
        "topology_summary": {"device_counts": {"PC": 2, "Printer": 1, "Switch": 1}},
    }
    report = build_inventory_capability_report(payload)
    assert "end devices" in report["device_families"]
    assert "end_device_mutation" in report["capabilities"]


def test_build_inventory_capability_report_infers_wireless_client_association_for_end_devices() -> None:
    payload = {
        "services": {},
        "wireless": {"AP1": {"mode": "ap", "ssid": "FIN"}},
        "vlans": {},
        "dhcp_pools": {},
        "acl_names": {},
        "topology_summary": {"device_counts": {"Tablet": 2, "LightWeightAccessPoint": 1}},
    }
    report = build_inventory_capability_report(payload)
    assert "wireless_client_association" in report["capabilities"]


def test_build_inventory_capability_report_infers_wireless_mutation() -> None:
    payload = {
        "topology_summary": {"device_counts": {"LightWeightAccessPoint": 1, "Tablet": 1}},
        "wireless": {"AP1": {"ssid": "FIN_WIFI"}},
    }
    report = build_inventory_capability_report(payload)
    assert "wireless_mutation" in report["capabilities"]
