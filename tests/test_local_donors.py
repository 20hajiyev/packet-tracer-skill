"""The base-donor pool was one file, and that was reported as a donor limit.

`_compat_donor_candidate()` resolves a single lab, bundled Cisco samples fail
the exact-build policy, and curated roots are empty unless `--donor-root` was
passed. So whatever that one lab lacked, the skill declared impossible --
"1 wireless router 2 laptop qur" came back as a donor limitation on a machine
holding labs full of wireless routers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import local_donors  # noqa: E402
from pkt_codec import encode_pkt_modern  # noqa: E402


def _lab(path: Path, version: str = "9.0.0.0810", types: tuple[str, ...] = ("Router",)) -> Path:
    devices = "".join(
        f"<DEVICE><ENGINE><NAME>D{index}</NAME><TYPE>{kind}</TYPE>"
        f"<SAVE_REF_ID>r{index}</SAVE_REF_ID></ENGINE></DEVICE>"
        for index, kind in enumerate(types)
    )
    xml = (
        f"<PACKETTRACER5><VERSION>{version}</VERSION>"
        f"<DEVICES>{devices}</DEVICES><LINKS/></PACKETTRACER5>"
    ).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode_pkt_modern(xml))
    return path


def test_labs_on_the_running_build_are_found(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(local_donors, "get_packet_tracer_target_version", lambda: "9.0.0.0810")
    monkeypatch.setattr(local_donors, "get_donor_policy", lambda: "exact")
    _lab(tmp_path / "mine.pkt")

    found = local_donors.discover_local_donors(roots=[tmp_path], index_path=tmp_path / "idx.json")

    assert [donor.path.name for donor in found] == ["mine.pkt"]


def test_labs_on_another_build_are_skipped(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(local_donors, "get_packet_tracer_target_version", lambda: "9.0.0.0810")
    monkeypatch.setattr(local_donors, "get_donor_policy", lambda: "exact")
    _lab(tmp_path / "old.pkt", version="9.0.0.0000")

    assert local_donors.discover_local_donors(roots=[tmp_path], index_path=tmp_path / "i.json") == []


def test_generated_output_is_never_used_as_a_donor(tmp_path: Path, monkeypatch) -> None:
    """A lab derived from a lab carries every simplification the first pass made.

    Without this the skill selected its own `output/` files as a base.
    """
    monkeypatch.setattr(local_donors, "get_packet_tracer_target_version", lambda: "9.0.0.0810")
    monkeypatch.setattr(local_donors, "get_donor_policy", lambda: "exact")
    _lab(tmp_path / "output" / "generated.pkt")
    _lab(tmp_path / "real.pkt")

    found = local_donors.discover_local_donors(roots=[tmp_path], index_path=tmp_path / "i.json")

    assert [donor.path.name for donor in found] == ["real.pkt"]


def test_the_index_avoids_re_reading_unchanged_labs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(local_donors, "get_packet_tracer_target_version", lambda: "9.0.0.0810")
    monkeypatch.setattr(local_donors, "get_donor_policy", lambda: "exact")
    _lab(tmp_path / "mine.pkt")
    index = tmp_path / "idx.json"

    local_donors.discover_local_donors(roots=[tmp_path], index_path=index)

    def _must_not_be_called(_path: Path) -> str:
        raise AssertionError("an unchanged lab must be answered from the index")

    monkeypatch.setattr(local_donors, "_version_of", _must_not_be_called)
    found = local_donors.discover_local_donors(roots=[tmp_path], index_path=index)

    assert len(found) == 1
    assert json.loads(index.read_text(encoding="utf-8"))["entries"]


def test_required_types_filter_on_what_a_lab_contains(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(local_donors, "get_packet_tracer_target_version", lambda: "9.0.0.0810")
    monkeypatch.setattr(local_donors, "get_donor_policy", lambda: "exact")
    _lab(tmp_path / "wired.pkt", types=("Router", "Switch", "Pc"))
    _lab(tmp_path / "wifi.pkt", types=("WirelessRouterNewGeneration", "WirelessEndDevice"))

    found = local_donors.discover_local_donors(
        roots=[tmp_path],
        index_path=tmp_path / "i.json",
        required_types={"WirelessRouter": 1, "Laptop": 1},
    )

    assert [donor.path.name for donor in found] == ["wifi.pkt"]


def test_equivalent_device_models_satisfy_a_request() -> None:
    """A laptop is `WirelessEndDevice` in one lab and `Laptop` in another."""
    assert local_donors.covers_requested_types(
        {"WirelessRouterNewGeneration": 5, "WirelessEndDevice": 5}, {"WirelessRouter": 1, "Laptop": 2}
    )
    assert not local_donors.covers_requested_types({"Pc": 10}, {"WirelessRouter": 1})


def test_indexing_can_be_turned_off(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PKT_LOCAL_DONORS", "off")

    assert local_donors.discover_local_donors(roots=[tmp_path]) == []


def test_planner_uses_the_same_equivalences_as_selection() -> None:
    """Selection understood the equivalences and the planner did not, which is
    why widening the pool still reported "no spare WirelessRouter"."""
    from generate_pkt import _spare_pool_for_type

    pools = {"WirelessRouterNewGeneration": [{"device": {"name": "WRT0"}}]}

    assert _spare_pool_for_type(pools, "WirelessRouter") == pools["WirelessRouterNewGeneration"]
    assert _spare_pool_for_type(pools, "Server") == []
