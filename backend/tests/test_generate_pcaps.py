"""Tests for the Phase 5 scenario generator (scripts/generate_pcaps.py).

The generator is a standalone script; it is loaded here by file path so the
`scripts/` directory need not be a package. Every capture is written to
``tmp_path`` — nothing is committed. Generation is unprivileged.
"""

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from scapy.utils import PcapReader

from app.ingest.synthetic import normal_traffic, port_scan, syn_burst

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_script(name: str) -> ModuleType:
    """Import a ``scripts/<name>.py`` module by file path."""
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_scripts_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen() -> ModuleType:
    return _load_script("generate_pcaps")


def test_writes_all_three_scenarios(gen: ModuleType, tmp_path: Path) -> None:
    written = gen.write_scenarios(tmp_path)
    assert set(written) == {"normal_traffic", "port_scan", "syn_burst"}
    for path in written.values():
        assert path.exists()
        assert path.stat().st_size > 0


def test_generation_is_deterministic(gen: ModuleType, tmp_path: Path) -> None:
    first = gen.write_scenarios(tmp_path / "a")
    second = gen.write_scenarios(tmp_path / "b")
    for name in first:
        assert first[name].read_bytes() == second[name].read_bytes()


def test_roundtrip_preserves_timestamps_and_length(gen: ModuleType, tmp_path: Path) -> None:
    events = port_scan()
    written = gen.write_scenarios(tmp_path)
    with PcapReader(str(written["port_scan"])) as reader:
        frames = list(reader)
    assert len(frames) == len(events)
    for event, frame in zip(events, frames, strict=True):
        assert float(frame.time) == pytest.approx(event.ts, abs=1e-6)
        assert len(frame) > 0


def test_event_to_frame_covers_every_protocol(gen: ModuleType) -> None:
    from scapy.layers.inet import ICMP, IP, TCP, UDP

    # One representative event per branch, drawn from the canonical scenarios.
    syn = port_scan(num_ports=1)[0]
    frame = gen.event_to_frame(syn)
    assert frame.haslayer(TCP)
    assert frame.getlayer(IP).dst == syn.dst_ip

    udp_event = next(e for e in normal_traffic() if e.protocol == "UDP")
    assert gen.event_to_frame(udp_event).haslayer(UDP)

    icmp_event = next(e for e in normal_traffic() if e.protocol == "ICMP")
    assert gen.event_to_frame(icmp_event).haslayer(ICMP)


def test_main_reports_written_files(
    gen: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = gen.main(["--out-dir", str(tmp_path / "out")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "port_scan" in out and "syn_burst" in out
    assert (tmp_path / "out" / "port_scan.pcap").exists()


def test_generated_syn_burst_has_expected_record_count(gen: ModuleType, tmp_path: Path) -> None:
    written = gen.write_scenarios(tmp_path)
    with PcapReader(str(written["syn_burst"])) as reader:
        frames = list(reader)
    assert len(frames) == len(syn_burst())
