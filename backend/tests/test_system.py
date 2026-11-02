import pytest
from fastapi.testclient import TestClient

from backend.app.engine import Engine
from backend.app.main import app
from backend.app.simulator import ATTACKS

E = Engine(seed=0, block_ttl=3)
client = TestClient(app)


def fresh(**kw):
    e = Engine(seed=0, **kw)
    e.detector = E.detector  # reuse trained model
    return e


def test_detector_quality_on_heldout_synthetic():
    r = E.detector.evaluate()
    assert r["accuracy"] > .9 and r["false_positive_rate"] < .1 and r["flash_crowd_false_positive_rate"] < .1


@pytest.mark.parametrize("attack", ATTACKS)
def test_attacks_are_detected(attack):
    e = fresh()
    rows = [e.step(attack) for _ in range(10)]
    assert sum(r["label"] == attack for r in rows) >= 8


def test_flash_crowd_is_never_blocked():
    e = fresh()
    for _ in range(25): e.step("flash_crowd")
    assert not any(a["action"] == "block" for a in e.mit.table(e.t))


def test_udp_flood_escalates_to_block_and_drops_traffic():
    e = fresh()
    rows = [e.step("udp_flood") for _ in range(4)]
    assert any(a["action"] == "block" for a in e.mit.table(e.t)) and rows[-1]["dropped"] > 0


def test_allow_listed_source_is_never_blocked():
    e = fresh()
    e.step("udp_flood")
    ip = e.mit.table(e.t)[0]["ip"]
    e.mit.allow(e.t, ip, True)
    for _ in range(5): e.step("udp_flood")
    assert all(a["ip"] != ip for a in e.mit.table(e.t))


def test_blocks_expire_when_traffic_is_normal():
    e = fresh(block_ttl=3, limit_ttl=2)
    for _ in range(3): e.step("udp_flood")
    for _ in range(6): e.step("normal")
    assert e.mit.table(e.t) == []


def test_no_public_telemetry():
    assert client.get("/api/health").status_code == 200
    for u in ("/api/state", "/api/evaluate", "/api/meta"):
        assert client.get(u).status_code in (404, 200) and "history" not in client.get(u).text
