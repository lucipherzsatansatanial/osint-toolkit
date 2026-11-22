from collections import Counter

from app import agent_detect, ingest, soc_store, telemetry
from app.config import settings

NOW = 1_800_000_000.0


def run(scale, ticks=300):
    eng = telemetry.Engine(seed=11, simulate=True, scale=scale)
    n = sum(len(eng.step(NOW + i)) for i in range(ticks))
    return eng, n


def test_scaled_inventory_is_five_times_and_unique():
    hosts = telemetry.scaled_hosts(5)
    assert len(hosts) == 70 and len({h[0] for h in hosts}) == 70 and len({h[2] for h in hosts}) == 70
    assert ("FIN-WS-114", "Windows 11", "finance.ops2") in hosts and ("SRV-WEB-41", "Ubuntu 22.04", "svc.web5") in hosts
    agents = agent_detect.demo_agents(5)
    assert len(agents) == 25 and len({a["id"] for a in agents}) == 25
    assert agent_detect.base_agent("support-copilot-3") == "support-copilot" and agent_detect.base_agent("x-2") == "x-2"
    assert len(telemetry.COUNTRIES) == 50


def test_scale_five_gives_about_five_times_the_data_and_capacity():
    e1, n1 = run(1)
    e5, n5 = run(5)
    assert 3.5 <= n5 / n1 <= 6.5, (n1, n5)                       # ~5x alerts per minute
    assert e5.events.maxlen == 5 * e1.events.maxlen == 1500
    assert e5.raw.maxlen == 25000 and e5.agents.records.maxlen == 10000
    assert len(e5.endpoints) == 70 and len(e5.agents.agents) == 25
    hosts5 = {e["host"] for e in e5.events}
    assert len(hosts5) > len({e["host"] for e in e1.events}) * 2  # activity spread over the bigger fleet
    # concurrent campaigns never exceed the scale and never share a host
    assert len(e5.campaigns) <= 5 and len({c["host"] for c in e5.campaigns}) == len(e5.campaigns)


def test_real_data_limits_follow_scale():
    k = settings.soc_scale
    assert ingest.MAX_RECORDS == 5000 * k and ingest.MAX_BYTES == 5_000_000 * k
    assert soc_store.INBOX_KEEP == 500 * k and telemetry.MAX_ASSETS == 50000 * k
    eng = telemetry.Engine(simulate=False, scale=k)
    assert eng.events.maxlen == 300 * k and eng.endpoints == {} and eng.agents.agents == {}  # no demo data for real tenants


def test_incremental_oai004_matches_brute_force():
    import random
    from app import offensive_ai as oa
    det = oa.Detector()
    rng = random.Random(3)
    t = NOW
    for i in range(4000):
        t += rng.random() * 2
        rec = {"kind": "http", "dst_host": "web", "src_ip": f"198.51.100.{rng.randint(1, 60)}", "method": "GET",
               "uri": rng.choice(["/", "/admin", "/x.php", "/login"]), "status": rng.choice([200, 200, 404, 403, 500])}
        det.evaluate(rec, t)
        q = det.inbound["web"]
        per, err = Counter(), Counter()
        for _, ip, st in q:
            per[ip] += 1
            err[ip] += 1 if st and st >= 400 else 0
        brute = {ip for ip, n in per.items() if n <= 5 and err[ip] / n >= 0.6}
        assert det.probers["web"] == brute, i
