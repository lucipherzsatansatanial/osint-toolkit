import importlib
import time

from fastapi.testclient import TestClient

from app import phase4, rule_templates


def test_every_template_is_valid_and_its_tests_pass():
    for t in rule_templates.public():
        rule = phase4.assemble({"local_rule": t["rule"], **{k: v for k, v in t["rule"].items() if k != "conditions"}})
        assert phase4.validate_rule(rule) == [], t["id"]
        res = phase4.run_tests(rule, t["test_cases"])
        assert res and all(r["passed"] for r in res), (t["id"], res)


def test_empty_or_non_numeric_values_are_rejected():
    base = {"kind": "process", "match": "all", "severity": "medium"}
    errs = phase4.validate_rule({**base, "conditions": [{"field": "cmdline", "op": "contains", "value": ""}]})
    assert any("ค่าว่าง" in e for e in errs)
    errs = phase4.validate_rule({**base, "kind": "net", "conditions": [{"field": "bytes_out", "op": "gte", "value": "lots"}]})
    assert any("ตัวเลข" in e for e in errs)


def test_demo_rules_run_on_simulated_data(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    import app.config, app.audit, app.soc_store, app.rbac, app.main
    for m in (app.config, app.audit, app.soc_store, app.rbac, app.main):
        importlib.reload(m)
    H = {"X-API-Key": "secret"}
    with TestClient(app.main.app) as c:
        eng = app.main.hub.engine_for("default")
        for i in range(200):
            eng.step(time.time() - 3000 + i * 15)
        rules = c.get("/api/soc/rules", headers=H).json()["rules"]
        demo = [r for r in rules if r.get("simulated")]
        assert len(demo) == 5 and all(r["status"] == "enabled" for r in demo)
        assert sum(r["hits"] for r in demo) > 0  # they really fire on the simulator's records
        assert any(e.get("rule", "").startswith("CUS-DEMO") for e in eng.events)
        assert app.soc_store.list_rules("default") == []
        assert len(c.get("/api/soc/rules/templates", headers=H).json()["templates"]) == len(rule_templates.TEMPLATES)
        # saving a real rule reloads the engine without dropping the demo rules
        t = rule_templates.public()[0]
        assert c.post("/api/soc/rules", headers=H, json={"rule": t["rule"]}).status_code == 200
        assert {"CUS-DEMO-1"} <= set(eng.custom.rules)
