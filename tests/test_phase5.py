import json
import sqlite3
from types import SimpleNamespace

from app import ai
from evals import ai_eval


def test_ground_check_flags_invented_entities():
    src = json.dumps({"hosts": ["SRV-FILE-02"], "alerts": [{"rule": "OAI-002", "technique": "T1071.001", "record": "1.2.3.4"}]})
    ok = ai.ground_check({"summary": "SRV-FILE-02 called DeepSeek (OAI-002, T1071.001) at 1.2.3.4"}, src)
    assert ok["grounded"] and not ok["leaked_pseudonyms"]
    bad = ai.ground_check({"summary": "SRV-DC-09 exploited CVE-2024-9999 from 5.6.7.8; see OAI-099 and USER_3"}, src)
    vals = {u["value"] for u in bad["unverified"]}
    assert {"SRV-DC-09", "CVE-2024-9999", "5.6.7.8", "OAI-099"} <= vals and bad["leaked_pseudonyms"] == ["USER_3"]
    assert not bad["grounded"]


def test_cost_estimate():
    assert ai.cost_usd("claude-opus-5-5", {"input_tokens": 1_000_000, "output_tokens": 100_000}) == 6.0
    assert ai.cost_usd("unknown-model", {"input_tokens": 1}) is None


async def test_eval_harness_scores_and_privacy(monkeypatch):
    cases = json.loads(ai_eval.GOLDEN.read_text(encoding="utf-8"))["cases"]
    case = cases[0]

    class M:
        async def create(self, **kw):
            sent = json.dumps(kw["messages"], ensure_ascii=False)
            user_tok = "USER_1" if "USER_1" in sent else "dev.user"
            reply = {"headline": "AI agent บน DEV-WS-031 สแกนเครือข่าย", "summary": f"{user_tok} ใช้ agent บน DEV-WS-031 (OAI-001, OAI-005)",
                     "assessment": "likely_malicious", "confidence": "high", "attack_stages": ["Execution"],
                     "timeline": [{"time": "t", "event": "OAI-001 nmap", "significance": "high"}],
                     "recommended_actions": [{"priority": "now", "action": "isolate DEV-WS-031", "owner": "IR"}], "open_questions": []}
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps(reply, ensure_ascii=False))],
                                   stop_reason="end_turn", model=kw["model"], usage=SimpleNamespace(input_tokens=1, output_tokens=1))
    monkeypatch.setattr(ai, "client", lambda: SimpleNamespace(beta=SimpleNamespace(messages=M())))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    report = await ai_eval.run([case])
    r = report["cases"][0]
    assert r["checks"] == {k: True for k in r["checks"]} and report["score"] == 1.0
    # a hallucinated host and an English summary are caught
    bad = ai_eval.score_case(case, {"source": "claude", **{k: "" for k in ai.SUMMARY_SCHEMA["required"]},
                                    "assessment": "likely_benign", "summary": "SRV-NOPE-1 is fine", "recommended_actions": []},
                             sent="dev.user leaked")
    assert not bad["checks"]["grounding"] and not bad["checks"]["privacy"] and not bad["checks"]["thai"]
