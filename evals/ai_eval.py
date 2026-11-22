"""Offline evaluation of the AI SOC Copilot against SYNTHETIC golden incidents.

Run (uses the real Claude API — costs money, roughly a few cents per case):
    ANTHROPIC_API_KEY=... python -m evals.ai_eval [--out evals/report.json]

Checks per case (deterministic, no LLM judge):
  schema       – summary has every required field (and came from Claude, not the rule fallback)
  assessment   – assessment is one of the acceptable labels for the case
  grounding    – no host / IP / CVE / technique / rule ID that is absent from the incident (ai.ground_check)
  privacy      – the request sent to the API contained none of the case's real user names, internal IPs or e-mails
  mentions     – the summary mentions the key entities the case lists
  urgency      – critical cases get at least one "now" action
  thai         – the summary is written in Thai
"""
import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

from app import ai

GOLDEN = Path(__file__).with_name("golden.json")
THAI = re.compile(r"[฀-๿]")


class Spy:
    """Wraps the Claude client to capture exactly what is sent (privacy check)."""

    def __init__(self, inner):
        self.inner, self.sent = inner, []
        self.beta = self
        self.messages = self

    async def create(self, **kw):
        self.sent.append(json.dumps(kw.get("messages"), ensure_ascii=False))
        return await self.inner.beta.messages.create(**kw)


def score_case(case: dict, out: dict, sent: str) -> dict:
    inc, exp = case["incident"], case["expect"]
    text = json.dumps({k: out.get(k) for k in ("headline", "summary", "timeline", "recommended_actions")}, ensure_ascii=False)
    secrets = {u for u in inc.get("users", []) if u not in ("unknown",) and not u.startswith("src:")}
    secrets |= set(re.findall(r"\b10\.\d+\.\d+\.\d+\b", json.dumps(inc)))
    checks = {
        "schema": out.get("source") == "claude" and all(k in out for k in ai.SUMMARY_SCHEMA["required"]),
        "assessment": out.get("assessment") in exp["assessment"],
        "grounding": not (out.get("checks") or ai.ground_check(text, json.dumps(inc)))["unverified"],
        "privacy": not any(s in sent for s in secrets),
        "mentions": all(m.lower() in text.lower() for m in exp.get("must_mention", [])),
        "urgency": (not exp.get("needs_now_action")) or any(a.get("priority") == "now" for a in out.get("recommended_actions", [])),
        "thai": bool(THAI.search(out.get("summary", ""))),
    }
    return {"case": case["name"], "passed": sum(checks.values()), "total": len(checks), "checks": checks,
            "model": out.get("model"), "note": out.get("note"), "unverified": (out.get("checks") or {}).get("unverified")}


async def run(cases: list[dict]) -> dict:
    results = []
    real_client = ai.client
    for case in cases:
        spy = Spy(real_client())
        ai.client = lambda spy=spy: spy  # route this case's calls through the spy
        try:
            out = await ai.summarize(case["incident"])
        finally:
            ai.client = real_client
        results.append(score_case(case, out, "\n".join(spy.sent)))
    passed = sum(r["passed"] for r in results)
    total = sum(r["total"] for r in results)
    return {"model": ai.MODEL, "effort": ai.EFFORT, "cases": results, "score": round(passed / total, 3) if total else 0}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="evals/report.json")
    a = ap.parse_args()
    if not ai.enabled():
        print("ANTHROPIC_API_KEY is not set — this evaluation calls the real Claude API.", file=sys.stderr)
        return 2
    report = asyncio.run(run(json.loads(GOLDEN.read_text(encoding="utf-8"))["cases"]))
    Path(a.out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    for r in report["cases"]:
        failed = [k for k, v in r["checks"].items() if not v]
        print(f"{r['case']:<28} {r['passed']}/{r['total']}  {'failed: ' + ', '.join(failed) if failed else 'ok'}")
    print(f"score {report['score']:.0%}  ({report['model']}, effort {report['effort']})  -> {a.out}")
    return 0 if report["score"] >= 0.85 else 1


if __name__ == "__main__":
    raise SystemExit(main())
