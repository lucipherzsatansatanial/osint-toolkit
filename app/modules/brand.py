"""Brand protection: typosquatting / lookalike domain discovery and CT-log keyword monitoring."""
import asyncio

from app.modules.common import dns_query, http_client, run_checks

MULTI_SUFFIXES = {"co.th", "in.th", "ac.th", "go.th", "or.th", "net.th", "mi.th",
                  "co.uk", "org.uk", "com.au", "com.sg", "com.my", "co.id", "co.jp", "com.vn"}
ALT_TLDS = ["com", "net", "org", "co", "info", "biz", "xyz", "online", "shop", "site",
            "app", "io", "asia", "co.th", "in.th", "th"]
HOMOGLYPHS = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"],
              "s": ["5"], "m": ["rn"], "w": ["vv"], "g": ["q"], "b": ["6"]}
KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok",
    "o": "ipl", "p": "o", "a": "qsz", "s": "awdz", "d": "sefx", "f": "drgc", "g": "fthv",
    "h": "gyjb", "j": "hukn", "k": "jilm", "l": "ko", "z": "asx", "x": "zsdc", "c": "xdfv",
    "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
MAX_CANDIDATES = 400


def split_domain(domain: str) -> tuple[str, str]:
    parts = domain.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIXES:
        return parts[-3], ".".join(parts[-2:])
    return parts[-2], parts[-1]


def permutations(domain: str) -> dict[str, str]:
    """Return {candidate_domain: technique}. The original domain is excluded."""
    name, tld = split_domain(domain)
    out: dict[str, str] = {}

    def add(label: str, technique: str, suffix: str = tld):
        if 1 <= len(label) <= 63 and not label.startswith("-") and not label.endswith("-"):
            out.setdefault(f"{label}.{suffix}", technique)

    for i in range(len(name)):
        add(name[:i] + name[i + 1:], "omission")
        add(name[:i] + name[i] + name[i:], "repetition")
        if i < len(name) - 1:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2:], "transposition")
        for k in KEYBOARD.get(name[i], ""):
            add(name[:i] + k + name[i + 1:], "keyboard-typo")
        for g in HOMOGLYPHS.get(name[i], []):
            add(name[:i] + g + name[i + 1:], "homoglyph")
        if 0 < i < len(name):
            add(name[:i] + "-" + name[i:], "hyphenation")
    for word in ["login", "secure", "online", "th", "official", "support", "app"]:
        add(f"{name}-{word}", "keyword-append")
        add(f"{name}{word}", "keyword-append")
    for alt in ALT_TLDS:
        if alt != tld:
            add(name, "tld-swap", alt)
    out.pop(domain, None)
    return dict(list(out.items())[:MAX_CANDIDATES])


async def _check(candidate: str, technique: str, sem: asyncio.Semaphore) -> dict | None:
    async with sem:
        a = await dns_query(candidate, "A")
        if not a:
            return None
        mx = await dns_query(candidate, "MX")
    return {"domain": candidate, "technique": technique, "a": a, "mx": bool(mx),
            "risk": "high" if mx else "medium"}


async def lookalikes(domain: str) -> dict:
    cands = permutations(domain)
    sem = asyncio.Semaphore(25)
    found = await asyncio.gather(*(_check(c, t, sem) for c, t in cands.items()))
    hits = sorted([f for f in found if f], key=lambda x: (x["risk"] != "high", x["domain"]))
    return {"candidates_checked": len(cands), "registered": len(hits), "results": hits,
            "note": "Registered lookalikes with MX records can send phishing email — verify ownership before action"}


async def ct_keyword(keyword: str) -> dict:
    """Certificates issued for any domain containing the brand keyword."""
    async with http_client(follow_redirects=True) as c:
        r = await c.get("https://crt.sh/", params={"q": f"%{keyword}%", "output": "json",
                                                   "exclude": "expired"}, timeout=45)
    r.raise_for_status()
    rows = r.json()
    names = {}
    for row in rows:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.")
            if keyword in n and n not in names:
                names[n] = {"domain": n, "issuer": row.get("issuer_name"), "not_before": row.get("not_before")}
    res = sorted(names.values(), key=lambda x: x["not_before"] or "", reverse=True)
    return {"count": len(res), "results": res[:300]}


async def scan(domain: str, keyword: str) -> dict:
    return await run_checks({
        "lookalike_domains": lambda: lookalikes(domain),
        "ct_keyword": lambda: ct_keyword(keyword),
    })
