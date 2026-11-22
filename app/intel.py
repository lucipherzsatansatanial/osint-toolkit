"""Intelligence database: one normalised view of every indicator the platform knows — public CTI feeds
(abuse.ch ThreatFox and Feodo Tracker, CISA KEV, ThreatDefence agentic indicators) plus the tenant's own IOCs —
with search, log matching (detections IOC-001 / IOC-002) and outgoing feeds (STIX 2.1, plain text, CSV).

TLP of public feeds is CLEAR (published openly). Tenant IOCs carry the TLP the analyst sets; feeds never export
indicators above the feed's max TLP.
"""
import csv
import hashlib
import io
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

IOC_RULES = {
    "IOC-001": ("Observed indicator from the tenant's own IOC collection", "high", "T1071.001", "Command and Control"),
    "IOC-002": ("Observed indicator from a public CTI feed", "high", "T1071.001", "Command and Control"),
}
TLP = ["clear", "green", "amber", "amber+strict", "red"]
TYPES = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "cve", "user_agent")
CONF = {"high": 85, "medium": 60, "low": 30}
SOURCES = {"threatfox": "abuse.ch ThreatFox", "feodo": "abuse.ch Feodo Tracker", "kev": "CISA KEV",
           "agentic": "ThreatDefence agentic-attack-detections", "tenant": "IOC ของ tenant"}
HEX = {32: "md5", 40: "sha1", 64: "sha256"}
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")


def classify(value: str) -> tuple[str | None, str]:
    """-> (type, normalised value) or (None, value) when it is not a supported indicator."""
    v = (value or "").strip().strip("[]").replace("[.]", ".").replace("hxxp", "http")
    if not v or len(v) > 2048:
        return None, v
    low = v.lower()
    if re.fullmatch(r"cve-\d{4}-\d{4,}", low):
        return "cve", v.upper()
    if re.fullmatch(r"[0-9a-f]+", low) and len(low) in HEX:
        return HEX[len(low)], low
    host = low.rsplit(":", 1)[0] if re.fullmatch(r"[\d.]+:\d+", low) else low
    try:
        ip = ipaddress.ip_address(host)
        return ("ipv4" if ip.version == 4 else "ipv6"), str(ip)
    except ValueError:
        pass
    if low.startswith(("http://", "https://")):
        return "url", v
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", low):
        return "email", low
    if DOMAIN_RE.match(low):
        return "domain", low
    return None, v


def _ind(value, typ, source, conf, tlp="clear", threat=None, first_seen=None, ref=None, tags=None, desc=None):
    return {"value": value, "type": typ, "source": source, "source_name": SOURCES.get(source, source), "confidence": conf,
            "tlp": tlp, "threat": threat, "first_seen": first_seen, "reference": ref, "tags": tags or [], "description": desc}


def from_feeds(threatfox: dict, feodo: dict, kev: dict, agentic: list[dict]) -> list[dict]:
    out = []
    seen_tf = set()
    for e in sorted(threatfox.values(), key=lambda e: str(e.get("first_seen") or ""), reverse=True):
        typ, v = classify(e.get("ioc") or "")
        if typ and (typ, v) not in seen_tf:  # one row per indicator (ThreatFox lists an IP once per port)
            seen_tf.add((typ, v))
            out.append(_ind(v, typ, "threatfox", int(e.get("confidence") or 50), threat=e.get("malware"),
                            first_seen=e.get("first_seen"), tags=[t for t in (e.get("tags") or []) if t][:5],
                            desc=e.get("threat")))
    for ip, e in feodo.items():
        out.append(_ind(ip, "ipv4", "feodo", 90 if e.get("status") == "online" else 70, threat=e.get("malware"),
                        first_seen=e.get("first_seen"), desc=f"botnet C2 ({e.get('status') or '?'})"))
    for cve, e in kev.items():
        out.append(_ind(cve, "cve", "kev", 100, threat=f"{e.get('vendor')} {e.get('product')}", first_seen=e.get("date_added"),
                        ref=f"https://nvd.nist.gov/vuln/detail/{cve}", tags=["ransomware"] if e.get("ransomware") else [],
                        desc=e.get("name")))
    for r in agentic:
        typ, v = classify(r.get("value") or "")
        if r.get("type") == "user_agent":
            typ, v = "user_agent", r["value"]
        if typ:
            out.append(_ind(v, typ, "agentic", CONF.get(r.get("confidence"), 50), threat=r.get("framework") or r.get("actor"),
                            first_seen=r.get("reported"), ref=r.get("source_url") or None, desc=r.get("context")))
    return out


def search(indicators: list[dict], query: str, types: list[str] | None = None, sources: list[str] | None = None,
           min_conf: int = 0, limit: int = 50, offset: int = 0) -> dict:
    """Multi-value search: separate values by newline or comma; each term matches exactly first, then as substring
    of value / threat / description."""
    terms = [t.strip().lower() for t in re.split(r"[\n,]", query or "") if t.strip()][:200]
    norm = [classify(t)[1].lower() for t in terms]
    rows = [i for i in indicators if (not types or i["type"] in types) and (not sources or i["source"] in sources)
            and i["confidence"] >= min_conf]
    if terms:
        exact = set(norm) | set(terms)
        hit = []
        for i in rows:
            v = i["value"].lower()
            if v in exact:
                hit.append((0, i))
            elif any(t in v or t in (i.get("threat") or "").lower() or t in (i.get("description") or "").lower() for t in terms):
                hit.append((1, i))
        hit.sort(key=lambda x: x[0])
        rows = [i for _, i in hit]
        found = {i["value"].lower() for i in rows}
        missing = [t for t, n in zip(terms, norm) if n not in found and t not in found]
    else:
        rows = sorted(rows, key=lambda i: str(i.get("first_seen") or ""), reverse=True)
        missing = []
    by_type, by_source = {}, {}
    for i in rows:
        by_type[i["type"]] = by_type.get(i["type"], 0) + 1
        by_source[i["source"]] = by_source.get(i["source"], 0) + 1
    return {"total": len(rows), "items": rows[offset: offset + limit], "by_type": by_type, "by_source": by_source,
            "not_found": missing}


# ---------- matching indicators in logs ----------
FIELDS = ("ip", "dest_ip", "src_ip", "client_ip", "dest", "dst_host", "uri", "image", "cmdline", "ua", "sha256", "md5",
          "sha1", "hash", "domain", "url")


def observables(rec: dict) -> set[str]:
    """Candidate indicator strings in a normalised record (exact-match keys, lower case)."""
    out = set()
    for f in FIELDS:
        v = rec.get(f)
        if not v:
            continue
        s = str(v).strip().lower()
        out.add(s)
        if f in ("dest", "uri", "url") and "://" in s:
            out.add(urlsplit(s).hostname or "")
        if f in ("dest", "dst_host") and ":" in s and s.count(":") == 1:
            out.add(s.split(":")[0])
        if f in ("dest_ip", "ip") and rec.get("port"):
            out.add(f"{s}:{rec['port']}")
    if rec.get("dst_host") and rec.get("uri"):
        out.add(f"http://{str(rec['dst_host']).lower()}{rec['uri']}")
        out.add(f"https://{str(rec['dst_host']).lower()}{rec['uri']}")
    out.discard("")
    return out


def build_index(indicators: list[dict]) -> dict[str, dict]:
    idx = {}
    for i in indicators:
        if i["type"] == "cve":
            continue
        key = i["value"].lower()
        if key not in idx or i["confidence"] > idx[key]["confidence"]:
            idx[key] = i
    return idx


def match(rec: dict, index: dict[str, dict]) -> dict | None:
    best = None
    for o in observables(rec):
        hit = index.get(o)
        if hit and (best is None or hit["confidence"] > best["confidence"]):
            best = hit
    return best


# ---------- outgoing feeds ----------
def tlp_ok(ind_tlp: str, max_tlp: str) -> bool:
    return TLP.index(ind_tlp if ind_tlp in TLP else "amber") <= TLP.index(max_tlp)


def select(indicators: list[dict], feed: dict) -> list[dict]:
    rows = [i for i in indicators if (not feed.get("types") or i["type"] in feed["types"])
            and (not feed.get("sources") or i["source"] in feed["sources"])
            and i["confidence"] >= int(feed.get("min_confidence") or 0) and tlp_ok(i["tlp"], feed.get("max_tlp", "green"))
            and not i.get("revoked")]
    rows.sort(key=lambda i: str(i.get("first_seen") or ""), reverse=feed.get("sort", "newest") == "newest")
    return rows[: int(feed.get("max_size") or 2000)]


STIX_PATTERN = {"ipv4": "ipv4-addr:value", "ipv6": "ipv6-addr:value", "domain": "domain-name:value", "url": "url:value",
                "email": "email-addr:value", "md5": "file:hashes.MD5", "sha1": "file:hashes.'SHA-1'",
                "sha256": "file:hashes.'SHA-256'", "user_agent": "network-traffic:extensions.'http-request-ext'.request_header.'User-Agent'"}
TLP_MARKING = {"clear": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
               "green": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
               "amber": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
               "amber+strict": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
               "red": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1"}


def _stix_ts(v) -> str:
    try:
        d = datetime.fromisoformat(str(v).replace(" UTC", "").replace("Z", "")[:19]).replace(tzinfo=timezone.utc)
    except ValueError:
        d = datetime.now(timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def to_stix(rows: list[dict], feed_name: str) -> dict:
    objs = []
    for i in rows:
        if i["type"] == "cve":
            objs.append({"type": "vulnerability", "spec_version": "2.1",
                         "id": "vulnerability--" + str(uuid.uuid5(uuid.NAMESPACE_URL, i["value"])),
                         "created": _stix_ts(i["first_seen"]), "modified": _stix_ts(i["first_seen"]), "name": i["value"],
                         "external_references": [{"source_name": "cve", "external_id": i["value"]}],
                         "object_marking_refs": [TLP_MARKING[i["tlp"]]]})
            continue
        path = STIX_PATTERN.get(i["type"])
        if not path:
            continue
        val = i["value"].replace("\\", "\\\\").replace("'", "\\'")
        ts = _stix_ts(i["first_seen"])
        objs.append({"type": "indicator", "spec_version": "2.1",
                     "id": "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{i['type']}:{i['value']}")),
                     "created": ts, "modified": ts, "valid_from": ts, "pattern_type": "stix",
                     "pattern": f"[{path} = '{val}']", "name": i["value"][:200], "confidence": i["confidence"],
                     "labels": [x for x in [i.get("threat"), *i.get("tags", [])] if x][:6],
                     "description": (i.get("description") or "")[:500] or None,
                     "external_references": [{"source_name": i["source_name"], **({"url": i["reference"]} if i.get("reference") else {})}],
                     "object_marking_refs": [TLP_MARKING[i["tlp"]]]})
    for o in objs:
        if o.get("description") is None:
            o.pop("description", None)
    bundle_id = "bundle--" + str(uuid.uuid5(uuid.NAMESPACE_URL, feed_name + hashlib.sha256(
        json.dumps([o["id"] for o in objs]).encode()).hexdigest()))
    return {"type": "bundle", "id": bundle_id, "objects": objs}


def to_text(rows: list[dict]) -> str:
    return "\n".join(i["value"] for i in rows) + ("\n" if rows else "")


def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["value", "type", "confidence", "tlp", "source", "threat", "first_seen"])
    for i in rows:
        w.writerow([_safe(i["value"]), i["type"], i["confidence"], i["tlp"], i["source_name"], _safe(i.get("threat") or ""),
                    i.get("first_seen") or ""])
    return buf.getvalue()


def _safe(s: str) -> str:
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
