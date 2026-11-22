"""Normalize real telemetry into the record shapes the SOC detectors read.

Accepted formats (query param `format`):
  native   : records already in the platform schema (see below); also the default for `auto`
  ecs      : Elastic Common Schema documents (Elastic Agent / Winlogbeat / Filebeat / Packetbeat), nested or dotted keys
  defender : Microsoft Defender XDR advanced-hunting rows (DeviceProcessEvents / DeviceNetworkEvents)
  access_log: Apache / Nginx "combined" log lines (one per line); pass `host` = the web server name
  auto     : per record, Defender if it has DeviceName, ECS if it has @timestamp / event.*, else native

Platform schema
  telemetry: kind = process | http | net
    process: host, user, pid, ppid, image, cmdline, parent_image, parent_cmdline
    http   : dst_host, src_ip, method, uri, status, ua
    net    : host, dest, dest_ip, port
  AI-agent audit (has `agent`): kind = prompt | tool_call | process | network | auth
    common: agent, session, summary, decision, on_behalf_of, host
    prompt: source, flags[], snippet · tool_call: tool, args, bytes, dest · process: pid, ppid, image, cmdline
    network: dest, ip, port, bytes_out · auth: action, scope
  every record: ts (epoch seconds or ISO-8601; default = receive time)

Everything here is untrusted input: strings are clipped, numbers coerced, unknown kinds rejected.
"""
import json
import re
import time
from datetime import datetime
from urllib.parse import urlsplit

MAX_BYTES = 5_000_000
MAX_RECORDS = 5000
MAX_STR = 2000
FORMATS = ("auto", "native", "ecs", "defender", "access_log")
TELEMETRY_KINDS = {"process", "http", "net"}
AGENT_KINDS = {"prompt", "tool_call", "process", "network", "auth"}
STR_FIELDS = ("host", "user", "image", "cmdline", "parent_image", "parent_cmdline", "dst_host", "src_ip", "method",
              "uri", "ua", "dest", "dest_ip", "agent", "session", "summary", "decision", "on_behalf_of", "source",
              "snippet", "tool", "args", "ip", "action", "scope", "account", "os")
INT_FIELDS = ("pid", "ppid", "status", "port", "bytes", "bytes_out")


class IngestError(ValueError):
    pass


def _ts(v, default: float) -> float:
    if v is None or v == "":
        return default
    if isinstance(v, (int, float)):
        return float(v) / 1000 if v > 1e12 else float(v)  # accept epoch millis
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return default


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def clean(rec: dict, now: float) -> dict | None:
    """Coerce one platform-schema record; None if it is unusable."""
    if not isinstance(rec, dict):
        return None
    out: dict = {}
    for k in STR_FIELDS:
        if rec.get(k) is not None:
            out[k] = str(rec[k])[:MAX_STR]
    for k in INT_FIELDS:
        if rec.get(k) is not None:
            out[k] = _int(rec[k])
    if isinstance(rec.get("flags"), list):
        out["flags"] = [str(f)[:64] for f in rec["flags"][:20]]
    kind = str(rec.get("kind") or "")
    out["ts"] = _ts(rec.get("ts"), now)
    out["simulated"] = False
    if out.get("agent"):
        if kind == "net":
            kind = "network"
        if kind not in AGENT_KINDS:
            return None
        out["kind"] = kind
        out.setdefault("session", f"ext-{out['agent']}"[:64])
        out.setdefault("decision", "allowed")
        if out["decision"] not in ("allowed", "denied", "blocked"):
            out["decision"] = "allowed"
        out.setdefault("summary", " ".join(str(out.get(k, "")) for k in ("tool", "args", "image", "dest", "action")
                                           if out.get(k))[:300] or kind)
        if kind == "network" and not out.get("ip"):
            out["ip"] = out.get("dest_ip")
        return out
    if kind == "network":
        kind = "net"
    if kind not in TELEMETRY_KINDS:
        return None
    out["kind"] = kind
    if kind == "process" and out.get("host") and (out.get("image") or out.get("cmdline")):
        out.setdefault("image", (out.get("cmdline") or "").split(" ")[0])
        out.setdefault("cmdline", out["image"])
        return out
    if kind == "http" and out.get("dst_host") and (out.get("uri") or out.get("ua")):
        out.setdefault("uri", "/")
        return out
    if kind == "net" and out.get("host") and (out.get("dest") or out.get("dest_ip")):
        if out.get("dest"):
            out["dest"] = _hostname(out["dest"])
        return out
    return None


def _hostname(v: str) -> str:
    v = v.strip()
    if "://" in v:
        return (urlsplit(v).hostname or "").lower()
    return v.split("/")[0].split(":")[0].lower()


# ---------- Elastic Common Schema ----------
def _g(d: dict, path: str):
    if path in d:  # dotted/flattened export
        return d[path]
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def from_ecs(d: dict) -> dict | None:
    cat = _g(d, "event.category") or []
    cat = [cat] if isinstance(cat, str) else list(cat)
    base = {"ts": _g(d, "@timestamp"), "host": _g(d, "host.name") or _g(d, "host.hostname"),
            "user": _g(d, "user.name")}
    if "process" in cat or _g(d, "process.command_line"):
        etype = _g(d, "event.type") or []
        etype = [etype] if isinstance(etype, str) else list(etype)
        if etype and "start" not in etype:
            return None  # only process starts
        return {**base, "kind": "process", "pid": _g(d, "process.pid"), "ppid": _g(d, "process.parent.pid"),
                "image": _g(d, "process.executable") or _g(d, "process.name"),
                "cmdline": _g(d, "process.command_line"),
                "parent_image": _g(d, "process.parent.executable") or _g(d, "process.parent.name"),
                "parent_cmdline": _g(d, "process.parent.command_line")}
    if "web" in cat or _g(d, "http.request.method"):
        path, query = _g(d, "url.path") or _g(d, "url.original") or "/", _g(d, "url.query")
        return {**base, "kind": "http", "dst_host": base["host"] or _g(d, "url.domain"),
                "src_ip": _g(d, "source.ip") or _g(d, "client.ip"), "method": _g(d, "http.request.method"),
                "uri": f"{path}?{query}" if query else path, "status": _g(d, "http.response.status_code"),
                "ua": _g(d, "user_agent.original")}
    dest = _g(d, "dns.question.name") or _g(d, "destination.domain") or _g(d, "url.domain")
    if "network" in cat or dest or _g(d, "destination.ip"):
        return {**base, "kind": "net", "dest": dest, "dest_ip": _g(d, "destination.ip"),
                "port": _g(d, "destination.port")}
    return None


# ---------- Microsoft Defender XDR advanced hunting ----------
def from_defender(d: dict) -> dict | None:
    base = {"ts": d.get("Timestamp") or d.get("TimeGenerated"), "host": d.get("DeviceName")}
    if d.get("ProcessCommandLine") is not None or d.get("ActionType") == "ProcessCreated":
        return {**base, "kind": "process", "user": d.get("AccountName") or d.get("InitiatingProcessAccountName"),
                "pid": d.get("ProcessId"), "ppid": d.get("InitiatingProcessId"),
                "image": d.get("FileName") or d.get("FolderPath"), "cmdline": d.get("ProcessCommandLine"),
                "parent_image": d.get("InitiatingProcessFileName"),
                "parent_cmdline": d.get("InitiatingProcessCommandLine")}
    if d.get("RemoteIP") or d.get("RemoteUrl"):
        return {**base, "kind": "net", "dest": d.get("RemoteUrl") or None, "dest_ip": d.get("RemoteIP"),
                "port": d.get("RemotePort"), "user": d.get("InitiatingProcessAccountName")}
    return None


# ---------- Apache / Nginx combined log ----------
COMBINED = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<uri>\S+)[^"]*" '
                      r'(?P<status>\d{3}) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?')


def from_access_log(line: str, host: str) -> dict | None:
    m = COMBINED.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        ts = None
    return {"kind": "http", "ts": ts, "dst_host": host, "src_ip": m["ip"], "method": m["method"], "uri": m["uri"],
            "status": int(m["status"]), "ua": m["ua"] or ""}


def _detect(d: dict) -> str:
    if "DeviceName" in d:
        return "defender"
    if "@timestamp" in d or "event" in d or "event.category" in d:
        return "ecs"
    return "native"


def parse(raw: bytes, fmt: str = "auto", host: str | None = None, now: float | None = None) -> tuple[list[dict], int]:
    """Returns (records, rejected). Raises IngestError on oversized or undecodable bodies."""
    if fmt not in FORMATS:
        raise IngestError(f"unknown format; use one of {', '.join(FORMATS)}")
    if len(raw) > MAX_BYTES:
        raise IngestError(f"body larger than {MAX_BYTES} bytes")
    now = time.time() if now is None else now
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise IngestError("body must be UTF-8") from e
    if fmt == "access_log":
        items = [ln for ln in text.splitlines() if ln.strip()]
        mapped = [from_access_log(ln, (host or "web")[:255]) for ln in items]
    else:
        try:
            doc = json.loads(text)
            items = doc.get("records", [doc]) if isinstance(doc, dict) else doc
        except json.JSONDecodeError:
            try:
                items = [json.loads(ln) for ln in text.splitlines() if ln.strip()]  # NDJSON
            except json.JSONDecodeError as e:
                raise IngestError(f"invalid JSON / NDJSON: {e.msg} at line {e.lineno}") from e
        if not isinstance(items, list):
            raise IngestError("expected a JSON array, {\"records\": [...]}, or NDJSON")
        mapped = []
        for d in items:
            if not isinstance(d, dict):
                mapped.append(None)
                continue
            f = _detect(d) if fmt == "auto" else fmt
            mapped.append(from_defender(d) if f == "defender" else from_ecs(d) if f == "ecs" else d)
    if len(items) > MAX_RECORDS:
        raise IngestError(f"more than {MAX_RECORDS} records in one request; split the batch")
    out = [r for r in (clean(m, now) if m else None for m in mapped) if r]
    return out, len(items) - len(out)
