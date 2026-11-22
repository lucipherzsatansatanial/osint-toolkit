"""A small, safe pipe query language for the query builder (no eval, no regex from users).

    events                                  -- raw telemetry (or: alerts)
    | where kind == "logon" and user contains "adm"
    | where bytes > 1000000 or port in (22, 3389)
    | sort by ts desc
    | count by host                          -- aggregate (ends the row stream)
    | fields ts, host, user                  -- keep only these columns
    | limit 100

Operators: == != contains !contains startswith endswith > >= < <= in !in, exists, !exists.
`and` binds tighter than `or`; no parentheses. Strings in double or single quotes; numbers are numbers.
"""
import re

SOURCES = ("events", "alerts")
MAX_LIMIT = 5000
TOKEN = re.compile(r"""\s*(?:("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(\(|\)|,)|([A-Za-z_][\w.]*|!?[=<>]=?|!?contains|!?in|!?exists|[<>]|-?\d+(?:\.\d+)?|\S+))""")
OPS = {"==", "!=", "contains", "!contains", "startswith", "endswith", ">", ">=", "<", "<=", "in", "!in", "exists", "!exists"}


class QueryError(ValueError):
    pass


def _tokens(s: str) -> list[str]:
    out, pos = [], 0
    while pos < len(s):
        m = TOKEN.match(s, pos)
        if not m or m.end() == pos:
            break
        out.append(m.group(1) or m.group(2) or m.group(3))
        pos = m.end()
    return [t for t in out if t]


def _value(tok: str):
    if tok[:1] in "\"'":
        return tok[1:-1].replace('\\"', '"').replace("\\'", "'")
    try:
        return float(tok) if "." in tok else int(tok)
    except ValueError:
        return tok  # bare word = string


def _parse_where(toks: list[str]) -> list[list[tuple]]:
    """-> OR-list of AND-lists of (field, op, value)."""
    groups, cur, i = [], [], 0
    while i < len(toks):
        field = toks[i]
        if not re.fullmatch(r"[A-Za-z_][\w.]*", field):
            raise QueryError(f"คาดว่าจะเป็นชื่อ field แต่เจอ '{field}'")
        if i + 1 >= len(toks) or toks[i + 1] not in OPS:
            raise QueryError(f"ต้องมีตัวดำเนินการหลัง '{field}' (เช่น ==, contains, >)")
        op = toks[i + 1]
        i += 2
        if op in ("exists", "!exists"):
            val = None
        elif op in ("in", "!in"):
            if i >= len(toks) or toks[i] != "(":
                raise QueryError("in ต้องตามด้วย (ค่า1, ค่า2)")
            vals, i = [], i + 1
            while i < len(toks) and toks[i] != ")":
                if toks[i] != ",":
                    vals.append(_value(toks[i]))
                i += 1
            if i >= len(toks):
                raise QueryError("ขาด ')'")
            i += 1
            val = vals
        else:
            if i >= len(toks):
                raise QueryError(f"ขาดค่าหลัง '{op}'")
            val = _value(toks[i])
            i += 1
        cur.append((field, op, val))
        if i < len(toks):
            if toks[i].lower() == "and":
                i += 1
            elif toks[i].lower() == "or":
                groups.append(cur)
                cur = []
                i += 1
            else:
                raise QueryError(f"คาดว่าจะเป็น and / or แต่เจอ '{toks[i]}'")
    if not cur:
        raise QueryError("where ว่าง")
    groups.append(cur)
    return groups


def parse(text: str) -> dict:
    stages = [s.strip() for s in text.strip().split("|")]
    if not stages or stages[0].lower() not in SOURCES:
        raise QueryError(f"query ต้องเริ่มด้วย {' หรือ '.join(SOURCES)}")
    plan = {"source": stages[0].lower(), "steps": []}
    for st in stages[1:]:
        if not st:
            raise QueryError("มี | ที่ไม่มีคำสั่งตามหลัง")
        toks = _tokens(st)
        cmd = toks[0].lower()
        if cmd == "where":
            plan["steps"].append(("where", _parse_where(toks[1:])))
        elif cmd == "limit":
            if len(toks) != 2 or not toks[1].isdigit():
                raise QueryError("limit ต้องตามด้วยตัวเลข")
            plan["steps"].append(("limit", min(int(toks[1]), MAX_LIMIT)))
        elif cmd == "sort":
            rest = toks[1:]
            if rest and rest[0].lower() == "by":
                rest = rest[1:]
            if not rest:
                raise QueryError("sort by ต้องมีชื่อ field")
            desc = len(rest) > 1 and rest[1].lower() == "desc"
            plan["steps"].append(("sort", rest[0], desc))
        elif cmd == "count":
            rest = toks[1:]
            if rest and rest[0].lower() == "by":
                rest = rest[1:]
            plan["steps"].append(("count", [t for t in rest if t != ","]))
        elif cmd == "fields":
            plan["steps"].append(("fields", [t for t in toks[1:] if t != ","]))
        else:
            raise QueryError(f"ไม่รู้จักคำสั่ง '{toks[0]}' (ใช้ได้: where, sort, limit, count, fields)")
    return plan


def _get(r: dict, f: str):
    v = r
    for part in f.split("."):
        v = v.get(part) if isinstance(v, dict) else None
    return v


def _num(v):
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _test(r: dict, f: str, op: str, val) -> bool:
    got = _get(r, f)
    if op == "exists":
        return got not in (None, "")
    if op == "!exists":
        return got in (None, "")
    if op in ("in", "!in"):
        hit = any(str(got).lower() == str(v).lower() for v in val)
        return hit if op == "in" else not hit
    if op in (">", ">=", "<", "<="):
        a, b = _num(got), _num(val)
        if a is None or b is None:
            return False
        return {">": a > b, ">=": a >= b, "<": a < b, "<=": a <= b}[op]
    s, v = ("" if got is None else str(got)).lower(), str(val).lower()
    return {"==": s == v, "!=": s != v, "contains": v in s, "!contains": v not in s,
            "startswith": s.startswith(v), "endswith": s.endswith(v)}[op]


def run(plan: dict, rows: list[dict], default_limit: int = 200) -> dict:
    out = rows
    columns = None
    aggregated = False
    limited = False
    for step in plan["steps"]:
        kind = step[0]
        if kind == "where":
            groups = step[1]
            out = [r for r in out if any(all(_test(r, f, o, v) for f, o, v in g) for g in groups)]
        elif kind == "sort":
            f, desc = step[1], step[2]
            def key(r, f=f):
                v = _get(r, f)
                n = _num(v)
                return (0, n, "") if n is not None else (1, 0, str(v or ""))
            out = sorted(out, key=key, reverse=desc)
            if desc:  # keep missing values last
                out = [r for r in out if _get(r, f) is not None] + [r for r in out if _get(r, f) is None]
        elif kind == "limit":
            out = out[: step[1]]
            limited = True
        elif kind == "count":
            keys = step[1]
            counts: dict[tuple, int] = {}
            for r in out:
                k = tuple(str(_get(r, f)) for f in keys)
                counts[k] = counts.get(k, 0) + 1
            out = [{**dict(zip(keys, k)), "count": n} for k, n in sorted(counts.items(), key=lambda kv: -kv[1])]
            columns = keys + ["count"]
            aggregated = True
        elif kind == "fields":
            columns = step[1]
            out = [{f: _get(r, f) for f in columns} for r in out]
    total = len(out)
    if not limited:
        out = out[:default_limit]
    return {"rows": out, "total": total, "columns": columns, "aggregated": aggregated}
