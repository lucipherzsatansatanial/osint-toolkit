"""Username footprint: checks whether a handle exists on public platforms.

Results are *possible* matches only — the same handle on two sites is not proof
of the same person. Analysts must verify manually before drawing conclusions.
"""
import asyncio

from app.modules.common import http_client

# check: "status" -> 200 = exists, 404 = not found
#        "json_null" -> body "null" = not found
#        "absent:<text>" -> text in body = not found
SITES = [
    {"name": "GitHub", "url": "https://github.com/{u}", "api": "https://api.github.com/users/{u}", "check": "status"},
    {"name": "GitLab", "url": "https://gitlab.com/{u}", "api": "https://gitlab.com/api/v4/users?username={u}", "check": "absent:[]"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{u}", "api": "https://www.reddit.com/user/{u}/about.json", "check": "status"},
    {"name": "Hacker News", "url": "https://news.ycombinator.com/user?id={u}", "api": "https://hacker-news.firebaseio.com/v0/user/{u}.json", "check": "json_null"},
    {"name": "Keybase", "url": "https://keybase.io/{u}", "api": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", "check": "absent:\"them\":[null]"},
    {"name": "Dev.to", "url": "https://dev.to/{u}", "api": "https://dev.to/api/users/by_username?url={u}", "check": "status"},
    {"name": "Docker Hub", "url": "https://hub.docker.com/u/{u}", "api": "https://hub.docker.com/v2/users/{u}/", "check": "status"},
    {"name": "npm", "url": "https://www.npmjs.com/~{u}", "api": "https://registry.npmjs.org/-/user/org.couchdb.user:{u}", "check": "status"},
    {"name": "PyPI", "url": "https://pypi.org/user/{u}/", "api": "https://pypi.org/user/{u}/", "check": "status"},
    {"name": "Medium", "url": "https://medium.com/@{u}", "api": "https://medium.com/@{u}", "check": "status"},
    {"name": "Telegram", "url": "https://t.me/{u}", "api": "https://t.me/{u}", "check": "absent:tgme_page_extra\">If you have"},
    {"name": "Linktree", "url": "https://linktr.ee/{u}", "api": "https://linktr.ee/{u}", "check": "status"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{u}", "api": "https://soundcloud.com/{u}", "check": "status"},
    {"name": "Chess.com", "url": "https://www.chess.com/member/{u}", "api": "https://api.chess.com/pub/player/{u}", "check": "status"},
]


def interpret(check: str, status: int, body: str) -> str:
    if status in (403, 429) or status >= 500:
        return "unknown"
    if check == "status":
        return "found" if status == 200 else "not_found" if status in (404, 410) else "unknown"
    if check == "json_null":
        return "not_found" if body.strip() == "null" else "found" if status == 200 else "unknown"
    if check.startswith("absent:"):
        marker = check.split(":", 1)[1]
        if status == 404:
            return "not_found"
        return "not_found" if marker in body else "found" if status == 200 else "unknown"
    return "unknown"


async def _probe(client, site: dict, username: str, sem: asyncio.Semaphore) -> dict:
    async with sem:
        try:
            r = await client.get(site["api"].format(u=username))
            state = interpret(site["check"], r.status_code, r.text[:200_000])
        except Exception as e:  # noqa: BLE001
            state, r = f"error: {type(e).__name__}", None
    return {"site": site["name"], "url": site["url"].format(u=username), "status": state,
            "http": r.status_code if r is not None else None}


async def scan(username: str) -> dict:
    sem = asyncio.Semaphore(8)
    async with http_client(follow_redirects=True) as client:
        rows = await asyncio.gather(*(_probe(client, s, username, sem) for s in SITES))
    return {"footprint": {"ok": True, "data": {
        "username": username,
        "found": sum(r["status"] == "found" for r in rows),
        "checked": len(rows),
        "results": rows,
        "disclaimer": "Possible matches only. Same handle ≠ same person. Verify manually.",
    }}}
