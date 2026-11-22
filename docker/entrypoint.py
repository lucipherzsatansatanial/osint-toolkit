"""Container entrypoint: prepare the data directory, drop root, start uvicorn.

Persistent disks (e.g. a Render disk at /var/data) are often mounted root-owned, which an unprivileged app user
cannot write. When started as root this script creates the directories for OSINT_DB_PATH and SOC_BACKUP_DIR,
hands them to the app user, then switches to that user for good before starting the server. It never keeps root.
"""
import os
import pwd
import sys

APP_USER = os.getenv("APP_USER", "osint")


def main() -> None:
    dirs = {os.path.dirname(os.getenv("OSINT_DB_PATH", "/app/data/osint.db")) or "."}
    if os.getenv("SOC_BACKUP_DIR"):
        dirs.add(os.environ["SOC_BACKUP_DIR"])
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    if os.getuid() == 0:
        try:
            u = pwd.getpwnam(APP_USER)
        except KeyError:
            sys.exit(f"entrypoint: user {APP_USER!r} not found; refusing to run the server as root")
        for d in dirs:
            for root, subdirs, files in os.walk(d):
                for name in [root, *(os.path.join(root, f) for f in subdirs + files)]:
                    os.chown(name, u.pw_uid, u.pw_gid)
        os.setgroups([])
        os.setgid(u.pw_gid)
        os.setuid(u.pw_uid)
        os.environ["HOME"] = u.pw_dir or "/app"
        if os.getuid() == 0:
            sys.exit("entrypoint: failed to drop root")
    port = os.getenv("PORT", "8000")
    args = ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", port, "--proxy-headers", "--forwarded-allow-ips=*"]
    os.execvp(args[0], args)


if __name__ == "__main__":
    main()
