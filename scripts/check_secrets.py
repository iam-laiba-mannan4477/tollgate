"""Fail if a secret-looking value or a .env file is staged or present in tracked files.
Usage: python scripts/check_secrets.py   (checks staged files; --all checks tracked files)"""
import os, subprocess, sys

# The patterns live in one place, shared with Sentinel's scanner (same patterns as before).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tollgate.sentinel.secret_patterns import PATTERNS, PLACEHOLDER  # noqa: E402

def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True).stdout.splitlines()

def main():
    names = git("ls-files") if "--all" in sys.argv else git("diff", "--cached", "--name-only")
    bad = []
    for n in names:
        base = n.replace("\\", "/").split("/")[-1]
        if base == ".env" or (base.startswith(".env.") and base != ".env.example"):
            bad.append(f"{n}: environment file must not be committed")
            continue
        try:
            text = open(n, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if any(p.search(line) for p in PATTERNS) and not PLACEHOLDER.search(line):
                bad.append(f"{n}:{i}: possible secret (value hidden)")
    if bad:
        print("SECRET CHECK FAILED"); [print(" -", b) for b in bad]; sys.exit(1)
    print("secret check clean")

if __name__ == "__main__":
    main()
