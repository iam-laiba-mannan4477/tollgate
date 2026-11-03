"""Fail if a secret-looking value or a .env file is staged or present in tracked files.
Usage: python scripts/check_secrets.py   (checks staged files; --all checks tracked files)"""
import re, subprocess, sys

PATTERNS = [
    re.compile(r"BRAINTREE_(PRIVATE|PUBLIC)_KEY\s*=\s*[A-Za-z0-9]{16,}"),
    re.compile(r"BRAINTREE_MERCHANT_ID\s*=\s*[A-Za-z0-9]{12,}"),
    re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
    re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{24,}"),
]
PLACEHOLDER = re.compile(r"(?i)your_|example|changeme|xxxx|<.*>")

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
