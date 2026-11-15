#!/usr/bin/env python3
"""T-REPO-002: product crates may not depend on gate-testkit or void-bench
(plan.md §2.2). gate-testkit is a dev-dependency only.

Usage: dep_rule_check.py [--root DIR] [--self-test]
"""
import shutil
import sys
import tempfile
import tomllib
from pathlib import Path

FORBIDDEN = {"gate-testkit", "void-bench"}
NON_PRODUCT = {"gate-testkit", "void-bench"}


def product_crates(root: Path):
    for d in sorted((root / "crates").iterdir()):
        if not d.is_dir() or d.name in NON_PRODUCT:
            continue
        cargo = d / "Cargo.toml"
        if cargo.exists():
            yield d.name, tomllib.loads(cargo.read_text())


def check(root: Path) -> int:
    bad = []
    for name, manifest in product_crates(root):
        deps = manifest.get("dependencies", {})
        for f in FORBIDDEN:
            if f in deps:
                bad.append(f"{name} depends on {f} as a normal dependency")
    if bad:
        for b in bad:
            print(f"VIOLATION: {b} (T-REPO-002)", file=sys.stderr)
        return 1
    print("dep-rule-check: clean")
    return 0


def self_test(root: Path) -> int:
    with tempfile.TemporaryDirectory() as td:
        dst = Path(td) / "repo"
        shutil.copytree(root, dst, ignore=shutil.ignore_patterns("target", ".git"))
        c = dst / "crates" / "gate-ledger" / "Cargo.toml"
        text = c.read_text()
        if "[dependencies]" in text:
            text = text.replace("[dependencies]", "[dependencies]\ngate-testkit = { path = \"../gate-testkit\" }", 1)
        else:
            text += "\n[dependencies]\ngate-testkit = { path = \"../gate-testkit" + ' }"'
        c.write_text(text)
        if check(dst) == 0:
            print("SELF-TEST FAILED: seeded dependency was not detected", file=sys.stderr)
            return 1
        print("dep-rule-check self-test: detected seeded violation")
        return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    root = Path(args[args.index("--root") + 1]) if "--root" in args else Path(__file__).resolve().parents[2]
    sys.exit(self_test(root) if "--self-test" in args else check(root))
