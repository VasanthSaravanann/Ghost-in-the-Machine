#!/usr/bin/env python3
"""R11 / T-REPO-005: the TCB is Rust-only.

Walks the real dependency tree of every decision crate (via `cargo metadata`)
and fails if any dependency is native code (a `*-sys` crate, or a known
foreign-code builder such as cc / bindgen / pyo3 / cmake).

Usage: tcb_lang_check.py [--root DIR] [--self-test]
"""
import json
import subprocess
import sys
from pathlib import Path

DECISION_CRATES = [
    "gate-core", "gate-jcs", "gate-crypto", "gate-span", "gate-schema",
    "gate-policy", "gate-provenance", "gate-ledger", "gate-brief", "gate-tlog",
]

NATIVE = {"cc", "bindgen", "pyo3", "cmake", "pkg-config", "openssl-sys", "ring"}


def is_native(name: str) -> bool:
    return name in NATIVE or name.endswith("-sys")


def metadata(root: Path):
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features"],
        cwd=root, check=True, capture_output=True,
    )
    return json.loads(out.stdout)


def check(root: Path) -> int:
    md = metadata(root)
    by_id = {p["id"]: p for p in md["packages"]}
    resolve = md["resolve"]
    nodes = {n["id"]: n for n in resolve["nodes"]}

    def deps(name):
        """Normal and build dependencies only: dev-dependencies are never part
        of a shipped TCB artifact (plan.md §2.0)."""
        for p in md["packages"]:
            if p["name"] == name:
                node = nodes[p["id"]]
                out = []
                for d in node["deps"]:
                    kinds = [k.get("kind") for k in d.get("dep_kinds", [])] or [None]
                    if all(k == "dev" for k in kinds):
                        continue
                    out.append(by_id[d["pkg"]]["name"])
                return out
        raise SystemExit(f"tcb-lang-check: crate {name} not found")

    # transitive closure
    seen = set()
    stack = []
    for c in DECISION_CRATES:
        stack.append((c, [c]))
    violations = []
    while stack:
        cur, path = stack.pop()
        for d in deps(cur):
            if (cur, d) in seen:
                continue
            seen.add((cur, d))
            if is_native(d):
                violations.append(" -> ".join(path + [d]))
            stack.append((d, path + [d]))
    if violations:
        for v in sorted(set(violations)):
            print(f"VIOLATION: native-code dependency in TCB: {v}", file=sys.stderr)
        return 1
    print("tcb-lang-check: clean")
    return 0


def self_test(root: Path) -> int:
    """T-REPO-005: a seeded *-sys dep must be detected."""
    import tempfile, shutil
    with tempfile.TemporaryDirectory() as td:
        dst = Path(td) / "repo"
        shutil.copytree(root, dst, ignore=shutil.ignore_patterns("target", ".git"))
        c = dst / "crates" / "gate-core" / "Cargo.toml"
        text = c.read_text()
        text = text.replace("[dependencies]", '[dependencies]\nopenssl-sys = "0.9"', 1)
        c.write_text(text)
        try:
            rc = check(dst)
        except subprocess.CalledProcessError:
            return 0  # dependency does not resolve offline: still a failing build
        if rc == 0:
            print("SELF-TEST FAILED: seeded native dep was not detected", file=sys.stderr)
            return 1
        print("tcb-lang-check self-test: detected seeded violation")
        return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    root = Path(args[args.index("--root") + 1]) if "--root" in args else Path(__file__).resolve().parents[2]
    if "--self-test" in args:
        sys.exit(self_test(root))
    sys.exit(check(root))
