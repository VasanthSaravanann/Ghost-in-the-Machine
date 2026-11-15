#!/usr/bin/env python3
"""T-REPO-006: an `unwrap()` in non-test code must fail the build via clippy.

Creates a throwaway crate carrying the same lint set as the workspace, proves
the clean version passes and the seeded `unwrap()` version fails.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

LINTS = """
[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
"""


def clippy(extra: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / "src").mkdir()
        (p / "Cargo.toml").write_text(
            '[package]\nname = "lint_probe"\nversion = "0.0.0"\nedition = "2021"\n' + LINTS
        )
        (p / "src" / "lib.rs").write_text(
            "pub fn f(xs: &[u8]) -> u8 {\n    " + extra + "\n}\n"
        )
        # An empty workspace prevents inheriting the surrounding one.
        (p / ".cargo").mkdir()
        (p / ".cargo" / "config.toml").write_text("[workspace]\n")
        return subprocess.run(
            ["cargo", "clippy", "--offline", "--quiet", "--", "-D", "warnings"],
            cwd=p, capture_output=True, text=True,
        )


def main() -> int:
    clean = clippy("xs.first().copied().unwrap_or(0)")
    dirty = clippy("xs.iter().next().copied().unwrap()")
    if clean.returncode != 0:
        print(f"lint self-test baseline failed:\n{clean.stderr}", file=sys.stderr)
        return 1
    if dirty.returncode == 0 or "unwrap_used" not in dirty.stderr:
        print("SELF-TEST FAILED: seeded unwrap() was not rejected", file=sys.stderr)
        return 1
    print("lint self-test: seeded unwrap() rejected, clean code accepted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
