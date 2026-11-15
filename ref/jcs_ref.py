#!/usr/bin/env python3
"""Independent RFC 8785 implementation used only for differential tests.

NOT part of the TCB and never linked into a product binary (plan.md §2.0).
Deliberately avoids sharing code with gate-jcs: it starts from CPython's
shortest-round-trip `repr(float)`, whereas the Rust implementation starts from
Rust's `{:e}`.

Reads JSONL of {"in": <json text>, "out": <gate-jcs canonicalisation>} and
prints the number of mismatches; exits non-zero if any.
"""
import json
import math
import re
import sys

class Reject(Exception):
    pass


def _pairs_hook(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise Reject("duplicate key")
    return dict(pairs)


def _parse_constant(_name):
    raise Reject("non-finite")


def _check_surrogates(v):
    if isinstance(v, str):
        for ch in v:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise Reject("lone surrogate")
    elif isinstance(v, list):
        for x in v:
            _check_surrogates(x)
    elif isinstance(v, dict):
        for k, x in v.items():
            _check_surrogates(k)
            _check_surrogates(x)


def _fmt_number(x):
    # x is int or Decimal-or-float already validated as exact.
    f = float(x)
    if isinstance(x, int) and f != x:
        raise Reject("integer not representable")
    if not math.isfinite(f):
        raise Reject("non-finite")
    if f == 0:
        return "0"
    neg = math.copysign(1.0, f) < 0
    text = repr(abs(f))
    if "e" in text:
        mant, exp = text.split("e")
        exp = int(exp)
    else:
        mant, exp = text, 0
    if "." in mant:
        int_part, frac_part = mant.split(".")
    else:
        int_part, frac_part = mant, ""
    raw = int_part + frac_part
    stripped = raw.lstrip("0")
    digits = stripped.rstrip("0")
    if not digits:
        return "0"
    k = len(digits)
    trailing = len(stripped) - k
    n = k + exp - len(frac_part) + trailing
    out = "-" if neg else ""
    if k <= n <= 21:
        out += digits + "0" * (n - k)
    elif 0 < n <= 21:
        out += digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out += "0." + "0" * (-n) + digits
    else:
        out += digits[:1]
        if k > 1:
            out += "." + digits[1:]
        e = n - 1
        out += "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return out


def _escape(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonical(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _fmt_number(value)
    if isinstance(value, str):
        return _escape(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=lambda s: s.encode("utf-16-be"))
        return "{" + ",".join(_escape(k) + ":" + canonical(value[k]) for k in keys) + "}"
    raise Reject("unknown value")


def main(path):
    bad = 0
    total = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            total += 1
            try:
                value = json.loads(
                    rec["in"],
                    object_pairs_hook=_pairs_hook,
                    parse_constant=_parse_constant,
                )
                _check_surrogates(value)
                got = canonical(value)
            except (Reject, ValueError, RecursionError) as exc:
                got = f"ERROR: {exc}"
            if got != rec["out"]:
                bad += 1
                if bad <= 10:
                    print(f"MISMATCH in={rec['in'][:160]!r}\n  rust={rec['out'][:160]!r}\n  ref ={got[:160]!r}", file=sys.stderr)
    print(f"jcs-ref: {total} documents, {bad} mismatches")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
