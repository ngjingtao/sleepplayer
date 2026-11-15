"""Compare two captures to isolate what one user action added.

This is the actual reverse-engineering loop:

    1. capture a baseline connection
    2. do exactly one thing in the official app (open the alarm screen, receive a
       notification, start a workout)
    3. capture again
    4. diff

Whatever new ids and byte patterns appear are the wire representation of that
action.  Changing a single variable (a different contact name, a different
alarm time) and diffing again separates the field's position from its value.

Comparing captures rather than guessing from documentation is what keeps the
conclusions honest -- a claim about byte 7 is either supported by a diff or it
is not.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .analyze import Analysis

__all__ = ["Comparison", "compare", "render_comparison"]


@dataclass
class Comparison:
    a_path: str
    b_path: str
    only_a: dict[tuple[str, int], int] = field(default_factory=dict)
    only_b: dict[tuple[str, int], int] = field(default_factory=dict)
    changed: dict[tuple[str, int], tuple[list[bytes], list[bytes]]] = field(
        default_factory=dict
    )
    same: dict[tuple[str, int], int] = field(default_factory=dict)

    @property
    def has_differences(self) -> bool:
        return bool(self.only_a or self.only_b or self.changed)

    def to_dict(self) -> dict:
        def key(k):
            kind, cmd = k
            return {"kind": kind, "id": f"0x{cmd:02x}"}

        return {
            "a": self.a_path,
            "b": self.b_path,
            "only_in_a": [dict(key(k), count=v) for k, v in self.only_a.items()],
            "only_in_b": [dict(key(k), count=v) for k, v in self.only_b.items()],
            "changed": [
                dict(key(k),
                     a=[p.hex() for p in pa],
                     b=[p.hex() for p in pb])
                for k, (pa, pb) in self.changed.items()
            ],
            "unchanged": [dict(key(k), count=v) for k, v in self.same.items()],
        }


def _by_id(a: Analysis) -> dict[tuple[str, int], list[bytes]]:
    """Group observed payloads per (direction-kind, id), preserving order."""
    groups: dict[tuple[str, int], list[bytes]] = {}
    for df in a.frames:
        if df.frame.cmd is None:
            continue
        groups.setdefault((df.frame.kind.value, df.frame.cmd), []).append(
            df.frame.payload
        )
    return groups


def compare(a: Analysis, b: Analysis) -> Comparison:
    ga, gb = _by_id(a), _by_id(b)
    cmp = Comparison(a_path=a.path, b_path=b.path)

    for key in ga.keys() - gb.keys():
        cmp.only_a[key] = len(ga[key])
    for key in gb.keys() - ga.keys():
        cmp.only_b[key] = len(gb[key])

    for key in ga.keys() & gb.keys():
        pa, pb = ga[key], gb[key]
        if pa == pb:
            cmp.same[key] = len(pa)
        else:
            cmp.changed[key] = (pa, pb)

    return cmp


def _first_difference(left: bytes, right: bytes) -> tuple[int, int | None, int | None]:
    """Return (offset, left byte, right byte) of the first divergence.

    A byte that exists on one side only is reported as None, which is how a
    length change shows up.
    """
    for i in range(max(len(left), len(right))):
        lo = left[i] if i < len(left) else None
        ro = right[i] if i < len(right) else None
        if lo != ro:
            return i, lo, ro
    return -1, None, None


def _hex(b: bytes, limit: int = 40) -> str:
    text = b[:limit].hex(" ")
    return text + (" ..." if len(b) > limit else "")


def render_comparison(cmp: Comparison, limit: int = 6) -> str:
    out = [
        "=" * 78,
        " CAPTURE DIFF",
        "=" * 78,
        f" a  {cmp.a_path}",
        f" b  {cmp.b_path}",
    ]

    if not cmp.has_differences:
        out.append("\n The two captures are identical at the Mi Band frame level.")
        out.append(" (If you changed something in the app, the change is below the")
        out.append("  frame layer -- try comparing raw ATT writes instead.)")
        return "\n".join(out)

    def fmt(key: tuple[str, int]) -> str:
        kind, cmd = key
        return f"{kind:<8} 0x{cmd:02x}"

    if cmp.only_b:
        out.append(f"\n NEW IN b (added by whatever you did)  [{len(cmp.only_b)}]")
        out.append("-" * 78)
        for key, count in sorted(cmp.only_b.items()):
            out.append(f"   {fmt(key)}   {count} frame(s)")

    if cmp.only_a:
        out.append(f"\n ONLY IN a (removed)  [{len(cmp.only_a)}]")
        out.append("-" * 78)
        for key, count in sorted(cmp.only_a.items()):
            out.append(f"   {fmt(key)}   {count} frame(s)")

    if cmp.changed:
        out.append(f"\n SAME ID, DIFFERENT BYTES  [{len(cmp.changed)}]")
        out.append("-" * 78)
        for key, (pa, pb) in sorted(cmp.changed.items()):
            out.append(f"\n   {fmt(key)}")
            for left, right in list(zip(pa, pb))[:limit]:
                off, lb, rb = _first_difference(left, right)
                out.append(f"     a: {_hex(left)}")
                out.append(f"     b: {_hex(right)}")
                if off < 0:
                    out.append("        identical")
                elif lb is None or rb is None:
                    out.append(
                        f"        length differs at byte {off} "
                        f"(a={len(left)}, b={len(right)})"
                    )
                else:
                    out.append(
                        f"        first difference at byte {off}: "
                        f"0x{lb:02x} -> 0x{rb:02x}"
                    )
            if len(pa) > limit:
                out.append(f"     ... {len(pa) - limit} more")

    if cmp.same:
        out.append(f"\n UNCHANGED IDS  [{len(cmp.same)}]")
        out.append("-" * 78)
        out.append("   " + ", ".join(fmt(k) for k in sorted(cmp.same)))

    out.append("")
    out.append(" Next: label what you found")
    if cmp.only_b or cmp.changed:
        key = sorted(cmp.only_b or cmp.changed)[0]
        flag = " --response" if key[0] == "response" else ""
        out.append(
            f'   python3 -m remiband annotate <b> --cmd 0x{key[1]:02x}{flag} '
            f'--name "what the action was"'
        )
    return "\n".join(out)
