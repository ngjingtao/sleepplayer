"""Human-readable rendering of an `Analysis`.

Presentation only -- no inference happens here.  Anything the analyzer could
not prove is labelled as unknown or hypothesis rather than dressed up.
"""

from __future__ import annotations

import textwrap
from collections import Counter

from . import att as attmod
from . import miband, uuids
from .analyze import APP_TO_BAND, Analysis
from .fingerprint import Fingerprint, fingerprint

__all__ = [
    "render",
    "render_services",
    "render_frames",
    "render_timeline",
    "render_protocol",
    "render_survey",
]

RULE = "=" * 78
SUB = "-" * 78


def _header(title: str) -> str:
    return f"\n{title}\n{SUB}"


def _hex_or_text(value: bytes) -> str:
    """Text for long printable blobs, hex for short binary values.

    A one-byte battery level of 0x5A is not the string "Z"; showing it as text
    would be actively misleading.
    """
    if len(value) > 2:
        try:
            text = value.decode("utf-8")
            if text.isprintable() and text:
                return f'"{text}"'
        except UnicodeDecodeError:
            pass
    return value.hex(" ")


def render(a: Analysis, show_frames: bool = True, frame_limit: int = 200) -> str:
    out: list[str] = []
    cap = a.capture

    out.append(RULE)
    out.append(" REMiBand analysis")
    out.append(RULE)
    out.append(f" file      {a.path}")
    out.append(
        f" records   {len(cap.records)}   span {cap.span:.3f} s   "
        f"datalink {cap.datalink}"
        f"{' (HCI UART)' if cap.datalink == 1002 else ''}"
    )
    if cap.records:
        out.append(f" starts    {cap.records[0].ts_iso}")
    out.append(
        " l2cap     " + "  ".join(
            f"{k}={v}" for k, v in sorted(a.l2cap_counts.items())
        )
    )

    # -- link ----------------------------------------------------------
    out.append(_header(" LINK"))
    if a.peer_addr:
        name = f'  "{a.adv_name}"' if a.adv_name else ""
        out.append(f"   peer      {a.peer_addr}{name}")
    else:
        out.append("   peer      (no connection-complete event in capture)")
    bits = []
    if a.connect_handle is not None:
        bits.append(f"handle 0x{a.connect_handle:04x}")
    if a.mtu:
        bits.append(f"MTU {a.mtu}")
    if a.encryption_enabled is not None:
        bits.append(f"encryption {'on' if a.encryption_enabled else 'off'}")
    if bits:
        out.append("   link      " + "   ".join(bits))
    if a.adv_service_data:
        for svc, data in a.adv_service_data:
            out.append(
                f"   advert    service data {uuids.short_uuid(svc)}: {data.hex(' ')}"
            )

    # -- protocol ------------------------------------------------------
    out.append(render_protocol(fingerprint(a)))

    # -- auth ----------------------------------------------------------
    out.append(_header(" AUTHENTICATION"))
    st = a.auth.state
    verdict = {
        miband.AuthState.AUTHENTICATED: "PASS - command channel unlocked in this capture",
        miband.AuthState.FAILED: "FAIL - the band rejected the key",
        miband.AuthState.IDLE: "NOT OBSERVED - no auth traffic in this capture",
    }.get(st, f"INCOMPLETE - ended in state '{st.value}'")
    out.append(f"   result    {verdict}")
    if a.auth.key is not None:
        consistency = {
            True: "consistent with capture",
            False: "DOES NOT match capture (wrong key or different transform)",
            None: "not exercised (no challenge seen)",
        }[a.auth.key_consistent]
        out.append(f"   key       16 bytes supplied - {consistency}")
    elif a.auth.nonce is not None:
        out.append("   key       not supplied - pass --key to verify your key")
    if a.auth.nonce:
        out.append(f"   nonce     {a.auth.nonce.hex()}")
    if a.auth.steps:
        out.append("")
        for s in a.auth.steps:
            tag = f"{s.at - cap.t0:8.3f}s" if s.at is not None else " " * 9
            out.append(f"   {tag}  {s.direction:<10} {s.detail}")

    # -- timeline ------------------------------------------------------
    out.append(_header(" TIMELINE"))
    if not a.events:
        out.append("   (no events)")
    for e in a.events:
        out.append(f"   {e.rel:8.3f}s  {e.kind:<10} {e.text}")

    # -- services ------------------------------------------------------
    out.append(render_services(a))

    # -- channels ------------------------------------------------------
    out.append(_header(" CHANNELS (observed traffic per handle)"))
    rows = []
    for ch in sorted(a.channels.values(), key=lambda c: c.handle):
        if not ch.total:
            continue
        rows.append(
            (
                f"0x{ch.handle:04x}",
                uuids.short_uuid(ch.uuid) if ch.uuid else "?",
                ch.label,
                str(ch.writes + ch.write_cmds),
                str(ch.notifies + ch.indications),
                str(ch.frames),
                f"{ch.bytes_out}/{ch.bytes_in}",
            )
        )
    if rows:
        out.extend(
            _table(
                ("handle", "uuid", "label", "out", "in", "frames", "bytes o/i"),
                rows,
                indent="   ",
            )
        )
    else:
        out.append("   (no attribute traffic)")

    # -- frames --------------------------------------------------------
    if show_frames:
        out.append(render_frames(a, frame_limit))

    # -- unknowns ------------------------------------------------------
    unresolved = a.unresolved_ids()
    out.append(_header(" UNRESOLVED COMMAND IDS"))
    if unresolved:
        out.append(
            "   These ids appear in the capture but carry no known meaning."
        )
        out.append("   Give them names as you work out what triggers them:")
        out.append("")
        for (kind, cmd), count in unresolved.items():
            flag = " --response" if kind == "response" else ""
            out.append(
                f"     {kind:<8} 0x{cmd:02x}   {count:>3} frame(s)"
                f"    (--cmd 0x{cmd:02x}{flag})"
            )
        out.append("")
        out.append(
            '     python3 -m remiband annotate <file> --cmd 0x13 --name "..."'
        )
    else:
        out.append("   none - every observed id has a label")

    out.append("")
    return "\n".join(out)


def render_protocol(fp: Fingerprint) -> str:
    out = [_header(" PROTOCOL (which framing does this device speak?)")]
    out.append(f"   verdict   {fp.verdict}")
    out.append(
        f"   traffic   {fp.total_samples} candidate samples, "
        f"{fp.entropy:.2f} bits/byte entropy"
    )
    for h in sorted(fp.hypotheses, key=lambda x: -x.score):
        out.append(f"   {h.name:<11} {h.score:5.2f}   {h.evidence}")
    out.append("")
    for line in textwrap.wrap(fp.advice, 70):
        out.append("   " + line)
    return "\n".join(out)


def render_survey(a: Analysis, limit: int = 40) -> str:
    """Dump the traffic with no protocol assumptions at all.

    This is the command to reach for on an unrecognised device: it shows every
    handle that carried anything, the block sizes, and raw hex, before any
    decoder gets an opinion.
    """
    out = [RULE, " REMiBand survey (protocol-agnostic)", RULE]
    out.append(f" file      {a.path}")
    out.append(f" records   {len(a.capture.records)}   span {a.capture.span:.3f} s")
    out.append(f" peer      {a.peer_addr or '(no connection event)'}")
    out.append(f" services  {len(a.gatt.services)}   "
               f"characteristics {len(a.gatt.chars)}")

    by_handle: dict[int, list[tuple[float, str, bytes]]] = {}
    for rel, handle, direction, value in a.samples:
        by_handle.setdefault(handle, []).append((rel, direction, value))

    out.append(_header(" TRAFFIC BY HANDLE"))
    rows = []
    for handle in sorted(by_handle):
        vals = by_handle[handle]
        lengths = Counter(len(v) for _r, _d, v in vals)
        length_str = ", ".join(f"{ln}x{n}" for ln, n in lengths.most_common(3))
        directions = "both" if len({d for _r, d, _v in vals}) > 1 else (
            "out" if vals[0][1] == APP_TO_BAND else "in"
        )
        sample = vals[0][2].hex(" ")[:44]
        rows.append((
            f"0x{handle:04x}",
            uuids.short_uuid(a.gatt.uuid_of(handle) or "") or "?",
            directions,
            str(len(vals)),
            length_str,
            sample,
        ))
    if rows:
        out.extend(_table(("handle", "uuid", "dir", "n", "lengths", "first value"),
                          rows, indent="   "))
    else:
        out.append("   (no write or notification traffic found at all)")

    for handle in sorted(by_handle)[:8]:
        vals = by_handle[handle]
        out.append("")
        out.append(f"   handle 0x{handle:04x} "
                   f"({a.gatt.label(handle)}) - {min(len(vals), limit)} values")
        for _rel, direction, value in vals[:limit]:
            arrow = "->" if direction == APP_TO_BAND else "<-"
            out.append(f"     {arrow} {value.hex(' ')}")

    out.append(render_protocol(fingerprint(a)))
    out.append("")
    out.append(" Next steps for an unrecognised device")
    out.append(SUB)
    out.append("   1. confirm the block size and counter offset from the evidence above")
    out.append("   2. capture a baseline, do one action, `remiband diff`, and look")
    out.append("      for which bytes move")
    out.append("   3. if payloads are opaque, find the session key exchange first")
    return "\n".join(out)


def render_services(a: Analysis) -> str:
    out = [_header(f" SERVICES ({len(a.gatt.services)})")]
    if not a.gatt.services:
        out.append("   (no discovery traffic in capture)")
        return "\n".join(out)

    for svc in a.gatt.services:
        out.append("")
        out.append(f"   0x{svc.start:04x}-0x{svc.end:04x}  "
                   f"{uuids.short_uuid(svc.uuid):<12} {svc.name}")
        if not svc.characteristics:
            continue
        for ch in sorted(svc.characteristics, key=lambda c: c.value_handle):
            props = attmod.properties_str(ch.props)
            line = f"     0x{ch.value_handle:04x}  "
            line += f"{uuids.short_uuid(ch.uuid):<12} {ch.name:<24} [{props}]"
            value = a.gatt.values.get(ch.value_handle)
            if value:
                line += f"  = {_hex_or_text(value)}"
            out.append(line)
    return "\n".join(out)


def render_frames(a: Analysis, limit: int = 200) -> str:
    out = [_header(f" FRAMES ({len(a.frames)} decoded)")]
    if not a.frames:
        out.append("   (no 0xa0-framed Mi Band messages)")
        return "\n".join(out)

    shown = a.frames[:limit]
    for df in shown:
        arrow = "->" if df.direction == APP_TO_BAND else "<-"
        head = f"   {df.rel:8.3f}s {arrow} {df.label:<24}"
        body = df.frame.header()
        out.append(f"{head} {body}")
        if df.frame.payload:
            out.append(f"{'':>22}   {df.frame.payload.hex(' ')}")
        notes = []
        if df.name:
            notes.append(f"{df.name} [{df.confidence}]")
        if df.hint:
            notes.append(df.hint)
        if notes:
            out.append(f"{'':>22}   {' | '.join(notes)}")

    if len(a.frames) > limit:
        out.append(
            f"   ... {len(a.frames) - limit} more frames "
            f"(use --limit to widen)"
        )
    return "\n".join(out)


def render_timeline(a: Analysis) -> str:
    out = [_header(" TIMELINE")]
    for e in a.events:
        out.append(f"   {e.rel:8.3f}s  {e.kind:<10} {e.text}")
    return "\n".join(out)


def _table(headers, rows, indent: str = "") -> list[str]:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    lines = [indent + "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers))]
    lines.append(indent + "  ".join("-" * w for w in widths))
    for row in rows:
        lines.append(
            indent + "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row))
        )
    return lines
