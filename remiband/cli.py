"""Command line interface: `python3 -m remiband <command>`.

Commands are deliberately small and composable so that a real investigation can
be scripted:

    remiband demo                       # prove the toolchain, no hardware
    remiband analyze capture.btsnoop    # the main report
    remiband services capture.btsnoop   # just the recovered attribute table
    remiband frames capture.btsnoop     # just the 0xa0-framed messages
    remiband auth capture.btsnoop --key <32 hex>
    remiband annotate capture.btsnoop --cmd 0x13 --name "find device"
    remiband live --scan                # needs hardware + `pip install bleak`
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from . import compare, demo_capture, miband
from .analyze import analyze
from .render import (
    render,
    render_frames,
    render_services,
    render_survey,
    render_timeline,
)


def _parse_key(text: str | None) -> bytes | None:
    if not text:
        return None
    cleaned = text.replace(":", "").replace(" ", "").replace("-", "")
    try:
        key = bytes.fromhex(cleaned)
    except ValueError:
        raise SystemExit(f"error: --key must be hex, got {text!r}")
    if len(key) != 16:
        raise SystemExit(
            f"error: --key must be 16 bytes (32 hex chars), got {len(key)}"
        )
    return key


def _load_labels(path: str | None) -> miband.CommandTable:
    return miband.CommandTable(path) if path else miband.CommandTable()


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_analyze(args: argparse.Namespace) -> int:
    a = analyze(args.file, key=_parse_key(args.key),
                labels=_load_labels(args.labels))
    if args.json:
        json.dump(a.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    print(render(a, show_frames=not args.no_frames, frame_limit=args.limit))
    return 0


def cmd_services(args: argparse.Namespace) -> int:
    a = analyze(args.file, labels=_load_labels(args.labels))
    print(render_services(a))
    return 0


def cmd_frames(args: argparse.Namespace) -> int:
    a = analyze(args.file, key=_parse_key(args.key),
                labels=_load_labels(args.labels))
    print(render_frames(a, limit=args.limit))
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    a = analyze(args.file, labels=_load_labels(args.labels))
    print(render_timeline(a))
    return 0


def cmd_auth(args: argparse.Namespace) -> int:
    a = analyze(args.file, key=_parse_key(args.key),
                labels=_load_labels(args.labels))
    if not a.auth.steps:
        print("No authentication traffic in this capture.")
        return 1
    print(f"state:  {a.auth.state.value}")
    if a.auth.key is not None:
        if a.auth.key_consistent is False:
            print("key:    MISMATCH - this key does not reproduce the "
                  "band's challenge")
        elif a.auth.key_consistent is True:
            print("key:    consistent with capture")
        else:
            print("key:    not exercised (no challenge in this capture)")
    for s in a.auth.steps:
        tag = f"{s.at - a.capture.t0:8.3f}s" if s.at else " " * 9
        print(f"  {tag}  {s.direction:<10} {s.detail}")

    # Exit non-zero when a supplied key is demonstrably wrong, even if the
    # capture itself narrates a successful auth -- checking the key is the
    # whole point of this command.
    if not a.auth.succeeded:
        return 1
    return 1 if a.auth.key_consistent is False else 0


def cmd_annotate(args: argparse.Namespace) -> int:
    table = _load_labels(args.labels)
    cmd = int(args.cmd, 0)
    target = table.responses if args.response else table.commands
    target[cmd] = (args.name, args.confidence)
    out = args.labels or "labels.json"
    table.save(out)
    kind = "response" if args.response else "command"
    print(f"labelled {kind} 0x{cmd:02x} as {args.name!r} -> {out}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    path = args.keep or os.path.join(
        os.environ.get("TMPDIR", "/tmp"), "remiband_demo.btsnoop"
    )
    demo_capture.write(path)
    a = analyze(path, key=demo_capture.AUTH_KEY)
    print(render(a, show_frames=not args.no_frames, frame_limit=args.limit))
    print()
    print("NOTE: this capture is a synthetic fixture built by")
    print("      remiband/demo_capture.py to exercise every decoder path.")
    print("      It is not a recording of a real device.")
    print(f"      written to {path}")
    return 0


def cmd_survey(args: argparse.Namespace) -> int:
    a = analyze(args.file, key=_parse_key(args.key),
                labels=_load_labels(args.labels))
    if args.json:
        json.dump(a.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    print(render_survey(a, limit=args.limit))
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    labels = _load_labels(args.labels)
    key = _parse_key(args.key)
    a = analyze(args.a, key=key, labels=labels)
    b = analyze(args.b, key=key, labels=labels)
    cmp = compare.compare(a, b)
    if args.json:
        json.dump(cmp.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    print(compare.render_comparison(cmp, limit=args.limit))
    return 0


def cmd_live(args: argparse.Namespace) -> int:
    try:
        from . import live
    except ImportError as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return live.main(args)


# --------------------------------------------------------------------------
# wiring
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="remiband",
        description="Reverse-engineering workbench for the Xiaomi Mi Band BLE link.",
        epilog="No hardware needed for the capture commands: feed it a btsnoop "
               "from Android (HCI snoop log), btmon, or the nRF sniffer.",
    )
    p.add_argument("--version", action="version", version=f"remiband {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp, key: bool = False) -> None:
        sp.add_argument("file", help="btsnoop capture file")
        sp.add_argument("--labels", metavar="JSON",
                        help="command-label table (created by `annotate`)")
        if key:
            sp.add_argument("--key", metavar="HEX",
                            help="16-byte auth key, hex (verify against capture)")

    sp = sub.add_parser("analyze", help="full report: link, auth, services, frames")
    add_common(sp, key=True)
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    sp.add_argument("--no-frames", action="store_true", help="omit the frame log")
    sp.add_argument("--limit", type=int, default=200, help="max frames to show")
    sp.set_defaults(func=cmd_analyze)

    sp = sub.add_parser("services", help="recovered attribute table only")
    add_common(sp)
    sp.set_defaults(func=cmd_services)

    sp = sub.add_parser("frames", help="decoded Mi Band messages only")
    add_common(sp, key=True)
    sp.add_argument("--limit", type=int, default=500, help="max frames to show")
    sp.set_defaults(func=cmd_frames)

    sp = sub.add_parser("timeline", help="event timeline only")
    add_common(sp)
    sp.set_defaults(func=cmd_timeline)

    sp = sub.add_parser("auth", help="authentication handshake only")
    add_common(sp, key=True)
    sp.set_defaults(func=cmd_auth)

    sp = sub.add_parser("annotate", help="give a command id a name")
    sp.add_argument("file", help="capture the id was observed in")
    sp.add_argument("--cmd", required=True, help="command id, e.g. 0x13")
    sp.add_argument("--name", required=True, help="what it does")
    sp.add_argument("--response", action="store_true",
                    help="label a band->app id instead of an app->band one")
    sp.add_argument("--confidence", default="user",
                    choices=["user", "high", "medium", "low"])
    sp.add_argument("--labels", metavar="JSON", help="label table to update")
    sp.set_defaults(func=cmd_annotate)

    sp = sub.add_parser("demo", help="build a synthetic capture and analyse it")
    sp.add_argument("--keep", metavar="PATH", help="where to write the fixture")
    sp.add_argument("--no-frames", action="store_true")
    sp.add_argument("--limit", type=int, default=200)
    sp.set_defaults(func=cmd_demo)

    sp = sub.add_parser(
        "survey",
        help="dump traffic with no protocol assumptions (use on unknown devices)",
        description="Shows every handle that carried traffic, the block sizes, "
                    "or raw hex, then scores framing hypotheses. This is the "
                    "command for a band newer than the classic 0xA0 protocol.",
    )
    sp.add_argument("file", help="btsnoop capture file")
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    sp.add_argument("--limit", type=int, default=40,
                    help="values to show per handle")
    sp.add_argument("--labels", metavar="JSON", help="command-label table")
    sp.add_argument("--key", metavar="HEX", help="16-byte auth key")
    sp.set_defaults(func=cmd_survey)

    sp = sub.add_parser(
        "diff",
        help="compare two captures to isolate one user action",
        description="Capture a baseline connection, do exactly one thing in the "
                    "official app, capture again, then diff. New ids and changed "
                    "bytes are that action's wire representation.",
    )
    sp.add_argument("a", help="baseline capture")
    sp.add_argument("b", help="capture made after the action")
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    sp.add_argument("--limit", type=int, default=6, help="payload pairs to show")
    sp.add_argument("--labels", metavar="JSON", help="command-label table")
    sp.add_argument("--key", metavar="HEX", help="16-byte auth key")
    sp.set_defaults(func=cmd_diff)

    sp = sub.add_parser("live", help="talk to a real band (needs bleak + radio)")
    sp.add_argument("--scan", action="store_true", help="list nearby devices")
    sp.add_argument("--address", help="device address/MAC to connect to")
    sp.add_argument("--name", help="substring of the device name to match")
    sp.add_argument("--key", metavar="HEX", help="16-byte auth key")
    sp.add_argument("--timeout", type=float, default=20.0)
    sp.add_argument("--read", action="append", default=[], metavar="UUID",
                    help="read a characteristic after auth (repeatable)")
    sp.add_argument("--send", action="append", default=[], metavar="HEX",
                    help="write hex bytes after auth (repeatable)")
    sp.add_argument("--write-uuid", default="0000ff05-0000-1000-8000-00805f9b34fb",
                    help="characteristic for --send (default: ff05 control point)")
    sp.add_argument("--no-response", action="store_true",
                    help="use write-without-response for --send")
    sp.add_argument("--hold", type=float, default=0.0,
                    help="keep the connection open N seconds (watch notifications)")
    sp.set_defaults(func=cmd_live)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
