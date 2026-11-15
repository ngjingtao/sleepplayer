"""Work out which application-level framing a device actually speaks.

Why this exists: the classic `0xA0` protocol in `miband.py` covers Mi Band 3/4
well and 5/6 loosely.  Newer bands (7 and up, Zepp OS / HyperOS lineage) moved
to a chunked transport, and a decoder that silently finds zero frames on such a
device looks like a broken tool rather than an unrecognised protocol.

So instead of assuming, this module scores several framing hypotheses against
the traffic actually observed and reports which one fits.  Every score comes
with the evidence that produced it, and no hypothesis is ever asserted on
faith:

    classic-a0     message envelope starts 0xA0, header is cmd/seq/len
    chunked        fixed-length blocks with a per-frame counter -- the newer
                   transport shape
    textual        printable payloads (names, notification text)
    opaque         high-entropy, no ASCII structure: encrypted or compressed

Verdicts are advisory.  The point is to stop you writing a decoder for the
wrong protocol, which is the expensive mistake.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

from . import miband
from .analyze import Analysis

__all__ = [
    "Hypothesis",
    "Fingerprint",
    "fingerprint",
    "entropy",
    "printable_ratio",
    "distinct_ratio",
]

MIN_SAMPLES = 4


@dataclass
class Hypothesis:
    name: str
    score: float
    evidence: str


@dataclass
class Fingerprint:
    total_samples: int
    hypotheses: list[Hypothesis] = field(default_factory=list)
    verdict: str = "unknown"
    advice: str = ""
    entropy: float = 0.0
    printable_ratio: float = 0.0
    distinct_ratio: float = 0.0

    @property
    def top(self) -> Hypothesis | None:
        return max(self.hypotheses, key=lambda h: h.score) if self.hypotheses else None

    def score_of(self, name: str) -> float:
        for h in self.hypotheses:
            if h.name == name:
                return h.score
        return 0.0


# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------

def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(
        (c / n) * math.log2(c / n) for c in Counter(data).values()
    )


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII, tab, or newline."""
    if not data:
        return 0.0
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(data)


def distinct_ratio(data: bytes) -> float:
    """Fraction of byte values that appear only once -- near 1 for ciphertext.

    Short random samples are not high-entropy in the Shannon sense (20 bytes
    cannot express eight bits per byte of entropy), but they are still
    *structureless*, and this measures that directly.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    once = sum(1 for c in counts.values() if c == 1)
    return once / len(data)


# --------------------------------------------------------------------------
# Sample selection
# --------------------------------------------------------------------------

def _protocol_samples(a: Analysis) -> list[tuple[str, bytes]]:
    """Traffic worth judging the framing on.

    Two things are excluded on purpose:

    * the auth channel -- it is a fixed-format control channel (`01 08`,
      `10 02 01 ...`) that would drag every score toward "opaque";
    * values of two bytes or fewer -- those are CCCD subscriptions, not messages.
    """
    auth_uuid = miband.AUTH_UUID
    out: list[tuple[str, bytes]] = []
    for _rel, handle, direction, value in a.samples:
        ch = a.channels.get(handle)
        if ch is not None and ch.uuid == auth_uuid:
            continue
        if len(value) <= 2:
            continue
        out.append((direction, value))
    return out


# --------------------------------------------------------------------------
# Hypotheses
# --------------------------------------------------------------------------

def _score_classic(samples: list[tuple[str, bytes]]) -> tuple[float, str]:
    if not samples:
        return 0.0, "no candidate traffic"
    ok = sum(1 for d, v in samples if miband.decode_frame(v, d) is not None)
    frac = ok / len(samples)
    if ok == 0:
        return 0.0, f"0/{len(samples)} samples start with 0xA0"
    return frac, f"{ok}/{len(samples)} samples parse as 0xA0 frames"


def _score_chunked(samples: list[tuple[str, bytes]]) -> tuple[float, str]:
    if len(samples) < MIN_SAMPLES:
        return 0.0, "too few samples"

    lengths = Counter(len(v) for _d, v in samples)
    modal, count = lengths.most_common(1)[0]
    frac = count / len(samples)
    if modal < 8:
        return 0.0, f"modal block length {modal} is too small to be a transport"

    groups: dict[str, list[bytes]] = {}
    for d, v in samples:
        if len(v) == modal:
            groups.setdefault(d, []).append(v)

    best_ratio = 0.0
    best_off: int | None = None
    for vals in groups.values():
        if len(vals) < 3:
            continue
        for off in range(min(6, modal)):
            hits = total = 0
            for left, right in zip(vals, vals[1:]):
                total += 1
                if ((left[off] + 1) & 0xFF) == right[off]:
                    hits += 1
            ratio = hits / total if total else 0.0
            if ratio > best_ratio:
                best_ratio, best_off = ratio, off

    score = frac * (0.55 + 0.45 * best_ratio)
    evidence = f"{count}/{len(samples)} samples are exactly {modal} bytes"
    if best_off is not None and best_ratio >= 0.5:
        evidence += (
            f"; byte {best_off} increments per frame "
            f"({best_ratio:.0%} of consecutive pairs)"
        )
    return score, evidence


def _score_textual(pooled: bytes, samples: list[tuple[str, bytes]]) -> tuple[float, str]:
    if not samples:
        return 0.0, "no candidate traffic"
    ratio = printable_ratio(pooled)
    return ratio, f"{ratio:.0%} of bytes are printable ASCII"


def _score_opaque(pooled: bytes, samples: list[tuple[str, bytes]]) -> tuple[float, str]:
    if not samples:
        return 0.0, "no candidate traffic"
    score = (1.0 - printable_ratio(pooled)) * distinct_ratio(pooled)
    return score, (
        f"entropy {entropy(pooled):.2f} bits/byte, "
        f"{distinct_ratio(pooled):.0%} of bytes appear only once"
    )


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

_ADVICE = {
    "classic-a0": (
        "The classic 0xA0 decoder applies. Use `remiband frames` and build a "
        "label table with `annotate`."
    ),
    "chunked": (
        "This is NOT the classic 0xA0 protocol: fixed-size blocks with a "
        "running counter are the newer Xiaomi/Zepp transport. The 0xA0 decoder "
        "will find nothing here. Record the block size and the counter offset "
        "from the evidence above -- that is the first field of the new "
        "envelope -- then diff captures to find the rest."
    ),
    "textual": (
        "Payloads are mostly text, which is what a name or notification write "
        "looks like. Not enough structure here to identify a transport; "
        "capture a connect and some commands, not just a name write."
    ),
    "opaque": (
        "Payloads are high-entropy with no ASCII structure: encrypted or "
        "compressed. For a newer band this is expected -- it means the session "
        "has an encryption layer above BLE link encryption, and you will need "
        "the pairing/session key before any of it is readable. Find the key "
        "exchange in the capture first (see docs/protocol.md)."
    ),
    "unknown": (
        "No framing hypothesis scored well. Collect more traffic: connect, "
        "idle, do one action, disconnect. A capture with only discovery in it "
        "cannot identify an application protocol."
    ),
}


def fingerprint(a: Analysis) -> Fingerprint:
    samples = _protocol_samples(a)
    pooled = b"".join(v for _d, v in samples)

    fp = Fingerprint(
        total_samples=len(samples),
        entropy=entropy(pooled),
        printable_ratio=printable_ratio(pooled),
        distinct_ratio=distinct_ratio(pooled),
    )

    classic_s, classic_e = _score_classic(samples)
    chunked_s, chunked_e = _score_chunked(samples)
    text_s, text_e = _score_textual(pooled, samples)
    opaque_s, opaque_e = _score_opaque(pooled, samples)

    fp.hypotheses = [
        Hypothesis("classic-a0", classic_s, classic_e),
        Hypothesis("chunked", chunked_s, chunked_e),
        Hypothesis("textual", text_s, text_e),
        Hypothesis("opaque", opaque_s, opaque_e),
    ]

    # The classic envelope is a strong positive signal: it is checked
    # structurally, not statistically, so a clear majority wins outright.
    if classic_s >= 0.5:
        fp.verdict = "classic-a0"
    elif chunked_s >= 0.5:
        fp.verdict = "chunked"
    elif text_s >= 0.8:
        fp.verdict = "textual"
    elif opaque_s >= 0.35:
        fp.verdict = "opaque"
    else:
        fp.verdict = "unknown"

    fp.advice = _ADVICE[fp.verdict]
    return fp
