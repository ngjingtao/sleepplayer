"""End-to-end tests: synthetic HCI bytes in, device model out.

The fixture is built with the real btsnoop writer and real ATT encoders, so
these tests fail if the wire format, the reassembly, or the GATT bookkeeping
drifts apart.
"""

import os
import tempfile
import unittest

from remiband import att, btsnoop, demo_capture, fingerprint as fpm, miband, uuids
from remiband.analyze import analyze


class Fixture:
    _path = None

    @classmethod
    def path(cls) -> str:
        if cls._path is None:
            tmp = tempfile.mkdtemp(prefix="remiband-")
            cls._path = os.path.join(tmp, "demo.btsnoop")
            demo_capture.write(cls._path)
        return cls._path


class TestBtsnoop(unittest.TestCase):
    def test_epoch_constant(self):
        self.assertEqual(btsnoop.BTSNOOP_EPOCH_DELTA_US, 62168256000000000)

    def test_magic_rejected(self):
        with self.assertRaises(btsnoop.BtsnoopError):
            btsnoop.Capture.from_bytes(b"\x00" * 64)

    def test_timestamp_is_64_bit(self):
        cap = btsnoop.Capture.from_file(Fixture.path())
        # A 32-bit timestamp would wrap and land nowhere near 2026.
        self.assertAlmostEqual(cap.t0, demo_capture.T0, delta=1.0)

    def test_rejects_empty(self):
        blob = btsnoop.MAGIC + (1).to_bytes(4, "big") + (1002).to_bytes(4, "big")
        with self.assertRaises(btsnoop.BtsnoopError):
            btsnoop.Capture.from_bytes(blob)


class TestAttDecode(unittest.TestCase):
    def test_write_cmd(self):
        p = att.decode(bytes([0x52, 0x1A, 0x00, 0xA0, 0x01]))
        self.assertEqual(p.handle, 0x001A)
        self.assertEqual(p.value, b"\xa0\x01")
        self.assertTrue(p.is_request)

    def test_notify(self):
        p = att.decode(bytes([0x1B, 0x17, 0x00, 0xA0, 0x01, 0x02, 0x01]))
        self.assertEqual(p.handle, 0x0017)
        self.assertEqual(p.value, b"\xa0\x01\x02\x01")

    def test_mtu(self):
        self.assertEqual(att.decode(bytes([0x02, 0xB9, 0x00])).fields["mtu"], 185)

    def test_error_rsp(self):
        p = att.decode(bytes([0x01, 0x12, 0x23, 0x00, 0x05]))
        self.assertEqual(p.handle, 0x0023)
        self.assertEqual(att.ATT_ERRORS[p.fields["error"]], "insufficient auth")

    def test_128bit_uuid_is_byte_reversed(self):
        canonical = "00000009-0000-3512-2118-0009af100700"
        wire = bytes.fromhex(canonical.replace("-", ""))[::-1]
        self.assertEqual(len(wire), 16)
        self.assertEqual(att.uuid_from_wire(wire), canonical)

    def test_16bit_uuid(self):
        self.assertEqual(
            att.uuid_from_wire(bytes([0xE0, 0xFE])),
            "0000fee0-0000-1000-8000-00805f9b34fb",
        )

    def test_unknown_opcode_is_tolerated(self):
        self.assertIn("unknown", att.decode(bytes([0x7F])).name)


class TestFrames(unittest.TestCase):
    def test_command_frame(self):
        f = miband.decode_frame(bytes([0xA0, 0x02, 0x00, 0x02, 0xEA, 0x07]), "app->band")
        self.assertIs(f.kind, miband.FrameKind.COMMAND)
        self.assertEqual(f.cmd, 0x02)
        self.assertEqual(f.seq, 0)
        self.assertEqual(f.payload, b"\xea\x07")

    def test_response_frame(self):
        f = miband.decode_frame(bytes([0xA0, 0x01, 0x0E, 0x01]), "band->app")
        self.assertIs(f.kind, miband.FrameKind.RESPONSE)
        self.assertEqual(f.cmd, 0x0E)
        self.assertTrue(f.ok)

    def test_failed_response(self):
        f = miband.decode_frame(bytes([0xA0, 0x01, 0x13, 0x00]), "band->app")
        self.assertFalse(f.ok)

    def test_non_miband_payload(self):
        self.assertIsNone(miband.decode_frame(bytes([0x01, 0x08]), "app->band"))
        self.assertIsNone(miband.decode_frame(b"", "app->band"))

    def test_chunk_reassembly(self):
        asm = miband.ChunkAssembler()
        text = b"Hello from MiBand!"
        f1 = miband.decode_frame(bytes([0xA0, 0x0A, 0x00, 0x10]) + text[:16], "app->band")
        f2 = miband.decode_frame(bytes([0xA0, 0x0A, 0x01, 0x02]) + text[16:], "app->band")
        self.assertIsNone(asm.feed(f1))
        done = asm.feed(f2)
        self.assertIsNotNone(done)
        self.assertEqual(done.payload, text)

    def test_short_single_chunk_completes(self):
        asm = miband.ChunkAssembler()
        f = miband.decode_frame(bytes([0xA0, 0x04, 0x00, 0x02, 0x01, 0x02]), "app->band")
        self.assertIs(asm.feed(f), f)

    def test_payload_hints(self):
        # 0x07ea == 2026, then month/day/hour/min/sec
        stamp = bytes([0xEA, 0x07, 0x0B, 0x0C, 0x0E, 0x00, 0x00])
        self.assertIn("timestamp-like: 2026-11-12-14-0-0", miband.payload_hint(stamp))
        self.assertIn("text-like", miband.payload_hint(b"hello"))
        self.assertIn("scalar-like", miband.payload_hint(b"\x07"))


class TestAuth(unittest.TestCase):
    def _run(self, key):
        s = miband.AuthSession(key=key)
        s.feed_notify(b"\x10\x01\x01")
        s.feed_write(bytes([0x01, 0x08]))
        s.feed_write(bytes([0x02, 0x00]))
        s.feed_notify(b"\x10\x02\x01" + demo_capture.NONCE)
        s.feed_write(bytes([0x03, 0x00]) + demo_capture.CT)
        s.feed_notify(b"\x10\x03\x01")
        return s

    def test_success_flow(self):
        s = self._run(demo_capture.AUTH_KEY)
        self.assertTrue(s.succeeded)
        self.assertEqual(s.nonce, demo_capture.NONCE)
        self.assertEqual(s.response, demo_capture.CT)

    def test_wrong_key_is_flagged(self):
        # The capture itself narrates a successful auth; a wrong key does not
        # change what the capture says, but it must invalidate our key.
        s = self._run(bytes(16))
        self.assertFalse(s.key_consistent)
        self.assertTrue(
            any("does NOT match" in st.detail for st in s.steps),
            "a wrong key must be reported, not silently accepted",
        )

    def test_right_key_is_confirmed(self):
        s = self._run(demo_capture.AUTH_KEY)
        self.assertTrue(s.key_consistent)

    def test_band_rejects_key(self):
        s = miband.AuthSession(key=demo_capture.AUTH_KEY)
        s.feed_notify(b"\x10\x02\x01" + demo_capture.NONCE)
        s.feed_write(bytes([0x03, 0x00]) + demo_capture.CT)
        s.feed_notify(b"\x10\x03\x00")
        self.assertEqual(s.state, miband.AuthState.FAILED)

    def test_active_next_write_sequence(self):
        s = miband.AuthSession(key=demo_capture.AUTH_KEY)
        self.assertEqual(s.next_write(), miband.AUTH_START)
        s.feed_write(bytes([0x01, 0x08]))
        s.feed_notify(b"\x10\x01\x01")
        self.assertEqual(s.next_write(), miband.AUTH_NONCE_REQ)
        s.feed_write(bytes([0x02, 0x00]))
        s.feed_notify(b"\x10\x02\x01" + demo_capture.NONCE)
        self.assertEqual(
            s.next_write(), bytes([0x03, 0x00]) + demo_capture.CT
        )


class TestAnalyze(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = analyze(Fixture.path())

    def test_connection_recovered(self):
        self.assertEqual(self.a.peer_addr, "C2:4F:90:11:22:33")
        self.assertEqual(self.a.connect_handle, demo_capture.CONN_HANDLE)
        self.assertTrue(self.a.encryption_enabled)

    def test_mtu(self):
        self.assertEqual(self.a.mtu, 185)
        self.assertEqual(self.a.gatt.mtu_client, 185)

    def test_advertised_name(self):
        self.assertEqual(self.a.adv_name, "Mi Smart Band 4")
        self.assertTrue(
            any(uuid == uuids.normalize(0xFE95) for uuid, _ in self.a.adv_service_data)
        )

    def test_services_recovered(self):
        found = {s.uuid for s in self.a.gatt.services}
        self.assertIn(uuids.MIBAND_SERVICE, found)
        self.assertIn(uuids.MIBAND_AUTH_SERVICE, found)
        self.assertIn(uuids.normalize(0x180F), found)
        self.assertEqual(len(self.a.gatt.services), 6)

    def test_characteristics_recovered(self):
        chars = self.a.gatt.chars
        self.assertEqual(len(chars), len(demo_capture.CHARS))
        # the auth channel must be resolved to its real 128-bit UUID
        self.assertIn(demo_capture.H_AUTH, chars)
        self.assertEqual(chars[demo_capture.H_AUTH].uuid, uuids.AUTH_CHARACTERISTIC)
        self.assertEqual(chars[demo_capture.H_CTRL].uuid, uuids.normalize(0xFF05))

    def test_reads_captured(self):
        self.assertEqual(
            self.a.gatt.values[demo_capture.H_DEVICE_NAME], b"Mi Smart Band 4"
        )
        self.assertEqual(self.a.gatt.values[demo_capture.H_BATTERY], b"\x5a")

    def test_subscriptions(self):
        self.assertIsNotNone(self.a.gatt.cccd_value(demo_capture.H_AUTH))
        self.assertIsNotNone(self.a.gatt.cccd_value(demo_capture.H_NOTIFY))

    def test_smp_recovered(self):
        names = [m.name for m in self.a.smp]
        self.assertIn("Pairing Request", names)
        self.assertIn("Encryption Information (LTK)", names)
        req = next(m for m in self.a.smp if m.name == "Pairing Request")
        self.assertIn("NoInputNoOutput", req.detail)

    def test_authenticated(self):
        self.assertTrue(self.a.auth.succeeded)
        self.assertEqual(self.a.auth.nonce, demo_capture.NONCE)

    def test_frames_decoded(self):
        cmds = {f.frame.cmd for f in self.a.frames if f.frame.cmd is not None}
        self.assertIn(0x02, cmds)   # set datetime
        self.assertIn(0x0A, cmds)   # chunked text

    def test_chunked_command_assembled(self):
        text = [f for f in self.a.frames if f.frame.cmd == 0x0A]
        self.assertEqual(len(text), 1, "16+2 byte chunks must merge into one frame")
        self.assertEqual(text[0].frame.payload, b"Hello from MiBand!")

    def test_directions_attributed(self):
        dirs = {f.direction for f in self.a.frames}
        self.assertEqual(dirs, {"app->band", "band->app"})

    def test_channels_attributed_to_uuids(self):
        ch = self.a.channels[demo_capture.H_CTRL]
        self.assertEqual(ch.uuid, uuids.normalize(0xFF05))
        self.assertGreater(ch.write_cmds, 0)
        n = self.a.channels[demo_capture.H_NOTIFY]
        self.assertGreater(n.notifies, 0)

    def test_unresolved_ids_surface_unknowns(self):
        unresolved = self.a.unresolved_ids()
        self.assertIn(("command", 0x13), unresolved)
        self.assertNotIn(("command", 0x01), unresolved)  # seeded
        self.assertNotIn(("response", 0x01), unresolved)  # seeded

    def test_json_export_is_serializable(self):
        import json
        blob = json.dumps(self.a.to_dict())
        back = json.loads(blob)
        self.assertEqual(back["peer_address"], "C2:4F:90:11:22:33")
        self.assertEqual(len(back["services"]), 6)
        self.assertTrue(back["authentication"]["authenticated"])
        self.assertGreater(len(back["frames"]), 5)

    def test_timeline_is_ordered(self):
        rels = [e.rel for e in self.a.events]
        self.assertEqual(rels, sorted(rels))


class TestCompare(unittest.TestCase):
    """`diff` is the RE loop, so it gets tested against real differing bytes."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        from remiband import compare

        cls.compare = compare
        d = tempfile.mkdtemp(prefix="remiband-diff-")
        cls.base = os.path.join(d, "base.btsnoop")
        cls.variant = os.path.join(d, "variant.btsnoop")
        demo_capture.write(cls.base)
        demo_capture.write(
            cls.variant,
            text=b"Alarm 07:30 set",
            extra=[(0x1A, b"\x01\x02\x03\x04")],
        )
        cls.cmp = compare.compare(
            analyze(cls.base), analyze(cls.variant)
        )

    def test_new_id_detected(self):
        self.assertIn(("command", 0x1A), self.cmp.only_b)
        self.assertNotIn(("command", 0x1A), self.cmp.only_a)

    def test_changed_payload_detected(self):
        self.assertIn(("command", 0x0A), self.cmp.changed)

    def test_unchanged_ids_reported_as_same(self):
        self.assertIn(("command", 0x02), self.cmp.same)

    def test_identical_captures_differ_not(self):
        cmp = self.compare.compare(analyze(self.base), analyze(self.base))
        self.assertFalse(cmp.has_differences)

    def test_first_difference_offset(self):
        off, left, right = self.compare._first_difference(b"Hello", b"HEllo")
        self.assertEqual((off, left, right), (1, 0x65, 0x45))

    def test_length_change_reported(self):
        off, left, right = self.compare._first_difference(b"ab", b"abc")
        self.assertEqual(off, 2)
        self.assertIsNone(left)
        self.assertIsNotNone(right)

    def test_render_mentions_the_new_id(self):
        text = self.compare.render_comparison(self.cmp)
        self.assertIn("0x1a", text.lower())
        self.assertIn("annotate", text)

    def test_json_export(self):
        import json
        blob = json.loads(json.dumps(self.cmp.to_dict()))
        ids = {item["id"] for item in blob["only_in_b"]}
        self.assertIn("0x1a", ids)


class TestFingerprint(unittest.TestCase):
    """The tool must be able to say "this is NOT the classic protocol".

    A decoder that silently finds zero frames on a newer band is worse than
    useless: it looks like a bug in the capture. This class pins down the
    difference between "classic device, nothing interesting happened" and
    "device speaks something else".
    """

    @classmethod
    def setUpClass(cls):
        import tempfile

        d = tempfile.mkdtemp(prefix="remiband-fp-")
        cls.classic_path = os.path.join(d, "classic.btsnoop")
        cls.zepp_path = os.path.join(d, "zepp.btsnoop")
        demo_capture.write(cls.classic_path)
        demo_capture.write(cls.zepp_path, style="zepp")
        cls.classic = analyze(cls.classic_path)
        cls.zepp = analyze(cls.zepp_path)

    def test_classic_device_identified(self):
        fp = fpm.fingerprint(self.classic)
        self.assertEqual(fp.verdict, "classic-a0")
        self.assertGreaterEqual(fp.score_of("classic-a0"), 0.9)

    def test_newer_device_rejected_as_classic(self):
        fp = fpm.fingerprint(self.zepp)
        self.assertEqual(fp.score_of("classic-a0"), 0.0)
        self.assertNotEqual(fp.verdict, "classic-a0")

    def test_newer_device_identified_as_chunked(self):
        fp = fpm.fingerprint(self.zepp)
        self.assertEqual(fp.verdict, "chunked")
        evidence = next(h.evidence for h in fp.hypotheses if h.name == "chunked")
        self.assertIn("exactly 20 bytes", evidence)
        self.assertIn("byte 0 increments", evidence)
        self.assertIn("NOT the classic", fp.advice)

    def test_newer_capture_decodes_zero_classic_frames(self):
        self.assertEqual(self.zepp.frames, [])
        self.assertGreater(len(self.classic.frames), 0)

    def test_analysis_does_not_crash_on_unknown_protocol(self):
        # no auth, no frames, no 128-bit discovery of fee1 -- must still report
        self.assertIsNotNone(self.zepp.peer_addr)
        self.assertEqual(len(self.zepp.gatt.chars), 2)
        self.assertEqual(self.zepp.auth.steps, [])

    def test_protocol_in_json_export(self):
        import json
        blob = json.loads(json.dumps(self.zepp.to_dict()))
        self.assertEqual(blob["protocol"]["verdict"], "chunked")
        self.assertTrue(blob["protocol"]["hypotheses"])

    def test_entropy_helpers(self):
        self.assertEqual(fpm.entropy(b"\x00" * 100), 0.0)
        self.assertAlmostEqual(fpm.entropy(bytes(range(256))), 8.0, places=5)
        self.assertEqual(fpm.printable_ratio(b"abc"), 1.0)
        self.assertEqual(fpm.printable_ratio(b"\x00\x01"), 0.0)
        self.assertGreater(fpm.distinct_ratio(bytes(range(100))), 0.9)

    def test_sms_text_is_not_mistaken_for_a_transport(self):
        # A short all-text write must not outscore a real framing verdict.
        fp = fpm.fingerprint(self.classic)
        self.assertLess(fp.score_of("textual"), fp.score_of("classic-a0"))

    def test_survey_renders_on_undecodable_capture(self):
        from remiband.render import render_survey
        text = render_survey(self.zepp)
        self.assertIn("TRAFFIC BY HANDLE", text)
        self.assertIn("0x0013", text)
        self.assertIn("chunked", text)
        self.assertIn("Next steps", text)


if __name__ == "__main__":
    unittest.main()
