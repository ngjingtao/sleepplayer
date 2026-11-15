"""AES-128 correctness tests against FIPS-197 and NIST SP 800-38A vectors."""

import unittest

from remiband.aes import SBOX, encrypt_block, encrypt_ecb, expand_key


class TestSbox(unittest.TestCase):
    def test_known_entries(self):
        # First row of the AES S-box.
        self.assertEqual(SBOX[0x00], 0x63)
        self.assertEqual(SBOX[0x01], 0x7C)
        self.assertEqual(SBOX[0x02], 0x77)
        self.assertEqual(SBOX[0x03], 0x7B)
        self.assertEqual(SBOX[0x0F], 0x76)
        self.assertEqual(SBOX[0x10], 0xCA)
        self.assertEqual(SBOX[0x53], 0xED)
        self.assertEqual(SBOX[0xFF], 0x16)

    def test_bijective(self):
        self.assertEqual(len(set(SBOX)), 256)


class TestKeySchedule(unittest.TestCase):
    def test_fips197_key_expansion(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        rk = expand_key(key)
        self.assertEqual(len(rk), 11)
        self.assertEqual(bytes(rk[0]), key)
        # FIPS-197 Appendix A.1: round key 1 is
        #   d6aa74fd d2af72fa daa678f1 d6ab76fe
        self.assertEqual(bytes(rk[1][0:4]).hex(), "d6aa74fd")
        self.assertEqual(bytes(rk[1][4:8]).hex(), "d2af72fa")
        self.assertEqual(bytes(rk[1][8:12]).hex(), "daa678f1")
        self.assertEqual(bytes(rk[1][12:16]).hex(), "d6ab76fe")
        # Round key 10 starts 13111d7f and ends 4d2b30c5.
        self.assertEqual(bytes(rk[10][0:4]).hex(), "13111d7f")
        self.assertEqual(bytes(rk[10][12:16]).hex(), "4d2b30c5")


class TestEncrypt(unittest.TestCase):
    def test_fips197_appendix_c1(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(encrypt_block(key, pt), ct)

    def test_fips197_appendix_c3(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(encrypt_block(key, pt), ct)

    def test_nist_sp800_38a_ecb(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
        )
        ct = bytes.fromhex(
            "3ad77bb40d7a3660a89ecaf32466ef97"
            "f5d3d58503b9699de785895a96fdbaaf"
        )
        self.assertEqual(encrypt_ecb(key, pt), ct)

    def test_rejects_bad_lengths(self):
        with self.assertRaises(ValueError):
            encrypt_block(b"\x00" * 15, b"\x00" * 16)
        with self.assertRaises(ValueError):
            encrypt_block(b"\x00" * 16, b"\x00" * 15)
        with self.assertRaises(ValueError):
            encrypt_ecb(b"\x00" * 16, b"\x00" * 17)


if __name__ == "__main__":
    unittest.main()
