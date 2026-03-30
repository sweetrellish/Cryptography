import unittest

from cryptography.exceptions import InvalidTag

from aes_core import aes_decrypt
from aes_core import aes_encrypt
from aes_core import mode_pattern_report
from aes_core import random_iv
from aes_core import random_key


class AESCoreTests(unittest.TestCase):
    def test_cbc_round_trip(self):
        key = random_key(256)
        iv = random_iv("CBC")
        message = "MATH 447 AES CBC round trip"

        packet = aes_encrypt(message, key, iv, "CBC", b"")
        decrypted = aes_decrypt(packet, key)

        self.assertEqual(decrypted, message)
        self.assertEqual(packet["mode"], "CBC")
        self.assertIsNone(packet["tag"])

    def test_gcm_round_trip_with_aad(self):
        key = random_key(256)
        iv = random_iv("GCM")
        message = "MATH 447 AES GCM round trip"
        aad = b"section-1-demo"

        packet = aes_encrypt(message, key, iv, "GCM", aad)
        decrypted = aes_decrypt(packet, key)

        self.assertEqual(decrypted, message)
        self.assertEqual(packet["mode"], "GCM")
        self.assertIsNotNone(packet["tag"])

    def test_gcm_tag_verification_fails_when_modified(self):
        key = random_key(256)
        iv = random_iv("GCM")
        packet = aes_encrypt("tamper check", key, iv, "GCM", b"")

        packet["ciphertext"] = packet["ciphertext"][:-4] + "AAAA"

        with self.assertRaises(InvalidTag):
            aes_decrypt(packet, key)

    def test_mode_pattern_report_shows_ecb_repetition(self):
        key = bytes.fromhex("00" * 32)
        cbc_iv = bytes.fromhex("11" * 16)
        gcm_iv = bytes.fromhex("22" * 12)
        sample = "A" * 64

        report = mode_pattern_report(sample, key, cbc_iv, gcm_iv)

        self.assertGreater(report["ecb"]["repeated_blocks"], 0)
        self.assertEqual(report["cbc"]["repeated_blocks"], 0)


if __name__ == "__main__":
    unittest.main()
