import unittest

from aes_core_process import aes_cbc_decrypt_process
from aes_core_process import aes_cbc_encrypt_process
from aes_core_process import decrypt_block
from aes_core_process import encrypt_block
from aes_core_process import encrypt_block_with_trace


class AESProcessTests(unittest.TestCase):
    def test_aes128_known_vector_encrypt_decrypt(self):
        # FIPS-197 Appendix C.1 AES-128 test vector
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected_ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        ciphertext = encrypt_block(plaintext, key)
        decrypted = decrypt_block(ciphertext, key)

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_cbc_process_round_trip(self):
        key = bytes.fromhex("00112233445566778899aabbccddeeff")
        iv = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
        message = "Rijndael process-focused CBC demo for cryptography class"

        packet = aes_cbc_encrypt_process(message, key, iv, include_trace=False)
        result = aes_cbc_decrypt_process(packet, key, include_trace=False)

        self.assertEqual(packet["mode"], "CBC")
        self.assertEqual(packet["algorithm"], "AES-128 (Rijndael)")
        self.assertEqual(result["plaintext"], message)

    def test_trace_contains_round_steps(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

        result = encrypt_block_with_trace(plaintext, key)

        self.assertIn("ciphertext_hex", result)
        self.assertIn("trace", result)
        self.assertGreater(len(result["trace"]), 0)
        self.assertEqual(result["trace"][0]["step"], "initial_state")


if __name__ == "__main__":
    unittest.main()
