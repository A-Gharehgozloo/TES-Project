import unittest
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.crypto_utils import RSAManager, DESManager

class TestCrypto(unittest.TestCase):
    def test_rsa(self):
        priv, pub = RSAManager.generate_keys(1024)
        alice = RSAManager(private_key_data=priv, public_key_data=pub)
        bob = RSAManager(public_key_data=pub)

        msg = b"Hello World"
        encrypted = bob.encrypt(msg)
        decrypted = alice.decrypt(encrypted)
        self.assertEqual(msg, decrypted)

        sig = alice.sign(msg)
        self.assertTrue(bob.verify(msg, sig))
        self.assertFalse(bob.verify(b"Hello World!", sig))

    def test_des(self):
        key = DESManager.generate_key()
        des = DESManager(key)
        
        msg = b"Secret Data"
        encrypted = des.encrypt(msg)
        self.assertNotEqual(msg, encrypted)
        
        decrypted = des.decrypt(encrypted)
        self.assertEqual(msg, decrypted)

if __name__ == '__main__':
    unittest.main()
