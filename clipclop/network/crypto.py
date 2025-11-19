import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoManager:
    def __init__(self, key_b64: str):
        try:
            self.key = base64.urlsafe_b64decode(key_b64)
            self.aesgcm = AESGCM(self.key)
        except Exception as e:
            print(f"[CRYPTO] Error initializing crypto: {e}")
            raise

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts plaintext using AES-GCM.
        Returns: nonce + ciphertext (including tag)
        """
        try:
            nonce = os.urandom(12)
            ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
            return nonce + ciphertext
        except Exception as e:
            print(f"[CRYPTO] Encryption error: {e}")
            return b""

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypts data (nonce + ciphertext).
        Returns: plaintext bytes or None if failed.
        """
        try:
            if len(data) < 12:
                return None
            nonce = data[:12]
            ciphertext = data[12:]
            return self.aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            print(f"[CRYPTO] Decryption error: {e}")
            return None

