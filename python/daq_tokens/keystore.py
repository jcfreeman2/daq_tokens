"""
A simple key store.
"""

class keystore:

    def __init__(self):
        self.keys = {}

    def add(self, key, fingerprint=None):
        
        if not fingerprint:

            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives import hashes

            pkey = serialization.load_pem_public_key(key)
            h    = hashes.Hash(hashes.MD5())
            h.update(pkey.public_bytes(encoding = serialization.Encoding.DER,
                                       format   = serialization.PublicFormat.SubjectPublicKeyInfo))
            fingerprint = h.finalize().hex()
            self.keys[fingerprint] = key

            h   = hashes.Hash(hashes.SHA256())
            h.update(pkey.public_bytes(encoding = serialization.Encoding.DER,
                                       format   = serialization.PublicFormat.SubjectPublicKeyInfo))
            fingerprint = h.finalize().hex()
            self.keys[fingerprint] = key

        else:
            self.keys[fingerprint] = key

    def get(self, fingerprint):
        return self.keys.get(fingerprint)

