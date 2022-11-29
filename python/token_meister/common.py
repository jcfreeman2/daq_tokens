"""
Common helper routines for token_meister
"""

import sys
import os

life_time = 1200

private_key             = None
private_key_fingerprint = None
private_key_last_update = None

def make_token(user):
    """
    Create the actual JWToken, using the given
    private key, the user name and the claims.
    """

    global private_key, private_key_fingerprint, lifetime

    from datetime import datetime, timedelta
    from calendar import timegm
    from uuid import uuid4
    from jwt import PyJWT

    now = datetime.utcnow()

    claims = {
        'sub': user,
        'aud': 'atlas-tdaq-token',
        'jti': str(uuid4()),
        'iat': now,
        'nbf': now,
        'exp': timegm((now + timedelta(seconds=life_time)).utctimetuple()),
        'iss':os.environ.get('TDAQ_TOKEN_ISSUER', 'https://auth.cern.ch/auth/realms/cern')
        }

    header = {
        'kid': private_key_fingerprint
    }

    token = PyJWT()
    return token.encode(headers=header, payload=claims, key=private_key, algorithm='RS256')

def get_private_key(private_key_path):
    """
    Get the latest private key.
    Will read it first time if not done yet, then again
    if the file on disk has been modified.
    """

    global private_key, private_key_fingerprint, private_key_last_update

    import sys
    from time    import time
    from os.path import getmtime

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    # if not private_key or not private_key_last_update or getmtime(private_key_path) > private_key_last_update:
    if not private_key:

        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        private_key_last_update = time()

        h = hashes.Hash(hashes.SHA256(),backend=default_backend())
        h.update(private_key.public_key().public_bytes(encoding = serialization.Encoding.DER,
                                                       format = serialization.PublicFormat.SubjectPublicKeyInfo))
        private_key_fingerprint = h.finalize().hex()

    return private_key

