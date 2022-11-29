import os
from time import time
import urllib.request
import jwt

from .keystore import keystore

store = keystore()

recent = {}

def prune_recent():
    global recent
    entries = list(recent.items())
    entries.sort(key = lambda x: x[1][0])
    now = time()
    for entry in entries:
        if entry[1][0] < now:
            del recent[entry[0]]
    
def verify(encoded_token, /, allow_cache = False):
    """
    Verify an encoded JWToken using the TDAQ public key.

       encoded_token - a string containing the token.

    If we find a key with the same 'kid' in the store,
    use it. Else:

    If TDAQ_TOKEN_PUBLIC_KEY is set, it is taken as
    the actual public key and added to the key store.

    The location of the key is specified in a URL from
    in the TDAQ_TOKEN_PUBLIC_KEY_URL environment variable.
    It is downloaded and stored in the key store.
    """
    global  store, recent

    if allow_cache:
        if encoded_token in recent:
            exp, token = recent[encoded_token]
            if exp > int(time()):
                return token
            else:
                del recent[encoded_token]

    # The header *must* have a 'kid' attribute.
    headers = jwt.get_unverified_header(encoded_token)

    # See if it's already in store
    public_key     = store.get(headers['kid'])

    if not public_key:
        
        if 'TDAQ_TOKEN_PUBLIC_KEY' in os.environ:
            public_key = os.environ['TDAQ_TOKEN_PUBLIC_KEY']
            store.add(public_key)

        for url in os.environ.get('TDAQ_TOKEN_PUBLIC_KEY_URL', 'https://auth.cern.ch/auth/realms/cern/protocol/openid-connect/certs').split('|'):
            try:
                jwks = jwt.PyJWKClient(url)
                key  = jwks.get_signing_key_from_jwt(encoded_token)
                public_key = key.key
                store.add(key.key, key.key_id)
            except Exception as ex:
                try:
                    with urllib.request.urlopen(url) as f:
                        public_key = f.read()
                        store.add(public_key)
                except:
                    pass

        public_key = store.get(headers['kid'])

    token = jwt.PyJWT()
    decoded = token.decode(encoded_token, public_key, algorithms=['RS256'], audience='atlas-tdaq-token', issuer=os.environ.get('TDAQ_TOKEN_ISSUER', 'https://auth.cern.ch/auth/realms/cern'))
    recent[encoded_token] = (decoded['exp'], decoded)
    if len(recent) > 1000:
        prune_recent()
    return decoded
