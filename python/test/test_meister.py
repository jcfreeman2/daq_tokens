
import unittest

from daq_tokens import acquire, verify
from jwt import InvalidAudienceError

class DaemonTest(unittest.TestCase):

    def setUp(self):
        self.token = acquire()

    def test_user_acquire(self):
        pass

    def test_user_verify_correct(self):
        decoded = verify(self.token)
        self.assertEqual(decoded['aud'], 'atlas-tdaq-token')
        self.assertEqual(decoded['iss'], 'https://auth.cern.ch/auth/realms/cern')

    def test_user_verify_twice(self):
        decoded1 = verify(self.token)
        decoded2 = verify(self.token)
        self.assertEqual(decoded1['aud'], 'atlas-tdaq-token')
        self.assertEqual(decoded1['iss'], 'https://auth.cern.ch/auth/realms/cern')

        # destroy environment and rely on key store
        import os
        old_key = os.environ.get('TDAQ_TOKEN_PUBLIC_KEY')
        if old_key:
            del os.environ['TDAQ_TOKEN_PUBLIC_KEY']
        old_url = os.environ.get('TDAQ_TOKEN_PUBLIC_KEY_URL')
        if old_url:
            del os.environ['TDAQ_TOKEN_PUBLIC_KEY_URL']

        self.assertEqual(decoded2['aud'], 'atlas-tdaq-token')
        self.assertEqual(decoded2['iss'], 'https://auth.cern.ch/auth/realms/cern')

        if old_key:
            os.environ['TDAQ_TOKEN_PUBLIC_KEY'] = old_key
        if old_url:
            os.environ['TDAQ_TOKEN_PUBLIC_KEY_URL'] = old_url

if __name__ == '__main__':
    unittest.main()
