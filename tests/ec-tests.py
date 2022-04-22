from binascii import unhexlify
import unittest

from core.ec import ec_sign_ecdsa_sha1, ec_verify_ecdsa_sha1

pem = '''-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIHIfsWDjrgEibDinnnBRkRm0BoSfE/r4eOeHpr4RHA0PoAcGBSuBBAAKoUQDQgAENN5giV/nlJVDOIwBqmi5yCXcmiw0+lQqGiMEqUCBmKIU81X250Ur4P0DWdMKdcAjuUoDAng+Rj2i6cCxF5vOtQ==
-----END EC PRIVATE KEY-----'''.encode('ascii')

msg = unhexlify('70656163652062652075706f6e20746865207269676874656f757320616e642074686520696e6e6f63656e74')

sig = unhexlify('aaa1468483153362c688de3de0dc5b66c6a8fc952cc931bf223bbc725deef9e1ac692c1e571ba6f508118bf5429d5d8662307ad82077de79789ac1e96e7f9d0a')

class TestKeyWrapping(unittest.TestCase):
    
    def test_ec_sign_ecdsa_sha1(self):
        signature = ec_sign_ecdsa_sha1(pem, msg)
        ec_verify_ecdsa_sha1(pem, msg, signature)
        self.assertEqual(True, True)

if __name__ == '__main__':
    unittest.main()