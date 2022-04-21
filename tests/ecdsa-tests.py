from binascii import hexlify, unhexlify
import unittest

from ecdsa import VerifyingKey, SigningKey

pem = '''-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIHIfsWDjrgEibDinnnBRkRm0BoSfE/r4eOeHpr4RHA0PoAcGBSuBBAAKoUQDQgAENN5giV/nlJVDOIwBqmi5yCXcmiw0+lQqGiMEqUCBmKIU81X250Ur4P0DWdMKdcAjuUoDAng+Rj2i6cCxF5vOtQ==
-----END EC PRIVATE KEY-----'''

msg = unhexlify('f55247e1a922d4596602a083579ea1d03838e59c3f126722e0bee279c823735c1a03a3af675a22995085740b71182c6df268db6dc5e93271f381818d824b136f5810c74a18514d14f445b4bfc415acd5c65f7f7e071f0fcb56ceb3aececd5186ef2dfc00594837e4c895ad398867af7e26b05df3c147ca1b396ab92b74dc9dc8d9b7be9d030d502af30313190c61cfb750e4c8e6c2af685422f65d2295b6b404292ea42bcb8d0e95a78a01ea74851c7a67491f20ffa5c080209d54f96028e801ff112cc75a05d740')
sig = unhexlify('c4e310b9114b2916a8b57f5f71fd27153556a5551bc1336f068a31985e6aa39dc1163add9812772c6334dd177239bf9adb60d5467e8b3e5a614db737b1f5dc3e')

class TestECDSA(unittest.TestCase):
    
    def test_verify_ecdsa(self):
        
        signing_key = SigningKey.from_pem(pem)
        assert signing_key.verifying_key.verify(sig, msg)

if __name__ == '__main__':
    unittest.main()