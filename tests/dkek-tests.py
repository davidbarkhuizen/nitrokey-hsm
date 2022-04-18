from binascii import unhexlify
import logging

logging.basicConfig()
logging.root.setLevel(logging.INFO)

import unittest
from base64 import b64decode

from core.dkek import decrypt_DKEK_share_blob, dkek_from_shares, dkek_kcv, encrypt_dkek_share

dkek_share_enc_password = 'passwordpassword'.encode('ascii')

enc_dkek_share_b64  = 'U2FsdGVkX19svhSIBSqUH/GixQX4+9KdFKpErNW7MLzNCX9YBE7+eseQB6Vh7JgaFmhlWzIcqCgB39n9xXe6BA=='
enc_dkek_share = b64decode(enc_dkek_share_b64.encode('ascii'))

ref_dkek_kcv = unhexlify('2AFA121E8764A1E3')
ref_dkek = unhexlify('c955af6fb058ca963d270049de57b75b175d528b8993d7651dcc4650097caffb')

class TestDKEK(unittest.TestCase):
    
    def test_decryption_of_dkek_share(self):

        dkek_share = decrypt_DKEK_share_blob(enc_dkek_share, dkek_share_enc_password)
        dkek = dkek_from_shares([dkek_share])        
        calced_kcv = dkek_kcv(dkek)
        self.assertEqual(calced_kcv, ref_dkek_kcv)

    # def test_encryption_of_dkek_share(self):

    #     dkek = encrypt_dkek_share()
    #     self.assertEqual(calced_kcv, ref_dkek_kcv)

if __name__ == '__main__':
    unittest.main()