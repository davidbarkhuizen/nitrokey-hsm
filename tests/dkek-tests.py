from binascii import unhexlify, hexlify
import unittest

from core.dkek import decrypt_DKEK_share_blob, dkek_from_shares, dkek_kcv, encrypt_dkek_share_blob

dkek_share_enc_password = 'passwordpassword'.encode('ascii')
encrypted_dkek_share = unhexlify('53616c7465645f5f3b2b00cce8b70b2b7f0d0b632c92f3cbdd2e91f3f4f1f65593c2afd11409a9990b89aec513664b5c36e57ce8af10746eed02442be23209b9')

dkek_share_enc_salt = unhexlify('3B2B00CCE8B70B2B')
decrypted_dkek_share = unhexlify('2848cb6e994f5a00c365c3c255ed130512ce1eb06bf08d348eeb8b2f866e3e50')

ref_dkek_kcv = unhexlify('97E303855DC1C54D')
ref_dkek = unhexlify('2848cb6e994f5a00c365c3c255ed130512ce1eb06bf08d348eeb8b2f866e3e50')

class TestDKEK(unittest.TestCase):
    
    def test_decryption_of_dkek_share(self):

        dkek_share = decrypt_DKEK_share_blob(encrypted_dkek_share, dkek_share_enc_password)
        print(f'dkek share {hexlify(dkek_share)}')
        dkek = dkek_from_shares([dkek_share])        
        print(f'dkek {hexlify(dkek)}')
        calced_kcv = dkek_kcv(dkek)
        print(f'kcv {hexlify(calced_kcv)}')
        self.assertEqual(calced_kcv, ref_dkek_kcv)

    def test_encryption_of_dkek_share(self):

        blob = encrypt_dkek_share_blob(decrypted_dkek_share, dkek_share_enc_password, dkek_share_enc_salt)
        self.assertEqual(blob, encrypted_dkek_share)

if __name__ == '__main__':
    unittest.main()