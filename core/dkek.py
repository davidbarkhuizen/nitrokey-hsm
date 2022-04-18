import logging
from binascii import hexlify, unhexlify
import hashlib
from os import urandom

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import cmac

encrypted_dkek_share_header = 'Salted__'.encode('ascii')
dkek_share_padding = unhexlify('10101010101010101010101010101010')

kek_padding = unhexlify("00000001")
mak_padding = unhexlify("00000002")

def blank_dkek():
    return bytes([0x00]*32)

def mix_key_share_into_dkek(dkek, share):    
    return bytes(a ^ b for a, b in zip(dkek, share))

def dkek_kcv(dkek):
    kcv_msg = hashlib.sha256()
    kcv_msg.update(dkek)
    return kcv_msg.digest()[:8]

def hex(b):
    return hexlify(b).upper()

def load_binary_file(path: str):
    binary_data = None
    with open(path, mode='rb') as file:
        binary_data = file.read()
    return binary_data

def decrypt_aes_cbc(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(ciphertext)
    decryptor.finalize()
    return plain_text

def encrypt_aes_cbc(key, iv, plain_text):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_text)
    encryptor.finalize()
    return cipher_text

def derive_DKEK_share_encryption_key(salt: bytes, password: bytes, hash_iterations=10000000):
    '''return 32 byte derived key concatenated with 16 byte IV'''
    
    d = bytes(0)
    
    key_iv = bytes([]) # bytes([0x00]*48) # 48 = 32 + 16

    for j in range(3):

        logging.info(f'deriving DKEK share encryption key (step {j+1} of 3)...')
        
        nd = d + password
        d = nd

        nd = d + salt
        d = nd

        to_hash = d
        hashed = None
        for i in range(hash_iterations):
            m = hashlib.md5()
            m.update(to_hash)
            hashed = m.digest()
            to_hash = hashed

        key_iv = key_iv + hashed

        d = hashed
    
    return key_iv

def decrypt_DKEK_share_blob(
        blob: bytes, 
        password: bytes
    ):

    assert len(blob) == 64

    share_prefix = blob[0:8]
    assert share_prefix == encrypted_dkek_share_header

    salt = blob[8:16]
    ciphertext = blob[16:]
    
    key_iv = derive_DKEK_share_encryption_key(salt, password)
    key = key_iv[0:32]
    iv = key_iv[32:]

    plain_text = decrypt_aes_cbc(key, iv, ciphertext)
    assert plain_text.endswith(dkek_share_padding)

    share = plain_text[:32]
    return share

def derive_kek_from_dkek(dkek):
    m = hashlib.sha256()
    m.update(dkek + kek_padding)
    return m.digest()

# 	var kencval = this.crypto.digest(Crypto.SHA_256, this.dkek.concat(new ByteString(, HEX)));
# 	var kenc = new Key();
# 	kenc.setComponent(Key.AES, kencval);
# 	return kenc;
# }

def derive_mak_from_dkek(dkek):
    m = hashlib.sha256()
    m.update(dkek + mak_padding)
    return m.digest()

# c.update(b"message to authenticate")
# c.finalize()

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

def dkek_from_shares(shares: list):
   
    dkek = blank_dkek()
    
    for share in shares:    
        dkek = mix_key_share_into_dkek(dkek, share)
    
    return dkek

# kek = derive_kek_from_dkek(dkek)
# kek_iv = bytes([0x00]*16)
# kek_cipher = Cipher(algorithms.AES(kek), modes.CBC(kek_iv))
# kek_encryptor = kek_cipher.encryptor()

# mak = derive_mak_from_dkek(dkek)
# mak_cipher = cmac.CMAC(algorithms.AES(mak))
# mak_cipher.update(b"message to authenticate")
# mak_cipher.finalize()

def encrypt_dkek_share(share: bytes, password: bytes):
	
    assert len(share) == 32

    salt = urandom(8)

    key_iv = derive_DKEK_share_encryption_key(salt, password)
    key = key_iv[0:32]
    iv = key_iv[32:]

    plain_text = share + dkek_share_padding
    cipher_text = encrypt_aes_cbc(key, iv, plain_text)

    blob = encrypted_dkek_share_header + salt + cipher_text
    return blob
    