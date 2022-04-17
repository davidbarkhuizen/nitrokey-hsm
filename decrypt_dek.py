import logging
from binascii import hexlify, unhexlify
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import cmac

dkek_share_file_header = 'Salted__'.encode('ascii')
dkek_share_padding = unhexlify('10101010101010101010101010101010')

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

def decrypt_DKEK_share_file(share_file: bytes, password: bytes):

    assert len(share_file) == 64

    share_prefix = share_file[0:8]
    assert share_prefix == dkek_share_file_header

    salt = share_file[8:16]
    logging.info(f'salt (L={len(salt)}): {hex(salt)}')

    ciphertext = share_file[16:]
    logging.info(f'ciphertext (L={len(ciphertext)}): {hex(ciphertext)}')

    key_iv = derive_DKEK_share_encryption_key(salt, password)

    logging.info(f'key_iv [L={len(key_iv)}]: {hexlify(key_iv)}')

    key = key_iv[0:32]
    iv = key_iv[32:]
    
    logging.info(f'key [L={len(key)}]: {hex(key)}')
    logging.info(f'iv: [L={len(iv)}]: {hex(iv)}')

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(ciphertext)
    decryptor.finalize()
    
    assert plain_text.endswith(dkek_share_padding)

    share = plain_text[:32]
    return share

# 	var kencval = this.crypto.digest(Crypto.SHA_256, this.dkek.concat(new ByteString(, HEX)));
# 	var kenc = new Key();
# 	kenc.setComponent(Key.AES, kencval);
# 	return kenc;
# }

def derive_kek_from_dkek(dkek):
    m = hashlib.sha256()
    m.update(dkek + unhexlify("00000001"))
    key_value = m.digest()
    cipher = Cipher(algorithms.AES(key_value), modes.CBC(bytes([0x00]*16)))
    return cipher.encryptor()

# recovered_kcv = dkek_encryptor.update(bytes([0x00] * 16)) 
# dkek_encryptor.finalize()

def derive_mak_from_dkek(dkek):
    m = hashlib.sha256()
    m.update(dkek + unhexlify("00000002"))
    mak_value = m.digest()
    cipher = cmac.CMAC(algorithms.AES(mak_value))
    return cipher
# c.update(b"message to authenticate")
# c.finalize()







# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

logging.basicConfig()
logging.root.setLevel(logging.INFO)

password = 'passwordpassword'.encode('ascii')
pbe_file_path = 'dkek-test.pbe'

logging.info(f'loading DKEK file share @ {pbe_file_path}')
dkek_share_file = load_binary_file(pbe_file_path)

dkek_share = decrypt_DKEK_share_file(dkek_share_file, password) 
logging.info(f'recovered dkek share: {hex(dkek_share)}')

dkek = mix_key_share_into_dkek(blank_dkek(), dkek_share)
logging.info(f'recovered dkek: {hex(dkek)}')

kcv = dkek_kcv(dkek)
logging.info(f'DKEK KCV: {hex(kcv)}')

kek = kek_from_dkek(dkek)

# from cryptography.hazmat.primitives import cmac
# from cryptography.hazmat.primitives.ciphers import algorithms
# c = cmac.CMAC(algorithms.AES(key))
# c.update(b"message to authenticate")
# c.finalize()

# aes_key = dkek
# dkek_key_cipher = Cipher(algorithms.AES(aes_key), modes.CBC(bytes([0x00]*16)))
# dkek_encryptor = dkek_key_cipher.encryptor()
# recovered_kcv = dkek_encryptor.update(bytes([0x00] * 16)) 
# dkek_encryptor.finalize()
# logging.info(f'KCV for recovered key: {hex(recovered_kcv)}')