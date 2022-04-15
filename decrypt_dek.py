import logging
from binascii import hexlify, unhexlify
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def hex(b):
    return hexlify(b).upper()

def derive_encryption_key(salt: bytes, password: bytes, hash_iterations=10000000):
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

def decrypt_DEK(share:bytes, password: bytes):

    assert len(share) == 64

    share_prefix = share[0:8]
    assert share_prefix.decode('ASCII') == 'Salted__'

    salt = share[8:16]
    logging.info(f'salt: {hex(salt)}')

    ciphertext = share[16:]
    logging.info(f'ciphertext: (L {len(ciphertext)}) {hex(ciphertext)}')

    key_iv = derive_encryption_key(salt, password)

    logging.info(f'key_iv [l={len(key_iv)}]: {hexlify(key_iv)}')

    key = key_iv[0:32]
    iv = key_iv[32:]
    
    logging.info(f'key: {hex(key)}')
    logging.info(f'iv: {hex(iv)}')

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(ciphertext)
    decryptor.finalize()
    
    expected_padding = unhexlify('10101010101010101010101010101010')
    assert plain_text.endswith(expected_padding)

    dkek = plain_text[:32]
    logging.info(f'recovered DKEK: {hex(dkek)}')

    dkek_key_cipher = Cipher(algorithms.AES(dkek), modes.CBC(bytes([0x00]*16)))
    dkek_encryptor = dkek_key_cipher.encryptor()
    recovered_kcv = dkek_encryptor.update(bytes([0x00] * 16))
    dkek_encryptor.finalize()
    logging.info(f'KCV for recovered key: {hex(recovered_kcv[0:3])}')


def load_local_share_file(path: str):
    logging.info(f'loading DKEK file share @ {path}')
    binary_data = None
    with open(path, mode='rb') as file:
        binary_data = file.read()
    return binary_data

logging.basicConfig()
logging.root.setLevel(logging.INFO)

password = 'passwordpassword'.encode('ascii')
share = load_local_share_file('single-component-test-share.pbe.test')
dek = decrypt_DEK(share, password)