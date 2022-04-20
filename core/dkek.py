import logging
from binascii import hexlify, unhexlify
import hashlib
from os import urandom
from enum import Enum
import struct
import asn1

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import cmac

encrypted_dkek_share_header = 'Salted__'.encode('ascii')
dkek_share_padding = unhexlify('10101010101010101010101010101010')

kek_padding = unhexlify("00000001")
mak_padding = unhexlify("00000002")

class KeyType(Enum):
    RSA = 5
    RSA_CRT = 6
    ECC = 12
    AES = 15

def blank_dkek():
    return bytes([0x00]*32)

def mix_key_share_into_dkek(dkek, share):    
    return bytes(a ^ b for a, b in zip(dkek, share))

def calc_dkek_kcv(dkek):
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
    print(f'salt {hex(salt)}')

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

def derive_mak_from_dkek(dkek):
    m = hashlib.sha256()
    m.update(dkek + mak_padding)
    return m.digest()

def calc_cmac(mak: bytes, msg: bytes):
    cipher = cmac.CMAC(algorithms.AES(mak))
    cipher.update(msg)
    return cipher.finalize()

def verify_cmac(mak: bytes, msg: bytes, mac: bytes):
    c = cmac.CMAC(algorithms.AES(mak))
    c.update(msg)
    c.verify(mac)

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

def dkek_from_shares(shares: list):
   
    dkek = blank_dkek()
    
    for share in shares:    
        dkek = mix_key_share_into_dkek(dkek, share)
    
    return dkek

def encrypt_dkek_share_blob(share: bytes, password: bytes, salt: bytes = None):
	
    assert len(share) == 32

    if salt == None:
        salt = urandom(8)

    key_iv = derive_DKEK_share_encryption_key(salt, password)
    key = key_iv[0:32]
    iv = key_iv[32:]

    plain_text = share + dkek_share_padding
    cipher_text = encrypt_aes_cbc(key, iv, plain_text)

    blob = encrypted_dkek_share_header + salt + cipher_text
    return blob

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

def decrypt_dkek_wrapped_ec_key(dkek: bytes, blob: bytes):

    def report_on(label:str, target):
        
        try: 
            target_str = hexlify(target)
        except:
            target_str = str(target)
        
        print(f'{label: <20} ({len(target):>3}) {target_str}')

    decoder = asn1.Decoder()
    decoder.start(blob)
    tag, value = decoder.read()
    x_decoder = asn1.Decoder()
    x_decoder.start(value)
    tag, value = x_decoder.read()

    blob = value

    def generate_unpacker(source: bytes):

        def get_obj_from_blob(offset: int):
            [l] = struct.unpack('>H', source[offset:offset+2])
            obj = source[offset+2:offset+2+l]
            return (obj, l, offset+2+l)

        return get_obj_from_blob


    dkek_kcv = blob[:8]
    report_on('DKEK KCV', dkek_kcv)

    raw_key_type = blob[8]   
    key_type = KeyType(raw_key_type)
    report_on('key_type', f'{key_type.name} ({raw_key_type})')
    
    get_blob_obj_at = generate_unpacker(blob)

    offset = 9
    [oid, obj_len,offset] = get_blob_obj_at(offset)
    report_on('oid', oid)

    # id-TA-ECDSA-SHA-256 0.4.0.127.0.7.2.2.2.2.3

    # 0000 allowed algos
    # 0000 access conditions
    # 0000 key OID

    [allowed_algos, size, offset] = get_blob_obj_at(offset)
    report_on('allowed_algos', allowed_algos)

    [access_conditions, size, offset] = get_blob_obj_at(offset)
    report_on('access_conditions', access_conditions)

    [key_oid, size, offset] = get_blob_obj_at(offset)
    report_on('key_oid', key_oid)

    encrypted_blob = blob[offset:-16] # TODO check what is in the last 16 bytes !!!

    kek = derive_kek_from_dkek(dkek)
    iv = bytes([0x00]*16)
    decrypted_blob = decrypt_aes_cbc(kek, iv, encrypted_blob)

    random_prefix = decrypted_blob[:8]
    report_on('random_prefix', random_prefix)

    get_key_obj_at = generate_unpacker(decrypted_blob)

    [key_size] = struct.unpack('>H', decrypted_blob[8:10])
    print(f'key size, bits: {key_size}')

    offset = 10
    
    [a, size, offset] = get_key_obj_at(offset)
    report_on('a', a)

    [b, size, offset] = get_key_obj_at(offset)
    report_on('b', b)

    [prime_factor, size, offset] = get_key_obj_at(offset)
    report_on('prime_factor', prime_factor)

    [order, size, offset] = get_key_obj_at(offset)
    report_on('order', order)

    [generator_g, size, offset] = get_key_obj_at(offset)
    report_on('generator_g', generator_g)

    [secret_d, size, offset] = get_key_obj_at(offset)
    report_on('secret_d', secret_d)

    [pub_point_q, size, offset] = get_key_obj_at(offset)
    report_on('pub_point_q', pub_point_q)

    return None # TODO key structure