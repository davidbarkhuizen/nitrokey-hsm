import logging
from binascii import hexlify, unhexlify
import hashlib
from os import urandom
from enum import Enum
import struct

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

def decrypt_wrapped_key_blob(dkek: bytes, blob: bytes):

    # TODO parse asn.1
    # blob below is actually the first element (an octet string) in an asn.1 SEQUENCE of l=3
    #
    # SEQUENCE (3 elem)
    #   OCTET STRING (363 byte) 97E303855DC1C54D0C000A04007F00070202020203000000000000B2C97ABAF6BF457…
    #   ... (2)
    #   ... (3)

    blob = unhexlify('97e303855dc1c54d0c000a04007f00070202020203000000000000b2c97abaf6bf457fd94d5d76eb668dd10d042b3aebacc4f5b36f723e1ca129c0b6676f2b63ba6accf71923b6bd8d2c3a9190e19722c763c3082c35605caaa4d2c2eef72b42c5b5040da7f9a7a5450d33f49722137f479f9f34bf8d79d08ff109c756edb3c1ff77b5b2edc548da72629708bc618f5c262591420d45c5decb6cc5cd4aef328c8320aa90aa1f755f0aaee27af363cc5db5d21d912570866884c491c51325df73194bb641fd74080e49559a3a11a96c29eccddbf8dcad16352588a8b58990adf360df03e0e9d6081772d89a33b38931c64ebf4f9c8a3aa10fc87d71525a299401739531c0856b694bc124b2df87183bec684824bf57dba60ca511f3be96fcf16c06a4c4ad9c5c844d04d0f3d8a95208ea818d92263d1b754b0a840bd41b8d12f328b891f7bbad8f84806f5cfc24faa7b38b369fb98efdb77bccfb5af27e6021516b79619479e6138663277d')

    def generate_unpacker(source: bytes):

        def get_obj_from_blob(offset: int):
            [l] = struct.unpack('>H', source[offset:offset+2])
            obj = source[offset+2:offset+2+l]
            return (obj, l, offset+2+l)

        return get_obj_from_blob

    dkek_kcv = blob[:8]
    print(f'DKEK KCV {hexlify(dkek_kcv)}')

    raw_key_type = blob[8]   
    key_type = KeyType(raw_key_type)
    print(f'key type {key_type.name} ({raw_key_type})')

    get_blob_obj_at = generate_unpacker(blob)

    offset = 9
    [oid, obj_len,offset] = get_blob_obj_at(offset)
    print(hexlify(oid))
    # id-TA-ECDSA-SHA-256 0.4.0.127.0.7.2.2.2.2.3

    # 0000 allowed algos
    # 0000 access conditions
    # 0000 key OID

    [allowed_algos, size, offset] = get_blob_obj_at(offset)
    print(f'allowed_algos: {hexlify(allowed_algos)}')

    [access_conditions, size, offset] = get_blob_obj_at(offset)
    print(f'access_conditions: {hexlify(access_conditions)}')

    [key_oid, size, offset] = get_blob_obj_at(offset)
    print(f'key_oid: {hexlify(key_oid)}')

    encrypted_blob = blob[offset:-16] # TODO check
    print(len(encrypted_blob), hexlify(encrypted_blob))

    kek = derive_kek_from_dkek(dkek)
    iv = bytes([0x00]*16)
    decrypted_blob = decrypt_aes_cbc(kek, iv, encrypted_blob)
    print(f'decrypted_blob: {hexlify(decrypted_blob)}')

    random_prefix = decrypted_blob[:8]
    print(f'random_prefix: {hexlify(random_prefix)}')

    get_key_obj_at = generate_unpacker(decrypted_blob)

    [key_size] = struct.unpack('>H', decrypted_blob[8:10])
    print(f'key size, bits: {key_size}')

    offset = 10
    
    [a, size, offset] = get_key_obj_at(offset)
    print(f'a: {hexlify(a)}')

    [b, size, offset] = get_key_obj_at(offset)
    print(f'b: {hexlify(b)}')

    [prime_factor, size, offset] = get_key_obj_at(offset)
    print(f'prime_factor: {hexlify(prime_factor)}')

    [order, size, offset] = get_key_obj_at(offset)
    print(f'order: {hexlify(order)}')

    [generator_g, size, offset] = get_key_obj_at(offset)
    print(f'generator_g: {hexlify(generator_g)}')

    [secret_d, size, offset] = get_key_obj_at(offset)
    print(f'secret_d: {hexlify(secret_d)}')

    [pub_point_q, size, offset] = get_key_obj_at(offset)
    print(f'pub_point_q: {hexlify(pub_point_q)}')

    # mak = derive_mak_from_dkek(dkek)
    # print(f'len(mak) {len(mak)}')
    # calced_cmac = calc_cmac(mak, cert)

    # print(f'blob cmac   {hex(blob_cmac)}')
    # print(f'calced cmac {hex(calced_cmac)}')