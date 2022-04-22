import struct, asn1, time, logging, hashlib, base64
from os import urandom
from enum import Enum
from collections import namedtuple
from _md5 import md5 as MD5 # faster than hashlib.md5 (by factor of 2)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import cmac
from binascii import hexlify, unhexlify
import textwrap

encrypted_dkek_share_header = 'Salted__'.encode('ascii')
dkek_share_padding = unhexlify('10101010101010101010101010101010')

kek_padding = unhexlify("00000001")
mak_padding = unhexlify("00000002")

class KeyType(Enum):
    RSA = 5
    RSA_CRT = 6
    ECC = 12
    AES = 15

ECKey = namedtuple('ECKey',
    'random_prefix key_size a b prime_factor order generator_g secret_d pub_q')

KeyBlob = namedtuple('KeyBlob', 
    'dkek_kcv key_type oid encrypted_subblob')

def chunk(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def hex(b):
    return hexlify(b)

def readable_hex(b):
    hexed = hexlify(b)
    chunks = [hexed[i:i+4].decode('ascii') for i in range(0, len(hexed), 4)]
    return '\n'.join(['-'.join(line_chunks).upper() for line_chunks in chunk(chunks, 8)])

def timeit(method):
    def timed(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        te = time.time()        
        elapsed_ms = (te - ts) * 1000
        print(f'{method.__name__}: {elapsed_ms :.0} ms')
        return result
    return timed

def load_binary_file(path: str):
    binary_data = None
    with open(path, mode='rb') as file:
        binary_data = file.read()
    return binary_data

def write_text_file(path: str, text: str):
    with open(path, mode='wt') as file:
        file.write(text)

def write_binary_file(path: str, data: bytes):
    with open(path, mode='wb') as file:
        file.write(data)

def blank_dkek():
    return bytes([0x00]*32)

def mix_key_share_into_dkek(dkek, share):    
    return bytes(a ^ b for a, b in zip(dkek, share))

@timeit
def calc_dkek_kcv(dkek):
    kcv_msg = hashlib.sha256()
    kcv_msg.update(dkek)
    return kcv_msg.digest()[:8]

@timeit
def decrypt_aes_cbc(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(ciphertext)
    decryptor.finalize()
    return plain_text

@timeit
def encrypt_aes_cbc(key, iv, plain_text):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_text)
    encryptor.finalize()
    return cipher_text

@timeit
def derive_DKEK_share_encryption_key(salt: bytes, password: bytes, hash_iterations=10000000):
    '''return 32 byte derived key concatenated with 16 byte IV'''
    
    print('deriving DKEK share encryption password')

    d = bytes(0)
    
    key_iv = bytes([]) # bytes([0x00]*48) # 48 = 32 + 16

    for j in range(3):

        print(f'deriving DKEK share encryption key (step {j+1} of 3)...')
        
        nd = d + password
        d = nd

        nd = d + salt
        d = nd

        to_hash = d
        hashed = None
        for i in range(hash_iterations):
            hashed = MD5(to_hash).digest()
            to_hash = hashed

        key_iv = key_iv + hashed

        d = hashed
    
    return key_iv

@timeit
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

@timeit
def derive_kek_from_dkek(dkek):
    m = hashlib.sha256()
    m.update(dkek + kek_padding)
    return m.digest()

@timeit
def derive_mak_from_dkek(dkek):
    m = hashlib.sha256()
    m.update(dkek + mak_padding)
    return m.digest()

@timeit
def calc_cmac(mak: bytes, msg: bytes):
    cipher = cmac.CMAC(algorithms.AES(mak))
    cipher.update(msg)
    return cipher.finalize()

@timeit
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

@timeit
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

@timeit
def decrypt_dkek_wrapped_ec_key(dkek: bytes, der: bytes):

    decoder = asn1.Decoder()
    decoder.start(der)
    tag, value = decoder.read()
    x_decoder = asn1.Decoder()
    x_decoder.start(value)
    tag, value = x_decoder.read()

    blob = value

    def generate_unpacker(source: bytes):

        def unpack_obj_from_blob(offset: int):
            [l] = struct.unpack('>H', source[offset:offset+2])
            obj = source[offset+2:offset+2+l]
            return (obj, l, offset+2+l)

        return unpack_obj_from_blob

    dkek_kcv = blob[:8]

    raw_key_type = blob[8]   
    keytype = KeyType(raw_key_type)
    
    get_blob_obj_at = generate_unpacker(blob)

    offset = 9
    [oid, obj_len,offset] = get_blob_obj_at(offset)
    # id-TA-ECDSA-SHA-256 0.4.0.127.0.7.2.2.2.2.3

    [allowed_algos, size, offset] = get_blob_obj_at(offset)
    [access_conditions, size, offset] = get_blob_obj_at(offset)
    [key_oid, size, offset] = get_blob_obj_at(offset)

    encrypted_subblob = blob[offset:-16] # TODO check what is in the last 16 bytes !!!

    keyblob = KeyBlob(dkek_kcv, keytype, oid, encrypted_subblob)

    kek = derive_kek_from_dkek(dkek)
    iv = bytes([0x00]*16)
    decrypted_subblob = decrypt_aes_cbc(kek, iv, encrypted_subblob)

    # -------------------------------------------------------

    random_prepadding = decrypted_subblob[:8]
    get_key_obj_at = generate_unpacker(decrypted_subblob)
    [key_size] = struct.unpack('>H', decrypted_subblob[8:10])

    offset = 10

    [a, size, offset] = get_key_obj_at(offset)
    [b, size, offset] = get_key_obj_at(offset)
    [prime_factor, size, offset] = get_key_obj_at(offset)
    [order, size, offset] = get_key_obj_at(offset)
    [generator_g, size, offset] = get_key_obj_at(offset)
    [secret_d, size, offset] = get_key_obj_at(offset)
    [pub_point_q, size, offset] = get_key_obj_at(offset)

    eckey = ECKey(
        random_prepadding, 
        key_size, 
        a, 
        b, 
        prime_factor, 
        order, 
        generator_g, 
        secret_d, 
        pub_point_q)

    return (keyblob, eckey)

def unwrap_ec_key(encrypted_dkek_share: bytes, password: bytes, wrapped_key: bytes):
    dkek_share = decrypt_DKEK_share_blob(encrypted_dkek_share, password)
    dkek = dkek_from_shares([dkek_share])        
    calced_kcv = calc_dkek_kcv(dkek)
    print(f'dkek kcv {hexlify(calced_kcv)}')
    keyblob, eckey = decrypt_dkek_wrapped_ec_key(dkek, wrapped_key)
    return dkek, keyblob, eckey

def eckey_to_pem(eckey: ECKey):
    
    header = unhexlify('30740201010420')
    priv_key = eckey.secret_d
    joiner = unhexlify('a00706052b8104000aa144034200')
    pub_key = eckey.pub_q

    der = header + priv_key + joiner + pub_key

    return '\n'.join([
        '-----BEGIN EC PRIVATE KEY-----',
        *textwrap.wrap(base64.b64encode(der).decode('ascii'), 64),
        '-----END EC PRIVATE KEY-----'
    ])