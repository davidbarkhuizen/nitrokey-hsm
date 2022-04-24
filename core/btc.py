from binascii import hexlify, unhexlify
import hashlib
from Crypto.Hash import RIPEMD160
import base58

def hash_sha256(data: bytes):
    digestor = hashlib.sha256()
    digestor.update(data)
    return digestor.digest()

def hash_rip160(data: bytes):
    digestor = RIPEMD160.new()
    digestor.update(data)  
    return digestor.digest()

def btc_address_from_true_public_key(true_pub_key: bytes):
    assert len(true_pub_key) == 33

    prefixed_pub_key = bytes([0x04]) + true_pub_key
    shaed = hash_sha256(prefixed_pub_key)
    ripped = hash_rip160(shaed)

    version_byte = bytes([0x00])
    versioned = version_byte + ripped

    checked = base58.b58encode_check(versioned)
    
    return checked.decode('ascii')

def test():
    # private_key_hex = '18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725'
    public_key_hex = '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'
    ref_btc_address = '1LKmMsTRBiwtWFhZofan6RSNwGm4or8cQ3'
    assert btc_address_from_true_public_key(unhexlify(public_key_hex)) == ref_btc_address

test()