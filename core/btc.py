from binascii import hexlify, unhexlify
import hashlib
from Crypto.Hash import RIPEMD160
import base58

def btc_address(pub_key: bytes):
    assert len(pub_key) == 33

    msg = hashlib.sha256()
    msg.update(pub_key)
    one = msg.digest()

    msg = RIPEMD160.new()
    msg.update(one)  
    two = msg.digest()

    version_byte = bytes([0x00])
    three = version_byte + two

    four = base58.b58encode_check(three)
    
    return four.decode('ascii')

public_key_hex = '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'
assert btc_address(unhexlify(public_key_hex)) == '1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs'
print('ok')