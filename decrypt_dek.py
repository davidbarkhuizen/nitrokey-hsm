import logging
from binascii import hexlify, unhexlify
import hashlib

def hex(b):
    return hexlify(b).upper()

def blankDKEK():
    return unhexlify('0000000000000000000000000000000000000000000000000000000000000000')

# # Return the Key Check Value (KCV) of the internal DKEK
# # @type ByteString
# # @return the KCV
# DKEK.prototype.getKCV = function() {
# 	return this.crypto.digest(Crypto.SHA_256, this.dkek).left(8);
# }

# # Derive the encryption key from the DKEK
# # @type ByteString
# # * @return the encryption key
# DKEK.prototype.getKENC = function() {
# 	var kencval = this.crypto.digest(Crypto.SHA_256, this.dkek.concat(new ByteString("00000001", HEX)));
# 	var kenc = new Key();
# 	kenc.setComponent(Key.AES, kencval);
# 	return kenc;
# }



# /**
#  * Derive the message authentication key from the DKEK
#  *
#  * @type ByteString
#  * @return the message authentication key
#  */
# DKEK.prototype.getKMAC = function() {
# 	var kmacval = this.crypto.digest(Crypto.SHA_256, this.dkek.concat(new ByteString("00000002", HEX)));
# 	var kmac = new Key();
# 	kmac.setComponent(Key.AES, kmacval);
# 	return kmac;
# }


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

        m = hashlib.md5(hash_iterations)
        m.update(d)
        hashed = m.digest()

        key_iv = key_iv + hashed

        d = hashed
    
    return key_iv

# /**
#  * Encrypt a DKEK share
#  *
#  * @param {ByteString} keyshare the key share
#  * @param {ByteString} password the password
#  * @type ByteString
#  * @return Encrypted DKEK share value
#  */
# DKEK.encryptKeyShare = function(keyshare, password) {
# 	assert(keyshare instanceof ByteString, "Argument keyshare must be ByteString");
# 	assert(keyshare.length == 32, "Argument keyshare must be 32 bytes");
# 	assert(password instanceof ByteString, "Argument password must be ByteString");

# 	var crypto = new Crypto();
# 	var salt = crypto.generateRandom(8);

# 	var keyiv = DKEK.deriveDKEKShareKey(salt, password);

# 	var k = new Key();
# 	k.setComponent(Key.AES, keyiv.bytes(0, 32));
# 	var iv = keyiv.bytes(32, 16);
# 	keyiv.clear();

# 	var plain = keyshare.concat(new ByteString("10101010101010101010101010101010", HEX));
# 	var cipher = crypto.encrypt(k, Crypto.AES_CBC, plain, iv);
# 	plain.clear();
# 	k.getComponent(Key.AES).clear();

# 	var blob = (new ByteString("Salted__", ASCII)).concat(salt).concat(cipher);
# 	return blob;
# }

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# DKEK.testDKEK = function() {
# 	var crypto = new Crypto();
# 	var dkek = crypto.generateRandom(32);
# 	var password = new ByteString("Password", ASCII);
# 	var enc = DKEK.encryptKeyShare(dkek, password);
# 	print(enc);
# 	var plain = DKEK.decryptKeyShare(enc, password);
# 	assert(dkek.equals(plain), "Reference does not match");
# }

def decrypt_DEK(share:bytes, password: bytes):

    assert len(share) == 64

    share_prefix = share[0:8]
    assert share_prefix.decode('ASCII') == 'Salted__'

    salt = share[8:16]
    logging.info(f'salt: {hex(salt)}')

    hash_iterations=10000000

    from hashlib import pbkdf2_hmac
    dk = pbkdf2_hmac('md5', password, salt, hash_iterations, 32)

    print(hex(dk))

    # key_iv = derive_encryption_key(salt, password)

    # logging.info(f'key_iv [l={len(key_iv)}]: {hexlify(key_iv)}')

    # key = key_iv[0:32]
    # iv = key_iv[32:]
    
    # logging.info(f'key: {hexlify(key)}')
    # logging.info(f'iv: {hexlify(iv)}')


# 	var k = new Key();
# 	k.setComponent(Key.AES, keyiv.bytes(0, 32));
# 	var iv = keyiv.bytes(32, 16);
# 	keyiv.clear();

# 	var plain = crypto.decrypt(k, Crypto.AES_CBC, keyshare.bytes(16), iv);
# 	k.getComponent(Key.AES).clear();

# 	if (!(new ByteString("10101010101010101010101010101010", HEX)).equals(plain.right(16))) {
# 		throw new GPError(module.id, GPError.INVALID_DATA, 0, "Decryption of DKEK failed. Wrong password ?");
# 	}

# 	var val = plain.left(32);
# 	plain.clear();

# 	return val;
# }


def load_local_share_file(path: str):
    logging.info(f'loading DKEK file share @ {path}')
    binary_data = None
    with open(path, mode='rb') as file:
        binary_data = file.read()
    return binary_data

logging.basicConfig()
logging.root.setLevel(logging.INFO)

password = 'passwordpassword'.encode('ascii')
share = load_local_share_file('sample.pbe.share')
dek = decrypt_DEK(share, password)