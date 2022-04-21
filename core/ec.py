from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def ec_sign_ecdsa_sha1(pem, msg):
    key = serialization.load_pem_private_key(pem, password=None)
    return key.sign(msg, ec.ECDSA(hashes.SHA1()))

def ec_verify_ecdsa_sha1(pem, msg, sig):
    key = serialization.load_pem_private_key(pem, password=None)
    key.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA1()))