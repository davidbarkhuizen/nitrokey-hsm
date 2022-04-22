import subprocess

import argparse
from binascii import hexlify

from core.dkek import load_binary_file, unwrap_ec_key, eckey_to_pem, write_text_file
from ecdsa import SigningKey

parser = argparse.ArgumentParser(description='unwrap EC key exported from NitroKeyHSM')

parser.add_argument('dkek', 
    type=str, 
    help='path to pbe encrypted dkek share')

parser.add_argument('password', 
    type=str, 
    help='dke share encryption password')

parser.add_argument('key', 
    type=str, 
    help='path to wrapped ec key')

args = parser.parse_args()

encrypted_dkek_share = load_binary_file(args.dkek)
password = args.password.encode('ascii')
wrapped_ec_key = load_binary_file(args.key)

dkek, eckey = unwrap_ec_key(encrypted_dkek_share, password, wrapped_ec_key)
pem = eckey_to_pem(eckey)

lpr = subprocess.Popen("/usr/bin/lpr", stdin=subprocess.PIPE)
lpr.stdin.write(pem.encode('ascii'))

# print to printer
#
# plaintext ec private key
# plaintext ec public key
# plaintext ec pvt key in PEM format
# plaintext ec pvt key in der format (hex)
#
# print dek share (hex) & KCV

# =-=-=-=-=

#signing_key = SigningKey.from_pem(pem)
#assert signing_key.verifying_key.verify(sig, msg)