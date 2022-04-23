import subprocess

import argparse

from core.dkek import load_binary_file, unwrap_ec_key, eckey_to_pem
from core.hsm import configure_pkcs11_lib, sign_with_ec_key
from core.reports import ec_key_export_report

from ecdsa import VerifyingKey, SigningKey

from pkcs11 import Mechanism

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

parser.add_argument('hsm', 
    type=str, 
    help='hsm serial number')

parser.add_argument('hsm_user_pin', 
    type=str, 
    help='hsm user pin')

parser.add_argument('hsm_key_label', 
    type=str, 
    help='hsm key label')

args = parser.parse_args()

encrypted_dkek_share = load_binary_file(args.dkek)
password = args.password.encode('ascii')
wrapped_ec_key = load_binary_file(args.key)
key_label = args.hsm_key_label
hsm_serial = args.hsm # 'DENK0105702'
user_pin = args.hsm_user_pin # 'f0365bf44b657ba'

configure_pkcs11_lib('/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so') # TODO

print('unwrapping key')
dkek, keyblob, eckey = unwrap_ec_key(encrypted_dkek_share, password, wrapped_ec_key)
pem = eckey_to_pem(eckey)

print('producing reference signature using hard key')
data = 'Introibo ad altare Dei'.encode('ascii')
hard_sig = sign_with_ec_key(hsm_serial, user_pin, key_label, data, Mechanism.ECDSA_SHA1)
print('using exported soft key to verify signature produced with hard key')
soft_signing_key = SigningKey.from_pem(pem)
soft_signing_key.verifying_key.verify(hard_sig, data)
print('hard signature successfully verified using exported soft key!')

report_text = '\n'.join(ec_key_export_report(dkek, pem, keyblob, eckey))

def xprint(text: str):

    for l in text.split('\n'):
        print(l)

    # DEBUG
    #
    # encoded = text.encode('ascii')
    # print('using default printer')
    # lpr = subprocess.Popen("/usr/bin/lpr", stdin=subprocess.PIPE)
    # lpr.stdin.write(encoded)

print('printing plaintext key export')
xprint(report_text)