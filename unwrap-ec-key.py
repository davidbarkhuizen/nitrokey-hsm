import argparse

from core.dkek import read_binary_file, unwrap_ec_key, eckey_to_pem, write_text_file

parser = argparse.ArgumentParser(description='unwrap EC key exported from NitroKeyHSM')

parser.add_argument('dkek', 
    type=str, 
    help='path to pbe encrypted dkek share')

parser.add_argument('password', 
    type=str, 
    help='password used pbe encryption')

parser.add_argument('key', 
    type=str, 
    help='path to wrapped ec key')

parser.add_argument('pem', 
    type=str, 
    help='path to output plaintext ec key in PEM format')

args = parser.parse_args()

encrypted_dkek_share = read_binary_file(args.dkek)
password = args.password.encode('ascii')
wrapped_ec_key = read_binary_file(args.key)

eckey = unwrap_ec_key(encrypted_dkek_share, password, wrapped_ec_key)
pem = eckey_to_pem(eckey)
write_text_file(args.pem, pem)