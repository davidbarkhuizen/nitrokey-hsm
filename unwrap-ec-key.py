import argparse
from binascii import hexlify

from yaml import load

from core.dkek import decrypt_DKEK_share_blob, decrypt_dkek_wrapped_ec_key, dkek_from_shares, calc_dkek_kcv, load_binary_file

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

args = parser.parse_args()

encrypted_dkek_share = load_binary_file(args.dkek)
dkek_share_enc_password = args.password.encode('ascii')
wrapped_ec_key = load_binary_file(args.key)

dkek_share = decrypt_DKEK_share_blob(encrypted_dkek_share, dkek_share_enc_password)
dkek = dkek_from_shares([dkek_share])        
calced_kcv = calc_dkek_kcv(dkek)
print(f'dkek kcv {hexlify(calced_kcv)}')
ec_key = decrypt_dkek_wrapped_ec_key(dkek, wrapped_ec_key)
print(ec_key)