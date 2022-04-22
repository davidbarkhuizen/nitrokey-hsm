import subprocess

import argparse

from core.dkek import load_binary_file, unwrap_ec_key, eckey_to_pem
from core.reports import ec_key_export_report, dkek_report

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

dkek, keyblob, eckey = unwrap_ec_key(encrypted_dkek_share, password, wrapped_ec_key)
pem = eckey_to_pem(eckey)

dkek_report_text = '\n'.join(dkek_report(dkek))
ec_report_text = '\n'.join(ec_key_export_report(pem, keyblob, eckey))

print()
print(dkek_report_text)
print()
print(ec_report_text)

#lpr = subprocess.Popen("/usr/bin/lpr", stdin=subprocess.PIPE)
#lpr.stdin.write(printer_text.encode('ascii'))