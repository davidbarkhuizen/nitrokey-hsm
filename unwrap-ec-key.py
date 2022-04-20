import argparse

parser = argparse.ArgumentParser(description='unwrap NitroKey-HSM EC key')

parser.add_argument('--dek', type=str)
parser.add_argument('--password', type=str)
parser.add_argument('--key', type=str)

parser.parse_args()