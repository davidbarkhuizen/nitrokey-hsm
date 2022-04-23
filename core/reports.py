from binascii import hexlify
from core.dkek import ECKey, KeyBlob, hex, readable_hex

import base58

def format(target):

    try: 
        target_str = str(hex(target))
    except:
        target_str = str(target)
    
    return target_str 


def report_on(label:str, target):
    l = len(target) if hasattr(target, '__len__') else '?'

    return f'{label: <20} ({l:>3}) {format(target)}'

# print to printer
#
# plaintext ec private key
# plaintext ec public key
# plaintext ec pvt key in PEM format
# plaintext ec pvt key in der format (hex)
#
# print dek share (hex) & KCV

def ec_key_export_report(dkek, pem, blob: KeyBlob, key: ECKey):

    dkek_report = [
        'PLAINTEXT DKEK',
        readable_hex(dkek)
    ]

    blob_report = [
        'DKEK KCV', 
        format(blob.dkek_kcv),
        '',
        'key_type',
        f'{blob.key_type.name} ({blob.key_type.value})',
        '',
        'oid',
        format(blob.oid)
    ]

    short_ec_field_report = [
        'key size, bits', 
        format(key.key_size),
        '',
        'random_prefix',
        readable_hex(key.random_prefix),
        '',
        'a', 
        readable_hex(key.a),    
        '',
        'b', 
        readable_hex(key.b),    
        '',
        'prime_factor', 
        readable_hex(key.prime_factor),
        '',
        'order', 
        readable_hex(key.order),
        '',
        'generator_g', 
        readable_hex(key.generator_g)
    ]
        
    long_ec_fields_report = [
        f'secret_d ({len(key.secret_d)})', 
        readable_hex(key.secret_d), 
        '',
        f'pub_q ({len(key.pub_q)})', 
        readable_hex(key.pub_q),
        ''
        'pub_q (b58)',
        base58.b58encode_check(key.pub_q).decode('ascii')
    ]

    pem_report = [
        'PEM',
        pem
    ]

    return [
        *blob_report,
        '',
        *short_ec_field_report, 
        '',
        *long_ec_fields_report,
        '',
        *pem_report
    ]