from core.dkek import ECKey, KeyBlob, hex, readable_hex

def report_on(label:str, target):
    
    try: 
        target_str = hex(target)
    except:
        target_str = str(target)
    
    l = len(target) if hasattr(target, '__len__') else '?'

    return f'{label: <20} ({l:>3}) {target_str}'

# print to printer
#
# plaintext ec private key
# plaintext ec public key
# plaintext ec pvt key in PEM format
# plaintext ec pvt key in der format (hex)
#
# print dek share (hex) & KCV

def ec_key_export_report(dkek: bytes, blob: KeyBlob, key: ECKey):

    blob_report = [report_on(l,v) for [l,v] in [
        ('DKEK KCV', blob.dkek_kcv),
        ('key_type', f'{blob.key_type.name} ({blob.key_type.value})'),
        ('oid', blob.oid)
    ]]    

    short_ec_field_report = [report_on(l,v) for [l,v] in [
        ('key size, bits', key.key_size),
        ('random_prefix', key.random_prefix),
        ('a', key.a),    
        ('b', key.b),    
        ('prime_factor', key.prime_factor),
        ('order', key.order),
        ('generator_g', key.generator_g),        
    ]]        
        
    long_ec_fields_report = [
        'secret_d', 
        str(hex(key.secret_d)),
        readable_hex(key.secret_d), 
        'pub_q', 
        str(hex(key.pub_q)),
        readable_hex(key.pub_q)
    ]

    return [
        *blob_report,
        '', 
        *short_ec_field_report, 
        '',
        *long_ec_fields_report
    ]

