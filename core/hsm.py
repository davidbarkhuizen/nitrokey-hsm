from pkcs11 import Token, KeyType, Attribute, util, lib
from pkcs11 import KeyType, ObjectClass, Mechanism
#from pkcs11.util.ec import encode_ec_public_key, encode_ecdsa_signature

ilib = None
def configure_pkcs11_lib(path: str):
    global ilib
    ilib = lib(path)

def get_token(label: str):
    return ilib.get_token(token_label=label)

def generate_ec_keypair(token, user_pin: str, curve: str, label: str):
    '''secp256r1, secp256k1'''

    pub, priv = None, None

    with token.open(user_pin=user_pin, rw=True) as session:
        
        key_attrs = { Attribute.EC_PARAMS: util.ec.encode_named_curve_parameters(curve) }
        ec_params = session.create_domain_parameters(KeyType.EC, key_attrs, local=True)
        pub, priv = ec_params.generate_keypair(store=True, label=label)
    
    return pub, priv

# Mechanism.ECDSA_SHA1

def sign_with_ec_key(
        hsm_serial: str, 
        user_pin: str, 
        key_label: str,
        data: bytes,
        mechanism: Mechanism
    ):

    target_slot = None

    for slot in ilib.get_slots(token_present=True):
        if hsm_serial in slot.slot_description:
            target_slot = slot
            break

    token = target_slot.get_token()
    sig  = None

    with token.open(user_pin=user_pin, rw=True) as session:

        priv = session.get_key(key_type=KeyType.EC, label=key_label, object_class=ObjectClass.PRIVATE_KEY)
        sig = priv.sign(data, mechanism=mechanism)

    return sig
