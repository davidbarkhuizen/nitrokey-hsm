# key importation, generation & export

generate ec key  

    pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --login --pin xxx --keypairgen --key-type EC:prime256k1 --label aleph```

generate BTC key pair (using NIST curve secp256k1, https://neuromancer.sk/std/secg/secp256k1)

    $ pkcs11-tool --login --pin xxx --keypairgen --key-type EC:secp256k1 --label btc-test

    Using slot 0 with a present token (0x0)
    Key pair generated:
    Private Key Object; EC
    label:      btc-test
    ID:         272bc2fea76fd825cf980751a58de8191ff7f094
    Usage:      sign, derive
    Access:     none
    Public Key Object; EC  EC_POINT 256 bits
    EC_POINT:   044104492387dbacdf9abde5f56afee0b2e762a3548c0201ca46c5c0bc4a610cd7f78c87fea9e9c70e6085bd163102835aeb84db80daa3b31cc7a6c1bcf4d9b32a236f
    EC_PARAMS:  06052b8104000a
    label:      btc-test
    ID:         272bc2fea76fd825cf980751a58de8191ff7f094
    Usage:      verify, derive
    Access:     none

get key id

    $ pkcs15-tool --dump

    Private EC Key [btc-test]
        Object Flags   : [0x03], private, modifiable
        Usage          : [0x10C], sign, signRecover, derive
        Access Flags   : [0x1D], sensitive, alwaysSensitive, neverExtract, local
        Algo_refs      : 0
        FieldLength    : 256
        Key ref        : 1 (0x01)
        Native         : yes
        Auth ID        : 01
        ID             : 272bc2fea76fd825cf980751a58de8191ff7f094
        MD:guid        : b6eea0df-0f3e-eb7f-af20-a5404724bf40

    Public EC Key [btc-test]
        Object Flags   : [0x00]
        Usage          : [0x40], verify
        Access Flags   : [0x02], extract
        FieldLength    : 256
        Key ref        : 0 (0x00)
        Native         : no
        ID             : 272bc2fea76fd825cf980751a58de8191ff7f094
        DirectValue    : <present>

export key

    $ sc-hsm-tool --wrap-key wrapped-btc-key.bin --key-reference 1 --pin 648219

    Using reader with a card: Nitrokey Nitrokey HSM (DENK01057020000         ) 00 00

    $ hexdump -ve '1/1 "%.2x"' wrapped-btc-key.bin > wrapped-btc-key.hex

sample exported key:

SEQUENCE (3 elem)
  OCTET STRING (363 byte) 97E303855DC1C54D 0C000A04007F000702020202030000000000000B252EC58195361…
  [0] (3 elem)
    SEQUENCE (3 elem)
      UTF8String btc-test <--- label
        Offset: 375
        Length: 2+8
        Value:
        btc-test
      BIT STRING (2 bit) 11
      OCTET STRING (1 byte) 01
    SEQUENCE (3 elem)
      OCTET STRING (20 byte) 2D661828C62CC3C2E7801588CAF510510B29572E
      BIT STRING (9 bit) 001100001
      INTEGER 1
    [1] (1 elem)
      SEQUENCE (2 elem)
        SEQUENCE (1 elem)
          OCTET STRING (0 byte)
        INTEGER 256 <-- ECC key size in bits
  Application 7 (3 elem)
    Application 33 (2 elem)
      Application 78 (4 elem)
        Application 41 (1 byte) 00
        Application 2 (9 byte) UTCA00001 <-- public key reference ? UT + 
        Application 73 (8 elem)
          OBJECT IDENTIFIER 0.4.0.127.0.7.2.2.2.2.3 bsiTA_ECDSA_SHA256 (BSI TR-03110)
          [1] (32 byte) FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
          [2] (32 byte) 0000000000000000000000000000000000000000000000000000000000000000
          [3] (32 byte) 0000000000000000000000000000000000000000000000000000000000000007
          [4] (65 byte) 0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483A…
          [5] (32 byte) FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
          [6] (65 byte) 0410672D3327CCFEFB55EE6C7CDAEDFED0212E40EFDC9391AAB3D8070111EC90B0750E…
          [7] (1 byte) 01
        Application 32 (16 byte) DENK010570200001
      Application 55 (64 byte) FF359A24804A184936A0F9CE3B8558CF75D8AD384B1D8F7126941AF301B0B2CFACC93A…
    Application 2 (16 byte) DENK010570200000
    Application 55 (64 byte) 5569436B4A785BB00EA45D923EF35B78CAF18B2BBC47ACF5DE9755CA5F1FCBEB14CBCE…