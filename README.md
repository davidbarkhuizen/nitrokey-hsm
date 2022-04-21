# nitrokey-btc-node
nitrokey-hsm btc node

## nitro-key hsm

### references

Olaf Kirch <okir@suse.de>
pkcs11-tool - Man Page
https://www.mankier.com/1/pkcs11-tool

Remy van Elst
Get started with the Nitrokey HSM or SmartCard-HSM
https://raymii.org/s/articles/Get_Started_With_The_Nitrokey_HSM.html

Ján Jančá
Standardised Elliptic Curves
https://neuromancer.sk/std/

helpmanual.io  
pkcs11-tool  
https://helpmanual.io/help/pkcs11-tool/  

python-pkcs11
Using with SmartCard-HSM (Nitrokey HSM)  
https://python-pkcs11.readthedocs.io/en/latest/opensc.html  

asn1 pip library
https://python-asn1.readthedocs.io/en/latest/

### install

ubuntu apt packages to install:  
- opensc [pkcs11-tool, opensc-tool, sc-hsm-tool]  

### commissioning

query HSM status (dump all card objects)  

    pkcs15-tool -D

list algorithms implemented by HSM  

    $ opensc-tool --list-algorithms

determine location of opensc-pkcs11.so module  

    user@host:~$ whereis opensc-pkcs11.so  
    opensc-pkcs11: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so  

initialize HSM, irreversibly setting SO-PIN (write SO-PIN to write-once PROM)  
    
    pkcs11-tool --init-token --init-pin --so-pin=0000000000000000 --new-pin=xxx --label="test" --pin=xxx

change so-pin, using so-pin  

    pkcs11-tool --module /usr/local/lib/opensc-pkcs11.so --login --login-type so --so-pin 3537363231383830 --change-pin --new-pin 0123456789012345

change user-pin, using so-pin
    pkcs11-tool --login --login-type so --so-pin=3537363231383830 --init-pin --new-pin=648219

#### DKEK

re-initialize HSM, setting user pin to yyy, and configuring for a single DKEK key share file
    
    $ sc-hsm-tool --initialize --so-pin xxx --pin yyy --dkek-shares 1

##### Generation

generate single password-encrypted pbe DEK share file  

    $ sc-hsm-tool --create-dkek-share dkek-test.pbe

    Using reader with a card: Nitrokey Nitrokey HSM (DENK00000000000         ) 00 00

    The DKEK share will be enciphered using a key derived from a user supplied password.
    The security of the DKEK share relies on a well chosen and sufficiently long password.
    The recommended length is more than 10 characters, which are mixed letters, numbers and
    symbols.

    Please keep the generated DKEK share file in a safe location. We also recommend to keep a
    paper printout, in case the electronic version becomes unavailable. A printable version
    of the file can be generated using "openssl base64 -in <filename>".
    Enter password to encrypt DKEK share : 

    Please retype password to confirm : 

    Enciphering DKEK share, please wait...
    DKEK share created and saved to dkek-test.pbe

convert binary to text to print to paper  

    # hex (base 16)  
    $ hexdump -ve '1/1 "%.2x"' dkek-test.pbe > dkek-test.pbe.hex  

    # base64  
    $ openssl base64 -in dkek-test.pbe > dkek-test.pbe.b64  

convert dump back to binary

    # hexdump
    xxd -r -p dkek-test.pbe.hex dkek-test.pbe  

    # b64
    b64 -d dkek-test.pbe.64 dkek-test.pbe

##### Import

import DKEK  

    $ sc-hsm-tool --import-dkek-share dkek-test.pbe

    Using reader with a card: Nitrokey Nitrokey HSM (DENK00000000000         ) 00 00
    Enter password to decrypt DKEK share : 

    Deciphering DKEK share, please wait...
    DKEK share imported
    DKEK shares          : 1
    DKEK key check value : 1234567890123456

### unclassified

sc-hsm-tool --initialize --so-pin xxx --pin yyy
pkcs11-tool --login --login-type so --so-pin=xxx --init-pin --new-pin=yyy
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --login --login-type so --so-pin yyy --change-pin --new-pin xxx  

pkcs11-tool --login --login-type so --show-info

### key generation, import & export

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

### key operations

## specifications & performance

### capacity

76kB EPROM  

Key Storage
algorithm|bits|capacity  
---------|----|--------  
ECC|521|150  
ECC|256|300  
AES|256|300  
RSA|4096|19  
RS|2048|38  

### DKEK

AES256
password-based-encryption (PBE)

pip3 install -r requirements.txt 