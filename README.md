# nitrokey-btc-node
nitrokey-hsm btc node

## nitro-key hsm

### references

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

    pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --login --pin xxx --keypairgen --key-type EC:secp256k1 --label btc-test

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