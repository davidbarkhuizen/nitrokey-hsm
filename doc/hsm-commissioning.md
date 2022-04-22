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
