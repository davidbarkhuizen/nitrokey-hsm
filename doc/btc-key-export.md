# BTC Key Generation & Export

## DKEK

### Initialize HSM for 1 DKEK Share

re-initialize HSM, setting user pin to yyy, and configuring for a single DKEK key share file
    
    $ sc-hsm-tool --initialize --so-pin c20257d49033ac93 --pin f0365bf44b657ba --dkek-shares 1

    Using reader with a card: Nitrokey Nitrokey HSM (DENK01057020000         ) 00 00

### Generation of DKEK Share

    $ sc-hsm-tool --create-dkek-share dkek-test.pbe

    Using reader with a card: Nitrokey Nitrokey HSM (DENK01057020000         ) 00 00

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

### Dump DKEK Share to hex

    $ hexdump -ve '1/1 "%.2x"' dkek-test.pbe > dkek-test.pbe.hex 

    53616c7465645f5fa24f5a8aef8e398445568310e4a699667642a614ff11bdc854ccd1eca84164d2bc53ea682cda98af6080d0f37ef6d7a5ceb09d202a39abdd

### Import DKEK from Single Share  

    $ sc-hsm-tool --import-dkek-share dkek-test.pbe

    Using reader with a card: Nitrokey Nitrokey HSM (DENK01057020000         ) 00 00
    Enter password to decrypt DKEK share : 

    Deciphering DKEK share, please wait...
    DKEK share imported
    DKEK shares          : 1
    DKEK key check value : ECC92C62E3F6189E

## BTC Key

### Generate BTC Key

    $ pkcs11-tool --login --pin f0365bf44b657ba --keypairgen --key-type EC:secp256k1 --label btc-test

    Using slot 0 with a present token (0x0)
    Key pair generated:
    
    Private Key Object; EC
        label:      btc-test
        ID:         6ad40c319318588593caae7b24a956175f4d46e7
        Usage:      sign, derive
        Access:     none
    
    Public Key Object; EC  EC_POINT 256 bits
        EC_POINT:04410434de60895fe7949543388c01aa68b9c825dc9a2c34fa542a1a2304a9408198a214f355f6e7452be0fd0359d30a75c023b94a0302783e463da2e9c0b1179bceb5
        EC_PARAMS:  06052b8104000a
        label:      btc-test
        ID:         6ad40c319318588593caae7b24a956175f4d46e7
        Usage:      verify, derive
        Access:     none

### Query BTC Key Id

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
        ID             : 6ad40c319318588593caae7b24a956175f4d46e7
        MD:guid        : 5fa35623-5027-dc23-753e-b89b07fb11f3

    Public EC Key [btc-test]
        Object Flags   : [0x00]
        Usage          : [0x40], verify
        Access Flags   : [0x02], extract
        FieldLength    : 256
        Key ref        : 0 (0x00)
        Native         : no
        ID             : 6ad40c319318588593caae7b24a956175f4d46e7
        DirectValue    : <present>

### Export BTC Key

    $ sc-hsm-tool --wrap-key btc-test-key.der --key-reference 1 --pin f0365bf44b657ba

### Dump BTC Key To hex

    $ hexdump -ve '1/1 "%.2x"' btc-test-key.der > btc-test-key.hex 

