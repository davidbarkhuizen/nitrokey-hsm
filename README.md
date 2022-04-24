# nitrokey-hsm-tools
david barkhuizen, 2022 (david.barkhuizen@gmail.com)    

## test credentials

credential|value
----------|-----
token-label|nitro-test
so-pin|c20257d49033ac93 
user-pin|f0365bf44b657ba 
share|dkek-test

    $ ./install-btc-key.sh nitro-test c20257d49033ac93 f0365bf44b657ba dkek-test passwordpassword btc-test

## install

### ubuntu

#### apt packages

- opensc [pkcs11-tool, opensc-tool, sc-hsm-tool]  

### python3 (pip)

asn1  
Python-ASN1  
https://python-asn1.readthedocs.io/en/latest/usage.html  

ecdsa  
https://pypi.org/project/ecdsa/  

    pip install -r requirements.txt