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

## references

Ludovic Rousseau  
PyKCS11 1.5.2 documentation  
https://pkcs11wrap.sourceforge.io/api/  

Olaf Kirch <okir@suse.de>  
pkcs11-tool - Man Page  
https://www.mankier.com/1/pkcs11-tool  

Remy van Elst  
Get started with the Nitrokey HSM or SmartCard-HSM  
https://raymii.org/s/articles/Get_Started_With_The_Nitrokey_HSM.html  

Ján Jančá  
Standardised Elliptic Curves  
https://neuromancer.sk/std/  

pkcs11-tool  
https://helpmanual.io/help/pkcs11-tool/  

python-pkcs11  
Using with SmartCard-HSM (Nitrokey HSM)  
https://python-pkcs11.readthedocs.io
https://python-pkcs11.readthedocs.io/en/latest/api.html

asn1 pip library  
https://python-asn1.readthedocs.io/en/latest/  
