# unclassified

sc-hsm-tool --initialize --so-pin xxx --pin yyy
pkcs11-tool --login --login-type so --so-pin=xxx --init-pin --new-pin=yyy
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --login --login-type so --so-pin yyy --change-pin --new-pin xxx  

pkcs11-tool --login --login-type so --show-info 