from core.hsm import configure_pkcs11_lib, go

hsm_serial = 'DENK0105702'

configure_pkcs11_lib('/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so')
go(hsm_serial)