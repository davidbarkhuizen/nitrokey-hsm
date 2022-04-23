from core.hsm import configure_pkcs11_lib, go

hsm_serial = 'DENK0105702'
user_pin = 'f0365bf44b657ba'

configure_pkcs11_lib('/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so')
go(hsm_serial, user_pin, 'btc-test')