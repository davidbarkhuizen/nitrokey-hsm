echo '1 so-pin, 2 user-pin, 3 dkek-label, 4 dkek-password, 5 key-label'

# sc-hsm-tool --initialize --so-pin $1 --pin $2 --dkek-shares 1

# sc-hsm-tool --create-dkek-share $3.pbe --password $4 
# sc-hsm-tool --import-dkek-share $3.pbe --password $4

# pkcs11-tool --login --pin $2 --keypairgen --key-type EC:secp256k1 --label $5
# pkcs15-tool --dump

# sc-hsm-tool --wrap-key $5-key.der --key-reference 1 --pin $2

python print-btc-key.py $3.pbe $4 $5-key.der

#0102030405060708090A0B0C0D0E0F0102030405060708090A0B0C0D0E0F | xxd -r -p > msg.bin
#pkcs11-tool --pin $2 --sign --mechanism ECDSA-SHA1 --input-file msg.bin --output-file sig.bin