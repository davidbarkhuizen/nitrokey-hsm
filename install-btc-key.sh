echo '1 hsm-label 2 so-pin, 3 user-pin, 4 dkek-label, 5 dkek-password, 6 key-label'

sc-hsm-tool --initialize --label $1 --so-pin $2 --pin $3 --dkek-shares 1

return

sc-hsm-tool --create-dkek-share $4.pbe --password $5 
sc-hsm-tool --import-dkek-share $4.pbe --password $5

pkcs11-tool --login --pin $3 --keypairgen --key-type EC:secp256k1 --label $6
pkcs15-tool --dump

sc-hsm-tool --wrap-key $6-key.der --key-reference 1 --pin $3

python print-btc-key.py $4.pbe $5 $6-key.der

#0102030405060708090A0B0C0D0E0F0102030405060708090A0B0C0D0E0F | xxd -r -p > msg.bin
#pkcs11-tool --pin $3 --sign --mechanism ECDSA-SHA1 --input-file msg.bin --output-file sig.bin