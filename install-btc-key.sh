# 1 so-pin
# 2 user-pin
# 3 dkek-label
# 4 dkek-password
# 5 key-label

echo "dkek-share-label: $3";
echo "btc-key-label: $5";

sc-hsm-tool --initialize --so-pin $1 --pin $2 --dkek-shares 1

sc-hsm-tool --create-dkek-share $3.pbe --password $4 
sc-hsm-tool --import-dkek-share $3.pbe --password $4

pkcs11-tool --login --pin $2 --keypairgen --key-type EC:secp256k1 --label $5
pkcs15-tool --dump
sc-hsm-tool --wrap-key $5-key.der --key-reference 1 --pin $2

python install-btc-key.py $3.pbe $4 $5-key.der