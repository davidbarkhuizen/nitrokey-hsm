echo "so-pin $1";
echo "user-pin $2";
echo "dkek-share-file: $3";
echo "btc-key-label: $4";

sc-hsm-tool --initialize --so-pin $1 --pin $2 --dkek-shares 1

sc-hsm-tool --create-dkek-share $3
sc-hsm-tool --import-dkek-share $3

pkcs11-tool --login --pin $2 --keypairgen --key-type EC:secp256k1 --label $4
pkcs15-tool --dump
sc-hsm-tool --wrap-key $4-key.der --key-reference 1 --pin $2

# pkcs11-tool --pin f0365bf44b657ba --sign --id 6ad40c319318588593caae7b24a956175f4d46e7 --mechanism ECDSA-SHA1 --input-file binary_msg.bin --output-file binary_msg.sig.bin