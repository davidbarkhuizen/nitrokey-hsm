import random

import key_utils
import txn_utils
import msg_utils
import socket

private_key_hex = '' # hex

# 2022
# mean transaction fee 0.00004541 Bitcoin ($2.06)
# the median is        0.00001292 Bitcoin ($0.59)

#               0.00001292

# before        0.00101234
# less fee      0.00010000
#               0.00091234 BTC
amount_in_satoshis = 91234

prev_txn_output_hash = "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48"
source_index = 0
dest_address = '1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa'

btc_node_host = '97.88.151.164'
btc_node_port = 8333

wif = key_utils.privateKeyToWif(private_key_hex)
source_address = key_utils.keyToAddr(private_key_hex)

print(private_key_hex, wif, source_address)

privateKey = key_utils.wifToPrivateKey(wif)

signed_txn = txn_utils.makeSignedTransaction(privateKey,
    prev_txn_output_hash,
    source_index,
    key_utils.addrHashToScriptPubKey(source_address),
    [[amount_in_satoshis, key_utils.addrHashToScriptPubKey(dest_address)]]
)
    
txn_utils.verifyTxnSignature(signed_txn)
print('SIGNED TXN', signed_txn)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((btc_node_host, btc_node_port))

sock.send(msg_utils.getVersionMsg())
sock.recv(1000) # receive version
sock.recv(1000) # receive verack
sock.send(msg_utils.getTxMsg(signed_txn.decode('hex')))