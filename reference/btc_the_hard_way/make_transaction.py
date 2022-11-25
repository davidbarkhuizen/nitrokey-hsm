import utils
import key_utils
import txn_utils


privateKey = key_utils.wifToPrivateKey("5HusYj2b2x4nroApgfvaSfKYZhRbKFH41bVyPooymbC6KfgSXdD") #1MMMM

signed_txn = txn_utils.makeSignedTransaction(privateKey,
        "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48", # output (prev) transaction hash
        0, # sourceIndex
        key_utils.addrHashToScriptPubKey("1MMMMSUb1piy2ufrSguNUdFmAcvqrQF8M5"),
        [[91234, #satoshis
        key_utils.addrHashToScriptPubKey("1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa")]]
        )
    
txn_utils.verifyTxnSignature(signed_txn)
print 'SIGNED TXN', signed_txn
