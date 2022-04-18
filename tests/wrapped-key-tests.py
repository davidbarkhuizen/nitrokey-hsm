import unittest
from binascii import unhexlify

from core.dkek import decrypt_wrapped_key_blob

dkek = unhexlify('c955af6fb058ca963d270049de57b75b175d528b8993d7651dcc4650097caffb')
wrapped_btc_key = unhexlify('3082039a0482016b2afa121e8764a1e30c000a04007f00070202020203000000000000fbede3428f5b7dd4cb9ae76762c39f47d13e93ce1e581cbc1c8581f66dd9a470479a9f38d0632e0b60aa148b249f0d1453a193b78cb68d173062240b268df3193509cd03504b436c51b2ab03fa78f2a1eadfc719c811ee70fcf6315c80d046f07690adf871d43c925270500703967b6746edc9df3eb58a5f5f4b6f2992736f1235874d821f02cd447181c8dfc2f99be580c1946701a72614a61c8bfab1d8386bee14e17b86110ecd910d9ef881bd232c8d065ef17ebddd29d812df94336b38c6c04144818a4bd3d189a685a8fecc34e12b13b96268eb28d66b219cdc2ab0a7c50996d838ca3cba9aac51a702276f6f85fb661d908d55c6108b932fbb24d23fa6346a1219c2d18920db05d0d4b8f9480be025cd3b3b52bae324fb77afa1863b84babb818ccec6c11e48d0f4fe9c5b3ef5bf958be0abe0df39600cf489838884c0359ec5b2a56ed72a64a7cec779803e70a03f30110c086274632d74657374030206c0040101301e04141ea2dde2f6a5e450cb391e073d2919e582973aef0303073080020101a10a30083002040002020100678201e67f2182018c7f4e8201445f29010042095554434130303030317f4982011d060a04007f000702020202038120fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f822000000000000000000000000000000000000000000000000000000000000000008320000000000000000000000000000000000000000000000000000000000000000784410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b88520fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141864104c572506893f3a850ad98206f19585d1c77d6b48796ff9fbd32346e0d850578d0e679b77a15b702b40d7b2d2f9a63e6516e6bee8e33e50b6f97c69b0408106f0c8701015f201044454e4b3031303537303230303030315f3740ad280bef03a59938341f6dd8aa52fef9e700bb079173006e1e382455be8ed57cfa018157389cf7b561496540e7cc3a678703bedd0cc9b096b74e1d7ad1ab4309421044454e4b3031303537303230303030305f374037df977dd4030f1b9d916930014725eab9241391138d3b6ffe0e9070138264871a8f1cbf2edde032e5d15ca9892e3221c793bf4a216d91622f2fcac9ad832be3')

class TestKeyWrapping(unittest.TestCase):
    
    def test_encryption_of_wrapped_btc_key(self):
        decrypt_wrapped_key_blob(dkek, wrapped_btc_key)
        self.assertEqual(True, True)

if __name__ == '__main__':
    unittest.main()