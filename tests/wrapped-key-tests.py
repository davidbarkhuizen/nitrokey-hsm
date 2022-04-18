import unittest
from base64 import b64decode
from binascii import unhexlify

from core.dkek import decrypt_wrapped_key_blob

dkek = unhexlify('c955af6fb058ca963d270049de57b75b175d528b8993d7651dcc4650097caffb')

wrapped_btc_key = b64decode('MIIDmgSCAWsq+hIeh2Sh4wwACgQAfwAHAgICAgMAAAAAAAD77eNCj1t91Mua52diw59H0T6Tzh5YHLwchYH2bdmkcEeanzjQYy4LYKoUiySfDRRToZO3jLaNFzBiJAsmjfMZNQnNA1BLQ2xRsqsD+njyoerfxxnIEe5w/PYxXIDQRvB2kK34cdQ8klJwUAcDlntnRu3J3z61il9fS28pknNvEjWHTYIfAs1EcYHI38L5m+WAwZRnAacmFKYci/qx2Dhr7hThe4YRDs2RDZ74gb0jLI0GXvF+vd0p2BLflDNrOMbAQUSBikvT0Ymmhaj+zDThKxO5YmjrKNZrIZzcKrCnxQmW2DjKPLqarFGnAidvb4X7Zh2QjVXGEIuTL7sk0j+mNGoSGcLRiSDbBdDUuPlIC+AlzTs7UrrjJPt3r6GGO4S6u4GMzsbBHkjQ9P6cWz71v5WL4Kvg3zlgDPSJg4iEwDWexbKlbtcqZKfOx3mAPnCgPzARDAhidGMtdGVzdAMCBsAEAQEwHgQUHqLd4val5FDLOR4HPSkZ5YKXOu8DAwcwgAIBAaEKMAgwAgQAAgIBAGeCAeZ/IYIBjH9OggFEXykBAEIJVVRDQTAwMDAxf0mCAR0GCgQAfwAHAgICAgOBIP////////////////////////////////////7///wvgiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeEQQR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEg62ncmo8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4hSD////////////////////+uq7c5q9IoDu/0l6M0DZBQYZBBMVyUGiT86hQrZggbxlYXRx31rSHlv+fvTI0bg2FBXjQ5nm3ehW3ArQNey0vmmPmUW5r7o4z5Qtvl8abBAgQbwyHAQFfIBBERU5LMDEwNTcwMjAwMDAxXzdArSgL7wOlmTg0H23YqlL++ecAuweRcwBuHjgkVb6O1Xz6AYFXOJz3tWFJZUDnzDpnhwO+3QzJsJa3Th160atDCUIQREVOSzAxMDU3MDIwMDAwMF83QDffl33UAw8bnZFpMAFHJeq5JBORE407b/4OkHATgmSHGo8cvy7d4DLl0VypiS4yIceTv0ohbZFiLy/Kya2DK+M='.encode('ascii'))

class TestKeyWrapping(unittest.TestCase):
    
    def test_encryption_of_wrapped_btc_key(self):
        decrypt_wrapped_key_blob(dkek, wrapped_btc_key)
        self.assertEqual(True, True)

if __name__ == '__main__':
    unittest.main()