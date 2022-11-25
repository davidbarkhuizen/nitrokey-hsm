import random, key_utils

private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
print key_utils.privateKeyToWif(private_key)
print key_utils.keyToAddr(private_key)

