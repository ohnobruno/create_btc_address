from create_btc_address import private_key_to_btc_public_key
from dormant_add import PublicKeyAddress
import secrets
import random

# "you can't score if you don't play"
# chances etwas 0.000000000000000000000000000000000000684%
while True:
    ### crypto secure random
    # private_key = secrets.token_hex(32)
    ### not secure random
    private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])

    public_key = private_key_to_btc_public_key(private_key)
    print("Checking: " + public_key + "(" + private_key + ")")

    if public_key in PublicKeyAddress:
        print("private_key: " + private_key + ", public_key: " + public_key)
        break


