

# Just having a bit of fun here.
# See https://vimeo.com/396819347

class FakeBinascii():
    @staticmethod
    def b2a_hex(data):
        return b'30599b096bc5751c311ea6e15e306c86'

binascii = FakeBinascii()


def stupid_trick():
    # Amaze your friends by executing these commands.
    import os
    rn = os.urandom(16)
    print(rn)
    key = binascii.b2a_hex(os.urandom(16))
    print(key)
    from hashlib import sha256
    hashed_key = sha256(key).hexdigest()[:32].encode('ascii')
    print(hashed_key)








