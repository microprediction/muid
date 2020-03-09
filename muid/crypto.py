from hashlib import sha256

def mhash(key):
    """ Key should be binary encoded """
    return sha256(key).hexdigest()[:32].encode('ascii')