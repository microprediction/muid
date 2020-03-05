import muid

def test_mnemonic():
    key = '22278208-bb81-424a-9102-400debcf46bd'
    memorable = muid.mnemonic(key)
    print(memorable)