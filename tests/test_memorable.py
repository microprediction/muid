from muid.memorable import muid4, mverify

def test_uuid4():
    min_len = 4
    key = muid4(min_len=min_len,timeout=150)
    verified = mverify(key=key,min_len=min_len)
    assert verified