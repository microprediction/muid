import muid

def test_binary():
    key = b'5ac8e9f7e58181a384951460e8da1a73'
    nml = muid.animal(key)
    assert nml == 'Leadable Boa'

def test_str():
    key = '5ac8e9f7e58181a384951460e8da1a73'
    nml = muid.animal(key)
    assert nml == 'Leadable Boa'