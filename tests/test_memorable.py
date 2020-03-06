from muid.memorable import muid4, mverify, Memorable
from itertools import zip_longest

def test_split():
    q_and_a = {'ecocod':['eco','cod'],
               'feltedcafe':['felted','cafe']}
    for q,a in q_and_a.items():
        a1 = Memorable.split(readable_phrase=q)
        assert all( a1_==a_ for a1_, a_ in zip_longest(a1,a) )

def test_uuid4():
    min_len = 8
    key = muid4(min_len=min_len,timeout=10)
    verified = mverify(key=key,min_len=min_len)
    assert verified

