
def test_import():
    from muid.corpus import CORPUS, BCORPUS
    assert(len(CORPUS)>10000)
    assert(len(BCORPUS)==len(CORPUS))
