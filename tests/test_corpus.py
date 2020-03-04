
from muid.corpus import Corpus
from contexttimer import Timer

def test_ring():
    with Timer() as t1:
        corpus = Corpus.words()
    with Timer() as t2:
        corpus = Corpus.words()
    ratio = t1.elapsed/t2.elapsed
    assert ratio>2, "Caching isn't helping "




