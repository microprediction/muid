
from muid.corpus import Corpus
from contexttimer import Timer

def test_ring():
    with Timer() as t1:
        corpus = Corpus.words()
    with Timer() as t2:
        corpus = Corpus.words()
    ratio = t1.elapsed/t2.elapsed
    assert ratio>2, "Caching isn't helping "

def test_corpus():
    mx = Corpus.max_phrase_len()
    mn = Corpus.min_word_len()
    for k in range(mn,mx+1):
        num_words = len(Corpus.words_of_len(k))
        num_phrases = len(Corpus.phrases_of_len(k))
        print((k,num_words,num_phrases))


