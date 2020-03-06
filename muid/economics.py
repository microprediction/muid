import requests, math, json, timeit
from hashlib import sha1, sha256
from contexttimer import Timer
from muid.memorable import Memorable
from muid import MIN_LEN


# Summary: these calculations, open to critique, suggest that mining MUIDs is 5x more profitable than bitcoin even
# before any attempt at optimizing the slow Python mining algorithm is attempted. They also suggest that mining MUIDs
# could be a hundred times more economical than bitcoin - assuming the current price remains at $0.10 USD per MUID and
# the min_len parameter at https://www.microprediction.com/config.json is not changed. There are lots of caveats and we
# welcome challenges to these estimates.

# -----------------------------------------------------------------------
#   (1) Mining economics set against bitcoin - for the ambitious hacker
# -----------------------------------------------------------------------

# So you are thinking ... this Python miner is dreadful. How much money could I make if I wrote a good one?

def bitcoin_digits_per_dollar():
    """ Pretend bitcoin hashing is a lever that pays $1 if you win a hash.
        This reports the equivalent number of hex digits you have to get right by accident.
    """
    bitcoin_price      = float(requests.get('https://blockchain.info/ticker').json()['USD']['last'])
    bitcoin_difficulty = float(requests.get('https://blockexplorer.com/api/status?q=getDifficulty').json()['difficulty'])
    bitcoin_hash_odds  = bitcoin_difficulty* ( 2**48) / ( 2** 16 -1 )
    bitcoin_hex_digits = math.log(bitcoin_hash_odds) / math.log(16)
    bitcoin_hex_digits_one_dollar = bitcoin_hex_digits - math.log(bitcoin_price *12.5 ) /math.log(16)
    return bitcoin_hex_digits_one_dollar    # Ans: 14.7

def muid_digits_per_dollar():
    """ As above except for MUIDs ... """
    muid_price = 0.1
    muid_hex_digits = MIN_LEN
    num_phrases = len(Memorable.phrases_of_len(MIN_LEN)) + len(Memorable.words_of_len(MIN_LEN))
    muid_hex_digits_one_dollar = muid_hex_digits - math.log(num_phrases*muid_price) / math.log(16)
    return muid_hex_digits_one_dollar

def bitcoin_hashes_per_muid_hash():
    """ Returns the ratio of dollars made per hash call when mining MUID versus bitcoin """
    # However note that at time of writing, MUID uses SHA-1 which is faster than SHA-256 so this underestimates the eventual advantage
    return 16**(bitcoin_digits_per_dollar( ) /muid_digits_per_dollar())

HASH_RATIO = bitcoin_hashes_per_muid_hash()

# --------------------------------------------------------------------------------
#    (2) Mining economics set against bitcoin - using muid.mine() out of the box
# --------------------------------------------------------------------------------

# Well so much for theory ... but what will my earnings be as a ratio to bitcoin if I just
# use the provided miner?

def muid_implementation_inefficiency():
    """ Returns the speed of bitcoin hashing """
    optimized_sha2_hash_seconds = 3.8 *(10**-8)
    muid_performance_report = muid_perforance_report(min_len=7)

def muid_default_hash_per_second():
    """ Estimate the actual number of hashes per second in muid.mining, prior to optimizations """
    t1 = timeit.timeit(setup="import uuid", stmt="str(uuid.uuid5(uuid.NAMESPACE_DNS, 'laksjdf'))", number=10000 ) /10000
    t2 = timeit.timeit(setup="import uuid", stmt="uuid.uuid4()", number=10000 ) /10000
    hash_throughput = int(1./(t1 +t2))
    # Check that looking up the word hits is immaterial...
    t3 = timeit.timeit( setup="import binascii, os; ss = set([str(binascii.b2a_hex(os.urandom(8))) for _ in range(100000)]); bb = set([str(binascii.b2a_hex(os.urandom(8))) for _ in range(48000)])",stmt="any(s in bb for s in ss)", number=100)/100
    assert t3<0.1, "Hmmm, that lookup took a lot longer than I thought"
    return hash_throughput     # Ans: about 100,000 hashes per second

def muid_perforance_report(min_len):
    """ Use this to test for variation by batch size """
    performance = dict()
    for batch_size in [100000 ,1000000]:
        with Timer() as t:
            gen = Memorable.key_generator(min_len=min_len, verbose=True, batch_size=batch_size, timeout=100)
            report = next(gen)
            num_attempts = report['num_attempts']
        num_seconds = t.elapsed
        performance[batch_size] = num_attempts / num_seconds
    with open("batch_size_report.json" ,"w") as f:
        json.dump(performance ,f)
    return performance

REPORTED_HASH_PER_SECOND_PER_CPU = 2000000
IMPLEMENTATION_INEFFICIENCY = REPORTED_HASH_PER_SECOND_PER_CPU/ muid_default_hash_per_second()
EFFICIENCY = {"cpu":HASH_RATIO / IMPLEMENTATION_INEFFICIENCY}  # TODO: GPU

# --------------------------------------------------------------------------------
#    (3) Miscelleneous comparisons
# --------------------------------------------------------------------------------

def relative_sha_difficulty():
    """ Quick look at hashlib versus uuid.uuid5 """
    # Going via UUID constructor might not be the best :)
    t0 = timeit.timeit(setup="import uuid", stmt="str(uuid.uuid5(uuid.NAMESPACE_DNS, 'laksjdf'))", number=1000)
    t1 = timeit.timeit(setup="from hashlib import sha1, sha256; import uuid; s='should we use 256 instead?'", stmt="str(uuid.UUID(sha256(s.encode('utf-8')).hexdigest()[:32]))",number=1000)
    t2 = timeit.timeit(setup="from hashlib import sha1, sha256; s='should we use 256 instead?'.encode('utf-8')", stmt="sha256('some string'.encode('utf-8')).hexdigest()",number=1000)
    return (t1/t0,t2/t0)

