import requests, math, json, timeit, hashlib
from contexttimer import Timer
from muid.memorable import Memorable
from muid import MIN_LEN

# -----------------------------------------------------
#     Transparent mining economics versus bitcoin
# -----------------------------------------------------

# Part 1: A look at relative economics per hash call
#         This might be relevant ... eventually ... once the muid mining is made performant.

def bitcoin_digits_per_dollar():
    """ Pretend bitcoin hashing is a lever that pays $1 if you win a hash.
        This reports the equivalent number of hex digits you have to get right by accident.
    """
    bitcoin_price      = float(requests.get('https://blockchain.info/ticker').json()['USD']['last'])
    bitcoin_difficulty = float(requests.get('https://blockexplorer.com/api/status?q=getDifficulty').json()['difficulty'])
    bitcoin_hash_odds  = bitcoin_difficulty* ( 2**48) / ( 2** 16 -1 )
    bitcoin_hex_digits = math.log(bitcoin_hash_odds) / math.log(16)
    bitcoin_hex_digits_one_dollar = bitcoin_hex_digits - math.log(bitcoin_price *12.5 ) /math.log(16)
    return bitcoin_hex_digits_one_dollar

def muid_digits_per_dollar():
    """ As above except for MUIDs ... """
    muid_price = 0.1
    muid_hex_digits = MIN_LEN
    num_phrases = len(Memorable.phrases_of_len(MIN_LEN)) + len(Memorable.words_of_len(MIN_LEN))
    muid_hex_digits_one_dollar = muid_hex_digits - math.log(num_phrases *muid_price) / math.log(16)
    return muid_hex_digits_one_dollar

def bitcoin_hashes_per_muid_hash():
    """ Returns the ratio of dollars made per hash call when mining MUID versus bitcoin """
    return 16**(bitcoin_digits_per_dollar( ) /muid_digits_per_dollar())

def muid_implementation_inefficiency():
    """ Returns the speed of bitcoin hashing """
    optimized_sha2_hash_seconds = 3.8 *(10**-8)
    muid_performance_report = muid_perforance_report(min_len=7)

def muid_default_hash_per_second():
    t1 = timeit.timeit(setup="import uuid", stmt="str(uuid.uuid5(uuid.NAMESPACE_DNS, 'laksjdf'))", number=10000 ) /10000
    t2 = timeit.timeit(setup="import uuid", stmt="uuid.uuid4()", number=10000 ) /10000
    hash_throughput = int(1./(t1 +t2))  # about 100,000
    t3 = 10 /timeit.timeit(setup="ss = ['sally' for _ in range(1000)]; bb = ['laskdfaj' for _ in range(100000)]", stmt="any(s in bb for s in ss" ,number=10)
    # Comparison time is also roughly 1 second, hence...
    return hash_throughput /2




def muid_perforance_report(min_len):
    performance = dict()
    for batch_size in [100000 ,1000000]:
        with Timer() as t:
            gen = Memorable.key_generator(min_len=min_len, verbose=True, batch_size=batch_size, timeout=100)
            report = next(gen)
            num_attempts = report['num_attempts']
        num_seconds = t.elapsed
        performance[batch_size] = num_attempts / num_seconds
    with open("attempts_per_second.json" ,"w") as f:
        json.dump(performance ,f)
    return performance