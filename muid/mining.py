from muid.explanation import TITLE, EXPLANATION
import requests, pprint, time, binascii, os
from muid.corpus import BCORPUS, to_readable_hex
from muid.crypto import mhash

def get_official_min_len():
    return int(requests.get('https://www.microprediction.com/config.json').json()["min_len"])

MIN_LEN = get_official_min_len()

#------------------------------------------------------------------
#     A mining algorithm you are welcome to improve
#------------------------------------------------------------------


def mine(timeout=1000000000,skip_intro=False,quota=16):
    """ Mine for keys of increasing length """
    start_time = time.time()
    difficulty = 6
    count = 0

    if skip_intro:
        print( "Starting to mine ...", flush=True )
        print( "Control-C to stop ... ")
        print( " ")
    else:
        print(TITLE,flush=True)
        time.sleep(1)
        found_during_explanation = list()
        for ln in EXPLANATION:
            print(ln,flush=True)
            for _ in range(int(len(ln)/3)):
                found, difficulty, count = mine_once(difficulty,count,quota)
                found_during_explanation.extend(found)

        for q in found_during_explanation:
            time.sleep(3)
            pprint.pprint(q)
            print(" ",flush=True)

    while time.time()<start_time+timeout:
        found, difficulty, count = mine_once(difficulty,count,quota)
        if found:
            pprint.pprint(found[0])
            print(" ", flush=True)
            time.sleep(1)

def mine_once(difficulty,count,quota):

    keys         = [ binascii.b2a_hex(os.urandom(16)) for _ in range(100000) ]
    hashed_keys  = [ mhash(key) for key in keys ]
    short_codes  = [ hk[:difficulty]   for hk in hashed_keys ]
    longer_codes = [ hk[:difficulty+1] for hk in hashed_keys]
    candidates   = dict( zip(short_codes,keys) )
    long_candidates = dict( zip( longer_codes, keys) )

    if any( code in BCORPUS for code in short_codes ):
        for c,key in candidates.items():
            ks = BCORPUS.get(c)
            if ks is not None:
                report = report_finding(key=key,c=c,ks=ks)
                count = count+1
                if count==quota:
                    difficulty = difficulty+1
                    count = 0
    elif any( longer_code in BCORPUS for longer_code in longer_codes ):
        for c,key in long_candidates.items():
            ks = BCORPUS.get(c)
            if ks is not None:
                report = report_finding(key=key,c=c,ks=ks)
                difficulty = difficulty+1
                count = 1
    else:
        report = []
    return report, difficulty, count


def report_finding(key,c,ks):
    k1, k2 = ks
    w1 = c[:k1]
    w2 = c[k1:k1 + k2]
    a1 = w1.decode('ascii')
    a2 = w2.decode('ascii')
    r1 = to_readable_hex(a1)
    r2 = to_readable_hex(a2)
    pretty = r1[0].upper() + r1[1:] + ' ' + r2[0].upper() + r2[1:]
    longest_found = k1 + k2
    full_code = mhash(key)
    response = [{"length": longest_found, "pretty": pretty, "key": key, "hash": full_code}]
    return response
