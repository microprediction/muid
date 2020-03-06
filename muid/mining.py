from muid.memorable import Memorable
import Algorithmia, requests, pprint, math, json, timeit, hashlib
from contexttimer import Timer

def get_official_min_len():
    return int(requests.get('https://www.microprediction.com/config.json').json()["min_len"])

MIN_LEN = get_official_min_len()
DIFFICULTY = MIN_LEN


#------------------------------------------------------------------
#     An inefficient mining algorithm you are welcome to improve
#------------------------------------------------------------------

def mine(timeout=1000000000, min_len=MIN_LEN):
    print("min_len set to " + str(MIN_LEN), flush=True)
    gen = Memorable.key_generator(min_len=min_len, timeout=timeout, verbose=True)
    for report in gen:
        print(report, flush=True)

def mine_and_sell( timeout=60*60*24*30, algo='microprediction/motza', api_key="sim1uUcA8tlyE1X4M11jQFD4l/o1", email="purchases@microprediction.com"):
    """ Mine for MUID and immediately sell them to the buyer on Algorithmia

    Before running this do the following:
        (1) Sign up for algorithmia account at www.algorithmia.com/signup
        (2) Enter your Algorithmia API key below. See  https://algorithmia.com/developers/platform/customizing-api-keys#default-api-key
        (3) Publish a public algorithm on Algorithmia and set the price at 1000 credits.
    More instructions at https://algorithmia.com/algorithms/microprediction/mverify/docs

    """

    client = Algorithmia.client(api_key = api_key)
    gen = Memorable.key_generator(min_len=MIN_LEN, timeout=timeout, verbose=True)
    print("Difficulty set to " + str(MIN_LEN), flush=True)
    for report in gen:
        # Found one !
        print(report,flush=True)
        key = report["key"]
        input = {'key':key, 'algoRef':algo}
        if email:
            input.update({"email":email})
        # Sell it
        pprint.pprint(input)
        try:
            message = client.algo('microprediction/mverify').pipe(input).result
            pprint(message)
            print("Sold! ")
        except Exception as e:
            pprint(str(e))
            print('There was some problem selling the MUID ')



