from muid.economics import muid_perforance_report, muid_digits_per_dollar, relative_sha_difficulty, \
    bitcoin_digits_per_dollar, EFFICIENCY, HASH_RATIO
from muid import MIN_LEN
import json

def test_per_sec():
    muid_perforance_report(min_len=8)

def test_economics():
    report = {'min_len':MIN_LEN,
              'muid_dpd':muid_digits_per_dollar(),
              'bitcoin_dpd':bitcoin_digits_per_dollar(),
              'sha256_ratio':relative_sha_difficulty(),
              'efficiency':EFFICIENCY,
              'hash_ratio':HASH_RATIO}
    with open("economics.json","w") as f:
        json.dump(report,f)


