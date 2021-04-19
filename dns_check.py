import pickle
import zipfile

import os
import base64
import json
import time
import argparse
import requests
from itertools import cycle
from random import shuffle
from tqdm import tqdm

import virustotal3.errors
import virustotal3.core

API_KEYS = ['8ac2028878771ef100e894fefae64539ebdd75c62bd2daf51aae35a0798841c7',
'5979f1b50cc8ba8eb0c429e67524b604e7ebe3224903e1adcea8569b42cae175',
'08f6265afa1b95f02cdb73ee13cc3f47b7638122aacc134294752d8d5935f8d6',
'1d543117e558521ff6cf9f2e91309e991408a675da4350c0f3acf6db4a98f5c3',
'146dbd778782d57255c9552ba4b34dd31851d915594a310db9cb05dc0359b507',
'4c0eae034acdf3b3ab0e968ae094e58aca531cb27d447dcef8f77a55355cb5d4']

def load_VT_keys(api_keys_file):	
	API_KEYS = list()
	with open (api_keys_file, 'r') as fp:
		for line in fp:
			API_KEYS.append(str(line.strip("\n")))
	shuffle(API_KEYS)
	key_cycle = cycle(API_KEYS)
	return key_cycle

def get_report_url(url, APIKEY):
    vt_files = virustotal3.core.URL(APIKEY)
    info = vt_files.info_url(url, 10)
    json_data = json.loads(json.dumps(info))
    return json_data

parser = argparse.ArgumentParser("python script.py <dnsFile> <resultsFile>")
parser.add_argument("dnsFile", help="directory of dns pickle file", type=str)
parser.add_argument("resultsFile", help="directory of the result pickle file", type=str)
args = parser.parse_args()

with open(args.dnsFile, "rb") as f:
    dnss = pickle.load(f)

shuffle(API_KEYS)
key_cycle = cycle(API_KEYS)
maldns = list()
for dns in tqdm(dnss):
    key = next(key_cycle)
    if len(dns) > 0:
        try:
            dnsdata = get_report_url(dns, key)
            if dnsdata.get('data').get('attributes').get('last_analysis_stats').get('malicious') > 0 or \
            dnsdata.get('data').get('attributes').get('last_analysis_stats').get('suspicious') > 0:
                maldns.append(dns)
        except:
            continue
        finally:
            time.sleep(15)

        #print(dns + ': ' + str(dnsdata.get('data').get('attributes').get('last_analysis_stats')))

with open(args.resultsFile, 'wb') as f:
    pickle.dump(maldns, f, pickle.HIGHEST_PROTOCOL)