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

def get_report_url(url, APIKEY):
    vt_files = virustotal3.core.URL(APIKEY)
    info = vt_files.info_url(url, 10)
    json_data = json.loads(json.dumps(info))
    return json_data

filename = r"C:\Users\Quan Minh Pham\Documents\Projects\Ransomware 2020\TestFolder\results_3\mal_ip_reports.pkl"
output = r"C:\Users\Quan Minh Pham\Documents\Projects\Ransomware 2020\android-paybreak\questions\q2_dns_pickle.pkl"

filtered_flags = list()

with open(filename, "rb") as f:
    # fulltext = f.read()
    # textarr = fulltext.split('\n')
    # textarr = textarr[:(len(textarr)-1)]
    # print(textarr)
    dnss = pickle.load(f)
    for dns in dnss:
        report = dns[1].get('data').get('attributes').get('last_analysis_stats')
        print(report)
        if (report.get('malicious') + report.get('suspicious')) >= 7:
            filtered_flags.append(dns[0])
    # print(dnss[0][1].get('data').get('attributes').get('last_analysis_stats'))
print(len(filtered_flags))

# with open(output, 'wb') as f2:
#     pickle.dump(textarr, f2, pickle.HIGHEST_PROTOCOL)
    

# shuffle(API_KEYS)
# key_cycle = cycle(API_KEYS)
# comps = set()
# for dns in dnss:
#     key = next(key_cycle)
#     if len(dns) > 0:
#         dnsdata = get_report_url(dns, key)
#         comps.add(dnsdata.get('data').get('attributes').get('as_owner'))

# print(comps)
