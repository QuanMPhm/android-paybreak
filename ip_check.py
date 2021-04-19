import pickle
import zipfile

import os
import base64
import json
import time
import requests
import argparse
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

def get_report_ip(ip, APIKEY):
	vt_files = virustotal3.core.IP(APIKEY)
	info = vt_files.info_ip(ip)
	json_data = json.loads(json.dumps(info))
	return json_data

parser = argparse.ArgumentParser("python script.py <masterFile> <ipFile> <resultsFile>")
parser.add_argument("masterFile", help="directory of the full result file", type=str)
parser.add_argument("ipFile", help="directory of ip pickle file", type=str)
parser.add_argument("resultsFile", help="directory of the result pickle file", type=str)
args = parser.parse_args()

with open(args.ipFile, "rb") as f:
    ips = pickle.load(f)

with open(args.masterFile, "rb") as f:
    master_Result = pickle.load(f)

#First, iterate over ip list to find malicious ips
shuffle(API_KEYS)
key_cycle = cycle(API_KEYS)
malips = set()
for ip in tqdm(ips):
    key = next(key_cycle)
    if len(ip) > 0:
        ipdata = get_report_ip(ip, key)
        if ipdata.get('data').get('attributes').get('last_analysis_stats').get('malicious') > 0 or \
        ipdata.get('data').get('attributes').get('last_analysis_stats').get('suspicious') > 0:
            malips.add(ip)
        #print(ip + ': ' + str(ipdata.get('data').get('attributes').get('total_votes')))
    time.sleep(3)


#Next, interate through master result file, find which hashes connected to which malicious IPs
hash_ip_list = list()
for data in tqdm(master_Result) :
    for ip in data[0]:
        hash = ''
        #Iterate first to get hash
        if (ip.find('pcap') == 0):
            hash = ip

        #Iterate again to check if ips called were malicious, if yes, add to res_list
        if (ip.find('pcap') != 0):
            before = len(malips)
            malips.add(ip)
            if before != len(malips):
                malips.remove(ip)
            else:
                hash_ip_list.append([hash, ip])


with open(args.resultsFile, 'wb') as f:
    pickle.dump(hash_ip_list, f, pickle.HIGHEST_PROTOCOL)
