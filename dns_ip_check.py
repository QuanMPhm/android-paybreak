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

API_KEYS = ['9bdee1eb9c8d0174c9228a3cb3a3492432f93bf61e1379f1a1c8af5cf298e928']

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

def get_report_ip(ip, APIKEY):
	vt_files = virustotal3.core.IP(APIKEY)
	info = vt_files.info_ip(ip)
	json_data = json.loads(json.dumps(info))
	return json_data

parser = argparse.ArgumentParser("python script.py <mode> <inputFile> <resultsFile>")
parser.add_argument("mode", help="I for IP, D for Domain scan", type=str)
parser.add_argument("inputFile", help="directory of data pickle file", type=str)
parser.add_argument("resultsFile", help="directory of the result pickle file", type=str)
args = parser.parse_args()

if (args.mode != "I" and args.mode != "D"):
    print('Invalid mode, chose I or D')
else:
    with open(args.inputFile, "rb") as f:
        datas = pickle.load(f)

    count = 0
    maldns = list()
    for data in (datas):
        key = API_KEYS[0]
        print(count)
        if (count > 2):
            break

        if len(data) > 0:
            try:
                if (args.mode == "I"):
                    json_data = get_report_ip(data, key)
                else:
                    json_data = get_report_url(data, key)
                
                print(json_data)
                maldns.append([data, json_data])
                count += 1
                # if json_data.get('data').get('attributes').get('last_analysis_stats').get('malicious') > 0 or \
                # json_data.get('data').get('attributes').get('last_analysis_stats').get('suspicious') > 0:
                #     maldns.append([data, json_data])
                #     count += 1
            except:
                continue
            finally:
                time.sleep(5)

    with open(args.resultsFile, 'wb') as f:
        print(maldns)
        pickle.dump(maldns, f, pickle.HIGHEST_PROTOCOL)
