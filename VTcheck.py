#This script gets all unique IPs and DNS, and exports them

import pickle
import zipfile

import os
import base64
import json
import time
import requests
from itertools import cycle
from random import shuffle
from tqdm import tqdm

import virustotal3.errors
import virustotal3.core

r'''
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
    info = vt_files.info_url(url)
    json_data = json.loads(json.dumps(info))
    return json_data

def get_report_ip(ip, APIKEY):
	vt_files = virustotal3.core.IP(APIKEY)
	info = vt_files.info_ip(ip)
	json_data = json.loads(json.dumps(info))
	return json_data
'''
r'''
urlVT = virustotal3.core.URL("1d543117e558521ff6cf9f2e91309e991408a675da4350c0f3acf6db4a98f5c3")
dict = urlVT.info_url(url="https://www.w3schools.com/python/python_tuples.asp")
print(dict)
'''
r'''
if not os.path.exists(r"C:\Users\Quan Minh Pham\Downloads\results") :
    with zipfile.ZipFile(r"C:\Users\Quan Minh Pham\Downloads\results.zip", 'r') as zip_ref:
        zip_ref.extractall(r"C:\Users\Quan Minh Pham\Downloads\results")
'''

IPS = set()
DNS = set()

#Flatten pickled list into IPS and DNS set
with open(r"C:\Users\Quan Minh Pham\Documents\Projects\Ransomware 2020\TestFolder\results_2\results_2.pkl", "rb") as f:
    datas = pickle.load(f)
    for data in datas:
        #print(data[0])
        try: 
            r'''
            #Iterate first to find hash
            hash = ""
            for entry in data[0]:
                #print(type(entry))
                if (entry.find("pcap") == 0):
                    hash = entry
            '''

            #Iterate again to find ips the hash connect to
            for entry in data[0]:
                if not('pcap' in entry):
                    IPS.add(entry)

            
            for entry in data[1]:
                if not('pcap' in entry):
                    DNS.add(entry)
        except:
            continue
       

print(len(IPS))

print(len(DNS))

file_dir = r"C:\Users\Quan Minh Pham\Documents\Projects\Ransomware 2020\TestFolder\results_2"

#keys = load_VT_keys(r"C:\Users\Quan Minh Pham\Documents\Projects\Ransomware 2020\TestFolder\vtkey.txt")

count = 0
file_end = 0
ipset = set()
for ip in IPS:
    ipset.add(ip)
    count = count + 1
    if len(ipset) == 3000 or count == len(IPS):
        #print(ipset)
        f = open(file_dir + r"\ip_folder\unique_ip2_" + str(file_end) + ".pkl", 'wb')
        pickle.dump(ipset, f, pickle.HIGHEST_PROTOCOL)
        ipset.clear()
        f.close()
        file_end = file_end + 1

count = 0
file_end = 0
dnsset = set()
for dns in DNS:
    dnsset.add(dns)
    count = count + 1
    if len(dnsset) == 3000 or count == len(DNS):
        f = open(file_dir + r"\url_folder\unique_dns2_" + str(file_end) + ".pkl", 'wb')
        pickle.dump(dnsset, f, pickle.HIGHEST_PROTOCOL)
        dnsset.clear()
        f.close()
        file_end = file_end + 1

r'''
malip = list()
count = 0
for ip in IPS:
    count += 1
    key = next(keys)
    ipdata = get_report_ip(ip, key)
   
    if urldata.get('data').get('attributes').get('last_analysis_stats').get('malicious') > 10:
        maldns.append(dns)
    
    print(ip + ': ' + str(ipdata.get('data').get('attributes').get('last_analysis_stats')))
    if count == 5:
        break

    time.sleep(10)
'''
r'''
maldns = list()
for dns in DNS:
    count += 1
    key = next(keys)
    if len(dns) > 0:
        dnsdata = get_report_url(dns, key)
        if dnsdata.get('data').get('attributes').get('last_analysis_stats').get('malicious') > 0:
            maldns.append(dns)
        print(dns + ': ' + str(dnsdata.get('data').get('attributes').get('total_votes')))

    time.sleep(15)

with open(file_dir + r"ipfolder\unique_ip_" + str(file_end) + ".pkl", 'wb') as f:
            pickle.dump(ipset, f, pickle.HIGHEST_PROTOCOL)
        ipset.clear()

#print(maldns)
'''


r'''
KEYS = load_VT_keys("")
for ip in IPS:
    key = next(KEYS)
    get_report_url()

for dns in DNS:
    key = next(DNS)
    dns_data = get_report_url(dns, key)
'''

