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

import numpy as np
import matplotlib.pyplot as plt

import virustotal3.errors
import virustotal3.core

API_KEYS = ['8ac2028878771ef100e894fefae64539ebdd75c62bd2daf51aae35a0798841c7',
'5979f1b50cc8ba8eb0c429e67524b604e7ebe3224903e1adcea8569b42cae175',
'08f6265afa1b95f02cdb73ee13cc3f47b7638122aacc134294752d8d5935f8d6',
'1d543117e558521ff6cf9f2e91309e991408a675da4350c0f3acf6db4a98f5c3',
'146dbd778782d57255c9552ba4b34dd31851d915594a310db9cb05dc0359b507',
'4c0eae034acdf3b3ab0e968ae094e58aca531cb27d447dcef8f77a55355cb5d4']

def func(i):
    return i[1]

def get_report_ip(ip, APIKEY):
	vt_files = virustotal3.core.IP(APIKEY)
	info = vt_files.info_ip(ip)
	json_data = json.loads(json.dumps(info))
	return json_data

def writeToFile(datas, fdir, fname):
    f = open(fdir + fname, 'w')
    for data in datas:
        try:
            f.write(str(data))
            f.write('\n')
        except:
            for char in str(data):
                try:
                    f.write(char)
                except:
                    pass
            f.write('\n')   
    f.close()

def get_report_url(url, APIKEY):
    vt_files = virustotal3.core.URL(APIKEY)
    info = vt_files.info_url(url, 10)
    json_data = json.loads(json.dumps(info))
    return json_data

def get_relationship_url(url, APIKEY, relation):
    vt_files = virustotal3.core.URL(APIKEY)
    info = vt_files.get_relationship(url, relation)
    json_data = json.loads(json.dumps(info))
    return json_data

def get_local_url(url, APIKEY):
    vt_files = virustotal3.core.URL(APIKEY)
    info = vt_files.get_network_location(url)
    json_data = json.loads(json.dumps(info))
    return json_data

def plotting(x, y, minx, maxx, miny, maxy, pxlabel, pylabel, ptitle):
    f, (ax, ax2) = plt.subplots(2, 1, sharex=True)
    ax.bar(x, y)
    ax2.bar(x, y)
    plt.subplot(2, 1, 1)
    plt.title(ptitle)
    plt.subplot(2, 1, 2)
    plt.xlabel(pxlabel)
    plt.ylabel(pylabel)

    # zoom-in / limit the view to different portions of the data
    ax.set_ylim(miny, maxy)  # outliers only
    ax2.set_ylim(minx, maxx)  # most of the data

    # hide the spines between ax and ax2
    ax.spines['bottom'].set_visible(False)
    ax2.spines['top'].set_visible(False)
    ax.xaxis.tick_top()
    ax.tick_params(labeltop=False)  # don't put tick labels at the top
    ax2.xaxis.tick_bottom()

    d = .015  # how big to make the diagonal lines in axes coordinates
    # arguments to pass to plot, just so we don't keep repeating them
    kwargs = dict(transform=ax.transAxes, color='k', clip_on=False)
    ax.plot((-d, +d), (-d, +d), **kwargs)        # top-left diagonal
    ax.plot((1 - d, 1 + d), (-d, +d), **kwargs)  # top-right diagonal

    kwargs.update(transform=ax2.transAxes)  # switch to the bottom axes
    ax2.plot((-d, +d), (1 - d, 1 + d), **kwargs)  # bottom-left diagonal
    ax2.plot((1 - d, 1 + d), (1 - d, 1 + d), **kwargs)  # bottom-right diagonal

def get_answers(master_Result, malips, maldnss, resultsDir, n):
    fdir = resultsDir + '\\'

    # #Next, interate through master result file, find which hashes connected to which malicious IPs/DNSs
    # hashes = set()
    # hash_ip_list = list()
    # hash_dns_list = list()
    # ip_errorcount = 0
    # dns_errorcount = 0
    # for data in tqdm(master_Result):
        
    #     try:
    #         for ip in data[0]:
    #             #Iterate first to get hash
    #             if ('pcap' in ip):
    #                 hashe = ip
    #                 hashes.add(hashe)

    #         for ip in data[0]:
    #             #Iterate again to check if ips called were malicious
    #             if not('pcap' in ip):
    #                 before = len(malips)
    #                 malips.add(ip)
    #                 if before != len(malips):
    #                     malips.remove(ip)
    #                 else:
    #                     hash_ip_list.append([hashe, ip])
    #     except:
    #         ip_errorcount+=1
    #         pass
        
    #     try:
    #         for dns in data[1]:
    #             #Iterate first to get hash
    #             if ('pcap' in dns):
    #                 hashe = dns

    #         for dns in data[1]:
    #             #Iterate again to check if dns called were malicious
    #             if not('pcap' in dns):
    #                 before = len(maldnss)
    #                 maldnss.add(dns)
    #                 if before != len(maldnss):
    #                     maldnss.remove(dns)
    #                 else:
    #                     hash_dns_list.append([hashe, dns])
    #     except:
    #         dns_errorcount+=1
    #         pass

    # print("hashes: " + str(len(hashes)))
    # print("hash_ip: " + str(len(hash_ip_list)))
    # print("hash_dns: " + str(len(hash_dns_list)))
    # #question 1, flagged hashes
    # question_1 = set()

    # for duo in hash_ip_list:
    #     question_1.add(duo[0])

    # for duo in hash_dns_list:
    #     question_1.add(duo[0])

    # print("Q1, n: " + str(len(question_1)) + ', ' + str(n))

    # writeToFile(question_1, fdir, 'q1.txt')

    #question 2, "if an apk made contact to a malicious ip or dns, which ones were they"
    question_2_ip = malips.copy()
    question_2_dns = maldnss.copy()
    print("Q2-IP: " + str(len(question_2_ip)))
    print("Q2-DNS: " + str(len(question_2_dns)))
    writeToFile(question_2_ip, fdir, 'q2_ip.txt')
    writeToFile(question_2_dns, fdir, 'q2_dns.txt')
    # #question 3, "if a particular malicious ip or dns has been made contact by an apk, which apks were they?"

    # #question 4, "what is the number of apks which made no contact to any malicious IP/dns and what are their hashes"
    # question_4 = hashes.copy()
    # for duo in hash_ip_list:
    #     question_4.discard(duo[0])

    # for duo in hash_dns_list:
    #     question_4.discard(duo[0])
    # print("Q4: " + str(len(question_4)))
    # writeToFile(question_4, fdir,  'q4.txt')

    # #question 5, "are there any apks that made contact to multiple malicious ips or domains, if so, how many what are their hashes"
    # temp = set()
    # question_5 = set()
    # for duo in hash_ip_list:
    #     before = len(temp)
    #     temp.add(duo[0])
    #     if (before == len(temp)):
    #         question_5.add(duo[0])

    # for duo in hash_dns_list:
    #     before = len(temp)
    #     temp.add(duo[0])
    #     if (before == len(temp)):
    #         question_5.add(duo[0])

    # print("Q5: " + str(len(question_5)))
    # writeToFile(question_5, fdir, 'q5.txt')

    # #question 6, "are there any common ips/domains that have been made contact with by multiple apks, 
    # # if so, how many ips and domains what are their addresses/domain names"
    # temp = set()
    # question_6_ip = set()
    # question_6_dns = set()
    # for duo in hash_ip_list:
    #     before = len(temp)
    #     temp.add(duo[1])
    #     if (before == len(temp)):
    #         question_6_ip.add(duo[1])

    # for duo in hash_dns_list:
    #     before = len(temp)
    #     temp.add(duo[1])
    #     if (before == len(temp)):
    #         question_6_dns.add(duo[1])

    # print("Q6_IP: " + str(len(question_6_ip)))
    # print("Q6_DNS: " + str(len(question_6_dns)))
    # writeToFile(question_6_ip, fdir, 'q6_ip.txt')
    # writeToFile(question_6_dns, fdir, 'q6_dns.txt')

    #question 7, Graphing
    #First graph, hash vs ip
    # question_7_hashes = list()

    # #Copy list of ALL UNIQUE hashes, change to unique hashes if for whatever anylsis or what the hell whaterver
    # for hashs in (hashes):
    #     question_7_hashes.append(hashs)
    
    # question_7_count_a = [0] * len(hashes)
    # #See how many times each flagged hash appears in hash_ip_list
    # for duo in hash_ip_list:
    #     found_hash = duo[0]
    #     index = question_7_hashes.index(found_hash)
    #     question_7_count_a[index] += 1

    # #Join the hash and hash count together
    # question_7_a = list()
    # for i in range(0, len(question_7_hashes)):
    #     question_7_a.append([question_7_hashes[i], question_7_count_a[i]])

    # def func(i):
    #     return i[1]

    # def findLargest(i):
    #     m = 0
    #     for duo in i:
    #         if duo[1] > m:
    #             m = duo[1]
    #     return m

    # #print("Q7-A: " + str(question_7_a[0:10]))
    # #Here, we're including 0-col
    # max_num = findLargest(question_7_a)
    # x_1 = range(0, max_num+1)
    # y_1 = [0] * len(x_1)
    # for duo in question_7_a:
    #     count = duo[1]
    #     y_1[count] += 1

    # plotting(x_1, y_1, 0, 500, 9000, 11000,  "No. of flagged IPs requested in AVD", "No. of AVD", "Distribution of flagged IPs requested per AVD: n = " + str(n))

    # # fig1 = plt.figure(num=1, figsize = (10, 5))
    
    # # # creating the bar plot
    # # plt.bar(x_1, y_1, color ='maroon', width = 0.4)
    
    # # plt.xlabel("No. of flagged IPs requested in AVD")
    # # plt.ylabel("No. of AVD")
    # # plt.title("Distribution of flagged IPs requested per AVD: n = " + str(n))

    # #Second Graph, hash vs dns
    # question_7_count_b = [0] * len(hashes)

    # for duo in hash_dns_list:
    #     found_hash = duo[0]
    #     index = question_7_hashes.index(found_hash)
    #     question_7_count_b[index] += 1

    # question_7_b = list()
    # for i in range(0, len(question_7_hashes)):
    #     question_7_b.append([question_7_hashes[i], question_7_count_b[i]])

    # max_num = findLargest(question_7_b)
    # x_2 = range(0, max_num+1)
    # y_2 = [0] * len(x_2)

    # for duo in question_7_b:
    #     count = duo[1]
    #     y_2[count] += 1

    # plotting(x_2, y_2, 0, 500, 9000, 11000,  "No. of flagged DNSs requested in AVD", "No. of AVD", "Distribution of flagged DNSs requested per AVD: n = " + str(n))
    # # fig2 = plt.figure(num=2, figsize = (10, 5))
    
    # # # creating the bar plot
    # # plt.bar(x_2, y_2, color ='maroon',
    # #         width = 0.4)
    
    # # plt.xlabel("No. of flagged DNSs requested in AVD")
    # # plt.ylabel("No. of AVD")
    # # plt.title("Distribution of flagged DNSs requested per AVD: n = " + str(n))

    # #Graph 3

    # def func2(i):
    #     return i[0]

    # question_7_a.sort(key=func2)
    # question_7_b.sort(key=func2)
    # question_7_c = list()
    # for i in range(0, len(question_7_a)) :
    #     question_7_c.append([question_7_a[i][0], question_7_a[i][1] + question_7_b[i][1]])

    # max_num = findLargest(question_7_c)
    # x_3 = range(0, max_num+1)
    # y_3 = [0] * len(x_3)

    # for duo in question_7_c:
    #     count = duo[1]
        
    #     y_3[count] += 1

    # plotting(x_3, y_3, 0, 500, 9000, 11000,  "No. of flagged IPs and DNSs requested in AVD", "No. of AVD", "Distribution of flagged IPs and DNSs requested per AVD: n = " + str(n))

    # #print(y_3)
    # # fig3 = plt.figure(num=3, figsize = (10, 5))
    
    # # # creating the bar plot
    # # plt.bar(x_3, y_3, color ='maroon',
    # #         width = 0.4)
    
    # # plt.xlabel("No. of flagged IPs and DNSs requested in AVD")
    # # plt.ylabel("No. of AVD")
    # # plt.title("Distribution of flagged IPs and DNSs requested per AVD: n = " + str(n))

    # plt.figure(num=1)
    # plt.savefig(fdir + 'q7_' + str(n) + '_1')
    # plt.cla()
    # plt.figure(num=2)
    # plt.savefig(fdir + 'q7_' + str(n) + '_2')
    # plt.cla()
    # plt.figure(num=3)
    # plt.savefig(fdir + 'q7_' + str(n) + '_3')
    # plt.cla()

    # print(np.sum(y_1))
    # print(np.sum(y_2))
    # print(np.sum(y_3))
    #question 8, "what are the top 10 connected malicious IPs? where do they resolve to? which country and/or company?"
    # question_8_ip = list()
    # question_8_count = [0] * len(malips)
    # for ip in (malips):
    #     question_8_ip.append(ip)

    # for duo in hash_ip_list:
    #     found_ip = duo[1]
    #     index = question_8_ip.index(found_ip)
    #     question_8_count[index] += 1

    # question_8 = list()
    # for i in range(0, len(question_8_ip)):
    #     question_8.append([question_8_ip[i], question_8_count[i]])

    # def func(i):
    #     return i[1]

    # question_8.sort(reverse=True, key=func)
    # true_question_8 = list()
    # shuffle(API_KEYS)
    # key_cycle = cycle(API_KEYS)
    # for i in range(0, 10):
    #     key = next(key_cycle)
    #     ipdata = get_report_ip(question_8[i][0], key)
    #     true_question_8.append([question_8[i][0], \
    #     ipdata.get('data').get('attributes').get('as_owner'), \
    #     ipdata.get('data').get('attributes').get('country')])

    # writeToFile(true_question_8, fdir, 'q8.txt')


    # print(question_8[0:10])

    # #question 9, top 10 DNS
    # question_9_dns = list()
    # question_9_count = [0] * len(maldnss)
    # for dns in (maldnss):
    #     question_9_dns.append(dns)

    # for duo in hash_dns_list:
    #     found_dns = duo[1]
    #     index = question_9_dns.index(found_dns)
    #     question_9_count[index] += 1

    # question_9 = list()
    # for i in range(0, len(question_9_dns)):
    #     question_9.append([question_9_dns[i], question_9_count[i]])


    # question_9.sort(reverse=True, key=func)


    # true_question_9 = list()
    # shuffle(API_KEYS)
    # key_cycle = cycle(API_KEYS)
    # for i in range(0, 10):
    #     key = next(key_cycle)
    #     #urldata = get_report_url(question_9[i][0], key)
    #     reldata = get_relationship_url(question_9[i][0],key, 'last_serving_ip_address')
    #     local = get_local_url(question_9[i][0],key)
    #     try:
    #         true_question_9.append([question_9[i][0], \
    #         reldata.get('data').get('attributes').get('as_owner'), \
    #         local.get('data').get('attributes').get('whois')])
    #     except:
    #         pass

    # writeToFile(true_question_9, fdir, 'q9.txt')


parser = argparse.ArgumentParser("python script.py <masterFile> <malip> <maldns> <resultsFile>")
parser.add_argument("masterFile", help="directory of the full result file", type=str)
parser.add_argument("malip", help="directory of malicious ip pickle file", type=str)
parser.add_argument("maldns", help="directory of malicious dns pickle file", type=str)
parser.add_argument("resultsFile", help="directory of the result pickle file", type=str)
args = parser.parse_args()

malips = list()
maldnss = list()

#Get all flagged ip result files, and group into one set
ipf = os.listdir(args.malip)
for ip_file_name in ipf:
    ip_file = open(args.malip + '/' + ip_file_name, 'rb')
    malips = pickle.load(ip_file)
    print(len(malips))

#Get all flagged dns result files, and group into one set
dnsf = os.listdir(args.maldns)
for dns_file_name in dnsf:
    dns_file = open(args.maldns + '/' + dns_file_name, 'rb')
    maldnss = pickle.load(dns_file)
    print(len(maldnss))

#Get Master result file.
with open(args.masterFile, "rb") as f:
    master_Result = pickle.load(f)

for i in [2]:
    filtered_malips = set()
    filtered_maldnss = set()
    
    for ips in malips:
        report = ips[1].get('data').get('attributes').get('last_analysis_stats')
        if (report.get('malicious') + report.get('suspicious')) >= i:
            filtered_malips.add(ips[0])
    
    for dns in maldnss:
        report = dns[1].get('data').get('attributes').get('last_analysis_stats')
        if (report.get('malicious') + report.get('suspicious')) >= i:
            filtered_maldnss.add(dns[0])
    
    get_answers(master_Result, filtered_malips, filtered_maldnss, args.resultsFile, i)
    # print('IP, DNS, n: ' + str(len(filtered_malips)) + ',' + str(len(filtered_maldnss)) + ',' + str(i))


r'''
with open(args.resultsFile, 'wb') as f:
    pickle.dump(hash_ip_list, f, pickle.HIGHEST_PROTOCOL)
'''