from scapy.all import *
from Crypto.Cipher import AES
import base64


traffic = rdpcap("filedump.pcap")

"""
packet.Packet.show(traffic[1936])
print(traffic[1936][IP].dst)
print(traffic[1936][TCP].dport)
a = traffic[1937].layers

print(a)
"""

a = ""

for i in traffic:
	if i.type == 2048: #Check if packet type is IPv4
		if i[IP].dst == "192.168.100.4": #Check IP Destination
			if i[TCP].dport == 6000: #Check port number
				if "Raw" in str(i.layers): #Check packet has Raw layer (data)
					#packet.Packet.show(i)
					a = str(i[Raw])

b = a[1:].strip("'")
keyinfo = b.rsplit("\\n")

with open('sample2.txt', 'r') as file:
    encryptedtxt = file.read().replace('\n', '')

txtfile = open('sample.txt', 'r')
txt = txtfile.readline()
print(txt)



siv = keyinfo[0]
mode = keyinfo[1]
skey = keyinfo[2]
keymode = keyinfo[3]

iv = base64.b64decode(siv)
key = base64.b64decode(skey)
bytetxt = base64.b64decode(skey)


cipher = AES.new(key, AES.MODE_GCM, nonce = iv)
encrypted = cipher.encrypt(bytes(txt, 'utf-8'))
encryptedtxt2 = str(base64.b64encode(encrypted), 'utf-8')
encryptedtxt = encryptedtxt.replace("gYf7Df3G3ETB0xUNMi5fWA==", "")
print("The Java: " + encryptedtxt)
print("The Python: " + encryptedtxt2)


cipher = AES.new(key, AES.MODE_GCM, nonce = iv)
decrypted2 = cipher.decrypt(base64.b64decode(bytes(encryptedtxt2, 'utf-8')))
decryptedtext2 = str(decrypted2,'utf-8')
print("The Python decrypted: " + decryptedtext2)


cipher = AES.new(key, AES.MODE_GCM, nonce = iv)
decrypted = cipher.decrypt(base64.b64decode(bytes(encryptedtxt, 'utf-8')))
print(decrypted)
decryptedtext = str(decrypted,'utf-8')
print("The Java decrypted: " + decryptedtext)


