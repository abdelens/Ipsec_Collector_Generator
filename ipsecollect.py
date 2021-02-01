import sys
import csv
import os

peers = []
ts = []
s1="set peer"
s2="crypto ipsec transform-set"
with open ('input\config.txt', 'rt') as myfile:
		for line in myfile:
			if s1 in line:
				#peer=line[line.index(s1) + (len(s1)+1):]
				res = line.split()
				peers.append(res[2])
		print("la liste des peer est:", peers)

with open ('input\config.txt', 'rt') as myfile:
		for line in myfile:
			if s2 in line:
				#peer=line[line.index(s1) + (len(s1)+1):]
				res2 = line.split()
				ts.append(res2[2])
		print("la liste des peer est:", peers)
