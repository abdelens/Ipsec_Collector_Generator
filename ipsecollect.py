import sys
import csv
import os

mylines = []
with open ('input\config.txt', 'rt') as myfile:
		for line in myfile:
			if "crypto isakmp key" in line:
				mylines.append(line)
		for element in mylines:
			print(element, end='')