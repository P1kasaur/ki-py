import os
import re
import requests
import xlsxwriter
import urllib.request
import time
from bs4 import BeautifulSoup

import csv
import sys
import openpyxl



#url = 'https://www.whois.com/whois/' + ip
#url = 'https://www.virustotal.com/#/ip-address/124.106.4.37'
#url = 'https://www.iptrackeronline.com/index.php?ip_address=52.125.128.200&k='
url = 'https://iplogger.org/ip-lookup/?d=52.125.128.200'

# Connect to the URL
response = requests.get(url)

# Parse HTML and save to BeautifulSoup object¶
soup = BeautifulSoup(response.text, "html.parser")

fPath = ".\output.txt"
f = open(fPath, "w")
f.write(str(soup.encode("utf-8")))
f.close()

xPath = ".\output.xlsx"
wc = xlsxwriter.Workbook(xPath)
ws = wc.add_worksheet()
bold = wc.add_format({'bold': 1})

xHead = ["IP Address", "Inetnum", "Description", "Country Code", "Organization Name"]

xData = ["", "", "", ""]

ws.write_row('A1', xHead, bold)
#ws.write_column('A2', uDstip)
#ws.write_column('B18', xdata[1])

fList = ["^[i][n][e][t][n][u][m][:]", 
		"^[d][e][s][c][r][:]",
		"^[c][o][u][n][t][r][y][:]",
		"^[o][r][g][-][n][a][m][e][:]"]

xCount = 1

with open(fPath) as fRead:
	for fLine in fRead:
		for fLii in range(1,5):
			fre = re.search(fList[fLii-1], fLine)
			if (fre is not None):
				#xCount += 1
				ix = fLii-1
				print(fLine.split())
				spLine = fLine.split()
				if (ix == 0):
					editLine = str(spLine[1]) + " " + str(spLine[2]) + " " + str(spLine[3])
					xData[ix] = editLine
				elif (ix == 1):
					editLine = ""
					for spLI in spLine:
						spre = re.search(fList[ix], spLI)
						if (spre is None):
							tLine = spLI
							tLine = tLine + " "
							editLine += tLine
					xData[ix] = editLine
				elif (ix == 2):	
					editLine = spLine[1]
					xData[ix] = editLine
				elif (ix == 3):
					editLine = ""
					for spLI in spLine:
						spre = re.search(fList[ix], spLI)
						if (spre is None):
							tLine = spLI
							tLine = tLine + " "
							editLine += tLine				
					xData[ix] = editLine			
		if '</html>' in fLine:
			break
ws.write_row('B2', xData)
wc.close()
