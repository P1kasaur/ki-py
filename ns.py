import os
import re
import csv
import sys
import openpyxl

dstip = []
n = 0
xi = -1

fPath = input(r"Input file (csv): ")
ffx = re.search('^["].*["]$', fPath)
if (ffx is not None):
	fPath = fPath[1:len(fPath)-1]

with open(fPath, 'r') as csvFile:
	reader = csv.reader(csvFile)
	for row in reader:
		n += 1
		if (n == 1):
			for rowlen in row:
				xi += 1
				print(str(xi) + " - " + rowlen)
		elif (n == 2):

			ri = int(input("Enter corresponding number: "))
			continue		
		else:	
			rx = re.search('^[0-9].*[0-9]$', str(row[ri]))
			if (rx is not None):
				dstip.append(str(row[ri]))

csvFile.close()

wb = openpyxl.Workbook()

ipx = wb.active

count = 1
aa = 'A' + str(count)
ipx[aa] = "Address"

bb = 'B' + str(count)
ipx[bb] = "Name"

fi = fPath.rfind(chr(92))
fOut = fPath[0:fi] + r"\output.txt"
open(fOut, "w")

uDstip = list(dict.fromkeys(dstip))

for ip in uDstip:
	ox = os.system('nslookup ' + ip + ' > ' + fOut)
	f = open(fOut, "r")
	if (ox == 0):
		count += 1
	for i in range(1,6):
		if (i == 4):
			fx = f.readline()
			rx = re.search("^[N][a][m][e][:][ ]", fx)
			if (rx is not None):
				sfx = fx.find('Name: ') + 9
				efx = len(fx) - 1
				nfx = fx[sfx:efx]
				bb = 'B' + str(count)
				ipx[bb] = nfx

		elif (i == 5):		
			fx = f.readline()
			rx = re.search("^[A][d][d][r][e][s][s][:]", fx)
			if (rx is not None):
				sfx = fx.find('Address: ') + 10
				efx = len(fx) - 1
				afx = fx[sfx:efx]
				aa = 'A' + str(count)
				ipx[aa] = afx

		else:
			f.readline()
			
fi = fPath.rfind(chr(46))
fSave = fPath[0:fi] + "_NSLooked.xlsx"
print("Your file is saved here:")
print(fSave)
wb.save(fSave)
f.close()
os.remove(fOut)
