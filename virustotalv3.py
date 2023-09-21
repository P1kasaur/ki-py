
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#	Name: 		Luigi Cruz
# 	Revision:	
#	v1 - Detection Urls, Downloaded Files, Communication Files	3/20/2019
# 	v2 - Optimize Query	3/27/2019
#	v3 - 
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

import requests
import os
import re
import pandas as pd 
import time

filein = input('File input: ').lstrip('"').rstrip('"')
userin = input('What IP Address?\n1:Source\n2:Destination\nChoose: ')

ipnum = {
	'1' : 'Source IP Address',
	'2' : 'Destination IP Address'
}

ipcoun = {
	'1' : 'Source Country',
	'2' : 'Destination Country'
}


rawdata = pd.read_csv(filein)
rawdata.sort_values(ipnum[userin], inplace = True)
rawdata.drop_duplicates(subset = ipnum[userin], keep = 'last' , inplace = True) 
rawdata = rawdata.loc[:, [ipnum[userin],ipcoun[userin]]]



'''=============================VIRUS TOTAL======================================================'''

df = pd.DataFrame(columns=[
	'IP Address',
	'AS Owner',
	'Resolution',
	'Detected Urls (DU)',
	'DU Rate',
	'DU Scan Date',
	'Undetected Urls (UU)',
	'UU Rate',
	'UU Scan Date',
	'Detected Downloaded Samples (DD)',
	'DD Rate',
	'DD Scan Date',
	'Undetected Downloaded Samples (UD)',
	'UD Rate',
	'UD Scan Date',
	'Detected Communicating Samples (DC)',
	'DC Rate',
	'DC Scan Date',
	'Undetected Communicating Samples (UC)',
	'UC Rate',
	'UC Scan Date',
	'Msg'
	])


def vtquery(ipp,asowner,dns,du,rdu,ddu,uu,ruu,duu,dd,rdd,ddd,ud,rud,dud,dc,rdc,ddc,uc,ruc,duc,msg):
	global df
	df = df.append({
		'IP Address' : ipp ,
		'AS Owner' : asowner,
		'Resolution': dns,
		'Detected Urls (DU)' : du,
		'DU Rate': rdu,
		'DU Scan Date': ddu,
		'Undetected Urls (UU)': uu,
		'UU Rate': ruu,
		'UU Scan Date': duu,
		'Detected Downloaded Samples (DD)': dd,
		'DD Rate': rdd,
		'DD Scan Date': ddd,
		'Undetected Downloaded Samples (UD)' : ud,
		'UD Rate': rud,
		'UD Scan Date': dud,
		'Detected Communicating Samples (DC)' : dc,
		'DC Rate': rdc,
		'DC Scan Date': ddc,
		'Undetected Communicating Samples (UC)' : uc,
		'UC Rate': ruc,
		'UC Scan Date': duc,
		
		'Msg' : msg
		},ignore_index='True')

def duemp():
	global idu,irdu,iddu
	idu = ''
	irdu = ''
	iddu = ''

def uuemp():
	global iuu,iruu,iduu
	iuu = ''
	iruu = ''
	iduu = ''

def ddempty():
	global idd,irdd,iddd
	idd = ''
	irdd = ''
	iddd = ''

def udempty():
	global iud,irud,idud
	iud = ''
	irud = ''
	idud = ''
	
def dcempty():
	global idc,irdc,iddc
	idc = ''
	irdc = ''
	iddc = ''

def ucempty():
	global iuc,iruc,iduc
	iuc = ''
	iruc = ''
	iduc = ''

def headerdesign(cn1,cn2,bold,textwrap,valign,fgcolor,border):
	
	header_format = workbook.add_format({
	'bold': bold,
	'text_wrap': textwrap,
	'valign': valign,
	'fg_color': fgcolor,
	'border': border
	}) 
	
	for col_num, value in enumerate(df.columns.values):
		if col_num >= cn1 and col_num <= cn2 :
			worksheet.write(0, col_num, value, header_format)
		elif col_num > cn2:
			break
		else:
			continue
		

url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
xi = 0
for i in range(int(rawdata.shape[0])):
	ip = str(rawdata.iloc[i,0])
	
	if xi == 0:
		params = {'apikey':'359f0f47ab81466839588031bf20dab7059ac9c33d34a3fc55f2d85827005b14','ip': ip}
		xi += 1
	elif xi == 1:
		params = {'apikey':'faa5a0e6ef90850a7cf9fccac02e6447e2487319f4692678a7a1a8cd1b7ca0d7','ip': ip}
		xi += 1
	elif xi == 2:
		params = {'apikey':'933ada8f362226e3f6cbe78c9543f11ce8e691c7b4cf471fbe9a993f968b5452','ip': ip}
		xi += 1
	else:
		params = {'apikey':'d2ea2372d0d9dcb9863d357dc460ac7b057bacd8191918acedcf740fefd3eb47','ip': ip}
		xi = 0	

	response = requests.get(url, params=params)
	dct = response.json()

	
	msg = dct['verbose_msg']

	if msg == 'IP address in dataset':

		maxrng = set([])

		if 'as_owner' in dct:
			maxrng.add(len(dct['as_owner']))
		if 'resolutions' in dct:
			maxrng.add(len(dct['resolutions']))
		if 'detected_urls' in dct:
			maxrng.add(len(dct['detected_urls']))
		if 'undetected_urls' in dct:
			maxrng.add(len(dct['undetected_urls']))
		if 'detected_downloaded_samples' in dct:
			maxrng.add(len(dct['detected_downloaded_samples']))
		if 'undetected_downloaded_samples' in dct:
			maxrng.add(len(dct['undetected_downloaded_samples']))
		if 'detected_communicating_samples' in dct:
			maxrng.add(len(dct['detected_communicating_samples']))
		if 'undetected_communicating_samples' in dct:
			maxrng.add(len(dct['undetected_communicating_samples']))
		maxrng = max(maxrng)
		
		for a in range(maxrng):
			if 'as_owner' in dct:
				if dct['as_owner'] is not None:
						asowner = dct['as_owner']
					
				else:
					asowner = ''
			else:
				as_owner = ''

			if 'resolutions' in dct:
				if dct['resolutions'] is not None:
					if a < len(dct['resolutions']):
						idns = dct['resolutions'][a]['hostname']
					else:
						idns = ''
				else:
					idns = ''
			else:
				idns = ''
			#print(idns)

			if 'detected_urls' in dct:
				if dct['detected_urls'] is not None:
					if a < len(dct['detected_urls']):
						idu = dct['detected_urls'][a]['url']
						irdu = str(dct['detected_urls'][a]['positives']) + '/' + str(dct['detected_urls'][a]['total'])
						iddu = dct['detected_urls'][a]['scan_date']
					else:
						duemp()
				else:
					duemp()
			else:
				duemp()

			if 'undetected_urls' in dct:
				if dct['undetected_urls'] is not None:
					
					if a < len(dct['undetected_urls']):
						iuu = dct['undetected_urls'][a][0]
						iruu = str(dct['undetected_urls'][a][2]) + '/' + str(dct['undetected_urls'][a][3])
						iduu = dct['undetected_urls'][a][4]
					else:
						uuemp()
				else:
					uuemp()
			else:
				uuemp()

			if 'detected_downloaded_samples' in dct:
				if dct['detected_downloaded_samples'] is not None:
					if a < len(dct['detected_downloaded_samples']):
						idd = dct['detected_downloaded_samples'][a]['sha256']
						irdd = str(dct['detected_downloaded_samples'][a]['positives']) + '/' + str(dct['detected_downloaded_samples'][a]['total'])
						iddd = dct['detected_downloaded_samples'][a]['date']
					else:
						ddempty()
				else:
					ddempty()

			else:
				ddempty()

			if 'undetected_downloaded_samples' in dct:
				if dct['undetected_downloaded_samples'] is not None:
					if a < len(dct['undetected_downloaded_samples']):
						iud = dct['undetected_downloaded_samples'][a]['sha256']
						irud = str(dct['undetected_downloaded_samples'][a]['positives']) + '/' + str(dct['undetected_downloaded_samples'][a]['total'])
						idud = dct['undetected_downloaded_samples'][a]['date']
					else:
						udempty()
				else:
					udempty()
			else:
				udempty()

			if 'detected_communicating_samples' in dct:
				if dct['detected_communicating_samples'] is not None:
					if a < len(dct['detected_communicating_samples']):
						idc = dct['detected_communicating_samples'][a]['sha256']
						irdc = str(dct['detected_communicating_samples'][a]['positives']) + '/' + str(dct['detected_communicating_samples'][a]['total'])
						iddc = dct['detected_communicating_samples'][a]['date']
					else:
						dcempty()
				else:
					dcempty()
			else:
				dcempty()

			if 'undetected_communicating_samples' in dct:
				if dct['undetected_communicating_samples'] is not None:
					if a < len(dct['undetected_communicating_samples']):
						iuc = dct['undetected_communicating_samples'][a]['sha256']
						iruc = str(dct['undetected_communicating_samples'][a]['positives']) + '/' + str(dct['undetected_communicating_samples'][a]['total'])
						iduc = dct['undetected_communicating_samples'][a]['date']
					else:
						ucempty()
				else:
					ucempty()
			else:
				ucempty()

			vtquery(ip,asowner,idns,idu,irdu,iddu,iuu,iruu,iduu,idd,irdd,iddd,iud,irud,idud,idc,irdc,iddc,iuc,iruc,iduc,msg)
	else:
		if 'as_owner' in dct:
			if dct['as_owner'] is not None:
				asowner = dct['as_owner']
			else:
				asowner = ''
		else:
			asowner = ''
		idns = ''
		duemp()
		uuemp()
		ddempty()
		udempty()
		dcempty()
		ucempty()

		vtquery(ip,asowner,idns,idu,irdu,iddu,iuu,iruu,iduu,idd,irdd,iddd,iud,irud,idud,idc,irdc,iddc,iuc,iruc,iduc,msg)

	time.sleep(4)
	print(ip)	
print('done')
	
'''===========================================Excel Design================================================================='''

writer = pd.ExcelWriter(r'D:\VirusTotal.xlsx', engine='xlsxwriter')
df.to_excel(writer, sheet_name='VirusTotal')

workbook  = writer.book
worksheet = writer.sheets['VirusTotal']

 
headerdesign(3,5,True,True,'top','#D7E4BC',1)
headerdesign(6,8,True,True,'top','#FFA500',1)
headerdesign(9,11,True,True,'top','#87CEFA',1)
headerdesign(12,14,True,True,'top','#FFA07A',1)
headerdesign(15,17,True,True,'top','#FFC0CB',1)
headerdesign(18,20,True,True,'top','#40E0D0',1)



cell_format = workbook.add_format()
cell_format.set_text_wrap()
cell_format.set_font_size(10)
worksheet.set_column('B:B', 20, cell_format)
worksheet.set_column('C:C', 40, cell_format)
worksheet.set_column('D:Z', 20, cell_format)


writer.save()

#print(df)

