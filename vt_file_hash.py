import csv

import requests
import xlsxwriter
import pandas as bpd
import os
import re
import time

import hashlib

from win32com.client import GetObject
import win32api, win32con, win32process

def pick_col():
	data_list_out = []
	n = 0
	xi = -1

	# fPath = input(r"Input file (csv): ")
	# fPath = r'C:\Users\jeromeg\Downloads\test_file.csv'
	fPath = r'C:\Users\jeromeg\Documents\Coding stht\Info Gather\bad_vt_md5.xlsx'

	# | Quotation remover
	ffx = re.search('^["].*["]$', fPath)
	if (ffx is not None):
		fPath = fPath[1:len(fPath) - 1]

	# | File reader (CSV)

	# ipnum = {
	# 	'1' : 'Source IP Address',
	# 	'2' : 'Destination IP Address'
	# }
	# rawdata = bpd.read_csv(fPath)
	rawdata = bpd.read_excel(fPath)
	# rawdata.sort_values(ipnum[userin], inplace = True)
	# rawdata.drop_duplicates(subset = ipnum[userin], keep = 'last' , inplace = True) 
	# rawdata = rawdata.loc[:, [ipnum[userin],ipcoun[userin]]]


	return rawdata

def proc_list():
	WMI = GetObject('winmgmts:')
	processes = WMI.InstancesOf('Win32_Process')		# | get list of all process
	hash256_list = []
	for p in processes:
		proc = p.Properties_[7].Value
		if proc is not None:
			# print(proc)               # | return the path and break the funcion
			filename = proc
			with open(filename,"rb") as f:
			    bytes = f.read() # read entire file as bytes
			    readable_hash = hashlib.sha256(bytes).hexdigest();
			    # print(readable_hash)
			    hash256_list.append(readable_hash)
	return (hash256_list)

def vt_report(hash256, api_count):
	# url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
	url = 'https://www.virustotal.com/vtapi/v2/file/report'
	
	if api_count == 0:
		params = {
		'apikey':'359f0f47ab81466839588031bf20dab7059ac9c33d34a3fc55f2d85827005b14',
		'resource': hash256
		}

	elif api_count == 1:
		params = {
		'apikey':'faa5a0e6ef90850a7cf9fccac02e6447e2487319f4692678a7a1a8cd1b7ca0d7',
		'resource': hash256
		}

	elif api_count == 2:
		params = {
		'apikey':'933ada8f362226e3f6cbe78c9543f11ce8e691c7b4cf471fbe9a993f968b5452',
		'resource': hash256
		}

	else:
		params = {
		'apikey':'d2ea2372d0d9dcb9863d357dc460ac7b057bacd8191918acedcf740fefd3eb47',
		'resource': hash256
		}

	response = requests.get(url, params=params)
	resp_main_dict = response.json()

	return resp_main_dict

def vt_def():
	# print(resp_main_dict['positives'])
	# print(resp_main_dict['total'])
	# print(resp_main_dict['scans']['Symantec']['result'])			
			
	col_lists = pick_col()
	# sss = xxx.sort_values('Log Timestamp (device time zone)', ascending = True)
	# xxx.rename(columns={'Vendor Code':'Symantec Name'}, inplace=True)
	# print(hash_col.columns)

	col_index = -1
	for col_select in col_lists.columns:
		col_index += 1
		if re.search('[Mm][Dd][5]$', col_select) is not None:
			md5_col = col_lists.iloc[:, col_index]			# | Find MD5 Hash list column
			md5_col = list(dict.fromkeys(md5_col))			# | Remove redundant
			md5_col = [x for x in md5_col if x == x]		# | Remove NaN/None elements

	hash256_list = md5_col
	api_count = 0

	vt_md5_list 	= []
	vt_sha1_list 	= []
	vt_sha256_list 	= []
	vt_positives 	= []
	vt_detectname 	= []

	antim_list = ['Symantec', 'McAfee', 'TrendMicro', 'Kaspersky', 'Sophos AV', 'Malwarebytes']
	print(md5_col)

	for hash256 in hash256_list:
		time.sleep(2)
		resp_main_dict = vt_report(hash256, api_count)
		api_count += 1
		if resp_main_dict['response_code'] == 1:
			vt_md5_list.append(resp_main_dict['md5'])
			vt_sha1_list.append(resp_main_dict['sha1'])
			vt_sha256_list.append(resp_main_dict['sha256'])
			vt_positives.append(str(resp_main_dict['positives']) + '/' + str(resp_main_dict['total']))

			av_count = -1
			
			for antim_name in antim_list:
				# print(type(antim_name in resp_main_dict['scans']))
				av_count += 1
				if (antim_name in resp_main_dict['scans']) == True:
					# print(antim_name, '1')
					if (resp_main_dict['scans'][antim_name]['detected']) == True:
						print(antim_name)
						vt_detectname.append(
							str(resp_main_dict['scans'][antim_name]['result'])
							+ '(' + antim_name + ')'
							)
						break
					elif av_count <= 5:
						# print(antim_name, av_count)
						continue
					else:
						# print(antim_name, '3')
						for else_name in resp_main_dict['scans']:
							if resp_main_dict['scans'][else_name]['detected'] == True:
								vt_detectname.append(
									str(resp_main_dict['scans'][else_name]['result'])
									+ '(' + else_name + ')'
									)
								break
							else:
								# vt_detectname.append('None')
								break

							break
						# break	
				# break				
				elif (antim_name in resp_main_dict['scans']) == False:
				# 	# print(antim_name)
					break
				# break
		print(vt_detectname)		
		print(str(resp_main_dict['positives']) + '/' + str(resp_main_dict['total']))
		# print(resp_main_dict['scans'])
		time.sleep(2)
		if api_count > 3:
			api_count = 0	

		vt_data = {
		'Detection Name':	vt_detectname,
		'Detection':		vt_positives,
		'File Sign MD5':	vt_md5_list,
		'File Sign SHA1':	vt_sha1_list,
		'File Sign SHA265':	vt_sha256_list
		}
		# print(bpd.DataFrame(vt_data))

		# 
	return bpd.DataFrame(vt_data)

vt_data = vt_def()
print(vt_data)
xcel_write = bpd.ExcelWriter(r'.\VirusTotal_detection.xlsx', engine='xlsxwriter')
vt_data.to_excel(xcel_write, sheet_name='Malware Detection')

workbook  = xcel_write.book
worksheet = xcel_write.sheets['Malware Detection']

# cell_format = workbook.add_format()
# cell_format.set_text_wrap()
# cell_format.set_font_size(10)

# worksheet.set_column('B:B', 20, cell_format)
# worksheet.set_column('C:C', 40, cell_format)
# worksheet.set_column('D:Z', 20, cell_format)


xcel_write.save()