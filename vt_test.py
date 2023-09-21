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
	fPath = r'C:\Users\jeromeg\Downloads\test_file.csv'

	# | Quotation remover
	ffx = re.search('^["].*["]$', fPath)
	if (ffx is not None):
		fPath = fPath[1:len(fPath) - 1]

	# | File reader (CSV)

	ipnum = {
		'1' : 'Source IP Address',
		'2' : 'Destination IP Address'
	}

	rawdata = bpd.read_csv(fPath)
	# rawdata.sort_values(ipnum[userin], inplace = True)
	# rawdata.drop_duplicates(subset = ipnum[userin], keep = 'last' , inplace = True) 
	# rawdata = rawdata.loc[:, [ipnum[userin],ipcoun[userin]]]


	return (data_list_out, rawdata)

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
	

	# params = {'apikey':'359f0f47ab81466839588031bf20dab7059ac9c33d34a3fc55f2d85827005b14','ip': ip}
	# params = {'apikey':'933ada8f362226e3f6cbe78c9543f11ce8e691c7b4cf471fbe9a993f968b5452','ip': ip}

	# params = {
	# 	'apikey'	:'faa5a0e6ef90850a7cf9fccac02e6447e2487319f4692678a7a1a8cd1b7ca0d7',
	# 	# 'resource'	: 'd36861185639313f291fab94a65c12deb60c2539e50b6d2ce8b6ed77b8aae144'
	# 	'resource'	:'c40e8c13dd03dd3829fdcd9a28a8633a'
	# 	}
	# response_list = []
	# print(hash256_list)
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


	# params = {
	# 'apikey':'933ada8f362226e3f6cbe78c9543f11ce8e691c7b4cf471fbe9a993f968b5452',
	# 'resource': hash256
	# }		

	response = requests.get(url, params=params)
	resp_main_dict = response.json()
	# response_list.append(resp_main_dict)
		

	return resp_main_dict
	# return (response_list)

def main():
	hash256_list = proc_list()
	api_count = 0
	for hash256 in hash256_list:
		time.sleep(2)
		resp_main_dict = vt_report(hash256, api_count)
		api_count += 1
		print(hash256)
		print(str(resp_main_dict['positives']) + '/' + str(resp_main_dict['total']))
		time.sleep(2)
		if api_count > 3:
			api_count = 0		

		# print(resp_main_dict)
		# for resp_main_dict in response_list:
		# for ii in resp_main_dict['scans']:
		# 	time.sleep(0.5)
		# 	# print(ii)
		# 	if resp_main_dict['scans'][ii]['result'] is not None:
					
		# 		print(str(ii) + ' = ' + str(resp_main_dict['scans'][ii]['result']))
		# 	else:
		# 		print('None')	


# print(resp_main_dict['positives'])
# print(resp_main_dict['total'])
# print(resp_main_dict['scans']['Symantec']['result'])			
		
# xxx = pick_col()[1]
# sss = xxx.sort_values('Log Timestamp (device time zone)', ascending = True)
# xxx.rename(columns={'Vendor Code':'Symantec Name'}, inplace=True)
# print(xxx.columns)

main()
