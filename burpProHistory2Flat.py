#!/usr/local/bin/python2.7

import sys
import os
import argparse
from xml.etree import ElementTree as ET
from base64 import b64decode


def usage():
	print(
		'\n'.join([
			'Goal:',
			'Abstract original raw HTTP request from Burp Suite History data.',
			'',
			'Description:'
			'Read some burp suite history files and decode them to original raw HTTP request data, then write them to a file.',
			'',
			'Warning:',
			'You must specify input data folder which contain burp suite history files, and output file name.',
			''
			'To use this script, execute like this',
			'$ python burpProHistory2Flat.py',
			''
		])
	)


def main():

	# You must specify !!
	input_data_folder = './burp_history_files'
	# You must specify !!
	output_file_name = 'original_http_request.data'


	# delete old output file.
	if os.path.isfile(output_file_name):
		os.remove(output_file_name)

	# search input files.
	input_list = []
	for file_name in os.listdir(input_data_folder):
		file_path = os.path.join(input_data_folder, file_name)
		if os.path.isfile(file_path):
			input_list.append(file_path)


	# decode burp suite history and write them to output file.
	with open(output_file_name, 'w+') as output:

		for input_file_path in input_list:
			xmlLog = ET.parse(input_file_path)
			rootElement = xmlLog.getroot()
			burpItemsList = rootElement.findall('item')
			if burpItemsList!=None:
				for item in burpItemsList:
					request = item.find('request').text
					if item.find('request').attrib['base64']:
						request = b64decode (request)
					
					method = request.split(' ')[0]
					if method == 'POST':
						output.write(request+'\n\n')
					else:
						output.write(request+'\n')
				
				print('End! Total number of log items parsed: %s ' % (len(burpItemsList)))



if __name__ == "__main__":
	main()
