#!/usr/bin/python

import os

# You must specify !!
input_data_folder = './logger_plusplus_files'
# You must specify !!
output_file_name = 'burpscan_abnormal.data'


# Dummy parameters for original HTTP request.
port = '8080'
user_agent = 'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)'
http_version = 'HTTP/1.1'


# delete old output file.
if os.path.isfile(output_file_name):
  os.remove(output_file_name)


# search input files.
input_list = []
for file_name in os.listdir(input_data_folder):
  file_path = os.path.join(input_data_folder, file_name)
  if os.path.isfile(file_path):
    input_list.append(file_path)


# Decode burp scan hisotry by Logger++, and write them to ouput file.
for input_file_path in input_list:
  with open(input_file_path) as in_file:
    with open(output_file_name,'w+') as output:

      for line in in_file.readlines():
        cols = line.split(',')
        tool = cols[2]
        host = cols[3]
        method = cols[4]
        path = cols[5]
        query = cols[6]
        mime = cols[10]

        if tool != 'Scanner':
          continue

        request = []
        if method == 'GET':
          request.append(method + ' ' + host + ':' + port + path + '?' + query + ' ' + http_version)
        elif method == 'POST':
          request.append(method + ' ' + host + ':' + port + path + ' ' + http_version)

        request.append('Host: ' + host[7:] + ':' + port)
        request.append('User-Agent: ' + user_agent)
        request.append('Accept: */*')
        request.append('Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5')
        request.append('Accept-Encoding: x-gzip, x-deflate, gzip, deflate')
        request.append('Accept-Language: en')

        if method == 'POST':
          request.append('Content-Length: '+ str(len(query)))
          
        request.append('Connection: close')
        request.append('')
        if method == 'POST' and query:
          request.append(query+'\n\n')
        else:
          request.append('\n')

        output.write('\n'.join(request))

