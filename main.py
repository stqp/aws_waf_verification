# -*- coding: utf-8 -*-

import boto3
import os
import sys
import subprocess
import urllib
import urlparse
import traceback
import copy
from time import sleep
import re
import requests
from multiprocessing import Pool
from threading import Thread
from Queue import Queue
from multiprocessing.pool import ThreadPool
from urlparse import urlparse


# You must specify cloudfront id.
cf_id = ""

# You must specify cloudfront hostname.
TARGET_HOST = ""



TARGET_PORT = 80
PROTO = 'https'
input_data_folder = './in_data'
thread_num = 10

session = boto3.Session(profile_name="dev")
waf = session.client('waf') # waf = session.client('waf-regional')
cf = session.client('cloudfront')


def get_out_file_path(acl_name):
  acl_name = re.sub(r'[-_ ]','',acl_name)
  out_file_path = './out_data/out_' + acl_name + '.csv'
  return out_file_path


def host_cant_resolve(method, req_sequence, request, in_data):
  return {
    "id": req_sequence,
    "request": 'Host name can\'t resolved' + request,
    "status": '404',
    "method": method,
    "in_data":in_data
  }


def unknown_error(method, req_sequence, request, in_data, e, res):
  return {
      "id": req_sequence,
      "request": str(e) + " " + request,
      "status": '-1',
      "method": method,
      "in_data":in_data
  }


def valid_response(method, req_sequence, request, test_data_file_name, status_code):
  return {
      "id": req_sequence,
      "request": request,
      "status": str(status_code),
      "method": method,
      "in_data": test_data_file_name
  }


def build_out_put(res):
  return ','.join( [str(res['id']), res['method'], '"'+res['request'].replace('"',"'")+'"', res['status'], res['in_data']+'\n'])


def do_request(req_sequence, req_raw_list, test_data_file_name):
  # debug
  if req_sequence % 100 == 0:
    print(req_sequence)

  request = ""
  req_raw_list = map(lambda x: x.replace('localhost:8080', HOST), req_raw_list)

  # リクエストの中身を文字列化する。var_formatsはバイト文字列でバグるので無視する
  if test_data_file_name.find('var_formats')<0:
    request = '\\n'.join(req_raw_list)


  res = req_raw_list.pop(0).split()
  method = res[0]
  url = res[1]


  # httpだとローカル端末のウイルス検知ソフトが勝手に通信遮断するので、httpsにする。
  url = url.replace('http://', 'https://')

  # hack code. To skip unknown hostname(=cant resolve hostname).
  try :
    url_parsed = urlparse(url)
    if url_parsed.hostname != HOST:
      return host_cant_resolve(method, req_sequence, request, test_data_file_name)
  except Exception as e:
    print(e)


  # header
  headers = {}
  while True:
    try :
      header = req_raw_list.pop(0)
      if not header:
        break;

      header = header.replace('localhost:8080', HOST)
      header = header.replace(' ','')
      tmp_headers = header.split(':')
      key = tmp_headers.pop(0)
      val = ':'.join(tmp_headers)
      headers[key] = val
    except Exception as e:
      print("Get header error.", e)

  try:
    data = '\n'.join(req_raw_list)
    if method == 'GET':
      res = requests.get(url, data=data, headers=headers, verify = False)
    elif method == 'POST':
      res = requests.post(url, data=data, headers=headers, verify = False)
    return valid_response(method, req_sequence, request, test_data_file_name, res.status_code)
  except Exception as e:
    return unknown_error(method, req_sequence, request, test_data_file_name, e, res)




def do_test(input_list, out_data):
  req_sequence = 1
  req_list = []
  input_list = sorted(input_list)

  for input_file_path in input_list:

    # Mac環境においては、憎き「.DS_Store」ファイルが勝手に作られるので無視する。
    if input_file_path.find('DS_Store')>=0:
      continue

    with open(input_file_path) as input_file:
      req_raw_list = []
      lines = input_file.readlines()
      lines = list(map(lambda x:x.replace('\n','').replace('\r',''), lines))

      for line in lines:
        if len(req_raw_list)>0 and ('GET' in line or 'POST' in line) :
          req_list.append((req_sequence,req_raw_list, input_file))
          req_raw_list = []
          req_raw_list.append(line)
          req_sequence = req_sequence + 1
          continue

        req_raw_list.append(line)

      #最後のリクエストがループ内では処理されないので、ここで再度処理する。
      req_list.append( (req_sequence, req_raw_list, input_file) )
      req_sequence = req_sequence + 1


  def do_request_wrapper(args):
    return do_request(*args)


  pool = ThreadPool(thread_num)
  response_list = pool.map(do_request_wrapper, req_list)
  pool.close()

  response_list = sorted(response_list, key=lambda x: x['id'])
  with open(out_data,'w') as out_file:
    for res in response_list:
      out_file.write(build_out_put(res))



#### メイン処理の開始地点 ####

# search input files.
input_list = []
for file_name in os.listdir(input_data_folder):
  file_path = os.path.join(input_data_folder, file_name)
  if os.path.isfile(file_path):
    input_list.append(file_path)


acl_list = waf.list_web_acls()['WebACLs']
acl_list = sorted(acl_list, key=lambda x:x['Name'])


for acl in acl_list:

  # Web ACLを１個ずつ切替えながら検査していく。
  new_cf_conf = copy.deepcopy(cf_conf)
  new_cf_conf['WebACLId'] = acl['WebACLId']

  cf_dist = cf.get_distribution_config(Id=cf_id)
  cf_conf = cf_dist['DistributionConfig']
  cf_etag = cf_dist['ETag']

  cf.update_distribution(
    DistributionConfig=new_cf_conf,
    Id=cf_id,
    IfMatch=cf_etag
  )


  #浸透するのを念のためまつ
  sleep(10)
  

  # 結果の出力先をクリーンして(後に)新規作成。
  out_data = get_out_file_path(acl['Name'])
  if os.path.isfile(out_data):
    os.remove(out_data)


  # 検査実行
  do_test(input_list, out_data)
  print("end : " + acl['Name'])



#### 出力結果を１つのファイルにまとめる ####

# ここではアウトプットファイルの枠だけ作成する。
with open(get_out_file_path(acl_list[0]['Name'])) as input_file:

  out_file_path = get_out_file_path('all')

  # 結果の出力先をクリーンして新規作成
  if os.path.isfile(out_file_path):
    os.remove(out_file_path)

  with open(out_file_path,'w') as out_file:

    # write headers.
    out_file.write('No.,method,request,data\n')

    for line in in_file.readlines():
      tmp = line.split(',')
      del tmp[len(tmp)-2]
      out_file.write(','.join(tmp))


# 前の処理で作ったアウトプットファイルの枠に、中身を突っ込んでいく。
for acl in acl_list:

  # debug code.
  print acl['Name']

  in_lines1 = []
  with open(out_data) as file:
    in_lines1 = file.readlines()


  in_lines2 = []
  with open(get_out_file_path(acl['Name'])) as file:
    in_lines2 = file.readlines()


  with open(out_data,'w') as out_file:
    for i in range(-1,len(in_lines2)):
      line1 = in_lines1[i+1]
      if i == -1:
        out_file.write(','.join([line1.rstrip(),acl['Name']])+'\n')
      else:
        try:
          line2 = in_lines2[i]
          tmp_line2 = line2[line2.index('"')+1:] if line2.index('"') >= 0 else line2
          tmp_line2 = tmp_line2[tmp_line2.index('"')+1:] if tmp_line2.index('"') >= 0 else tmp_line2
          out_file.write(','.join([line1.rstrip(), tmp_line2.split(',')[1]])+'\n')
        except Exception as e:
          print(traceback.format_exc()) 

