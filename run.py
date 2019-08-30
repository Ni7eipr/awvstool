#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import json
import os
import re
import shutil
import sqlite3
import sys
from datetime import datetime
from optparse import OptionParser
from xml.etree.ElementTree import fromstring

import requests
import urlparse

import iso8601
from conf import *

# from xmljson import badgerfish

headers = {"X-Auth":apikey, "content-type": "application/json"}
requests.packages.urllib3.disable_warnings()
req = requests.Session()

def get_scan():
    next_cursor = 0
    res = []
    while next_cursor != None:
        try:
            response = requests.get(server_url + "/api/v1/scans?c=" + str(next_cursor), headers=headers, verify=False)
            results = response.json()
            sys.stdout.write('page: ' + str(next_cursor / 100) + "x100\r")
            sys.stdout.flush()
            next_cursor = results['pagination']['next_cursor']
            for result in results['scans']:
                res.append(result)
        except requests.exceptions.ConnectionError:
            print "retry:", next_cursor
    print
    return res

def get_target():
    next_cursor = 0
    res = []
    while next_cursor != None:
        try:
            response = requests.get(server_url + "/api/v1/targets?c=" + str(next_cursor), headers=headers, verify=False)
            results = response.json()
            sys.stdout.write('page: ' + str(next_cursor / 100) + "x100\r")
            sys.stdout.flush()
            next_cursor = results['pagination']['next_cursor']
            for result in results['targets']:
                res.append(result)
        except requests.exceptions.ConnectionError:
            print "retry:", next_cursor
    print
    return res

def add_target(url):
    data = {"address":url, "description":url, "criticality":"10"}
    res = req.post(server_url + "/api/v1/targets", headers=headers, data=json.dumps(data), verify=False)
    try:
        target_id = res.json()['target_id']
        return target_id
    except:
        print url, res.json()

def start_target(target_id):
    data = {"target_id":target_id,"profile_id": profile_id, "schedule": {"disable": False,"start_date":None,"time_sensitive": False}}
    res = req.post(server_url + "/api/v1/scans", headers=headers, data=json.dumps(data), verify=False)
    return res.json()['profile_id']

def pausescan(ids):
    res = req.post(server_url + "/api/v1/scans/" + ids + '/pause', headers=headers, verify=False)

def stopscan(ids):
    res = req.post(server_url + "/api/v1/scans/" + ids + '/abort', headers=headers, verify=False)

def delscan(ids):
    res = req.delete(server_url + "/api/v1/scans/" + ids, headers=headers, verify=False)

def delete(ids):
    res = req.delete(server_url + "/api/v1/targets/" + ids, headers=headers, verify=False)

def download(name, url):
    with open("lib/download/" + name + ".json", "w") as f:
        res = req.get(server_url + url, headers=headers, verify=False).content
        try:
            res = json.dumps(badgerfish.data(fromstring(res)), indent=4)
        except :
            pass
        f.write(res)

def export(ids):
    data = {"export_id": "21111111-1111-1111-1111-111111111111", "source": {"list_type": "scan_result", "id_list": [ids]}}
    res = req.post(server_url + "/api/v1/exports", headers=headers, data=json.dumps(data), verify=False)
    results = res.json()
    report_id = results['report_id']
    res = req.get(server_url + "/api/v1/exports/" + report_id, headers=headers, verify=False)
    results = res.json()
    name = results['source']['description']
    url = results['download']
    while not url:
        res = req.get(server_url + "/api/v1/exports/" + report_id, headers=headers, verify=False)
        results = res.json()
        name = results['source']['description']
        url = results['download']
    name = re.sub("https?://", "", name.split(";")[0]).replace(":",".").split("/")[0]
    download(name, url[0])

def move_file(f, file_aim, file_sub=datetime.now().strftime('%Y_%m_%d_%H_%M_%S')):
    if os.path.isfile(f):
        file_aim_name = os.path.join(file_aim, file_sub, f)
        file_aim_dir = os.path.dirname(file_aim_name)
        if not os.path.exists(file_aim_dir):
            os.makedirs(file_aim_dir)
        shutil.move(f, file_aim_name)
    else:
        file_list = os.listdir(f)
        for ff in file_list:
            ff = os.path.join(f, ff)
            move_file(ff, file_aim)

def config(target_id):
    data = {"scan_speed": "sequential"}
    res = req.patch(server_url + "/api/v1/targets/%s/configuration"%target_id, headers=headers, data=json.dumps(data), verify=False)

parser = OptionParser("python %prog options")

parser.add_option("-a", "--add", dest="addscan", help="添加url", action="store_true")
parser.add_option("-s","--start", dest="start", help="扫描所有未扫面过的url", action="store_true")
parser.add_option("-r","--restart", dest="restart", help="重新扫描所有失败的", action="store_true")
parser.add_option("-d","--delete", dest="delete", help="删除所有目标", action="store_true")
parser.add_option("-o","--down", dest="down", help="下载所有已完成", action="store_true")
parser.add_option('-c', "--checktime", type='int', dest="checktime", help="暂停所有大于x小时的扫描")
parser.add_option("--clean", dest="clean", help="移动已下载到old文件夹", action="store_true")
parser.add_option("--conf", dest="conf", help="设置", action="store_true")
parser.add_option("--delscan", dest="delscan", help="删除所有扫描", action="store_true")
parser.add_option("--downclean", dest="downclean", help="下载所有已完成并删除目标", action="store_true")

(options,args)=parser.parse_args()
parser.print_help() if len(sys.argv)<2 else 0

dbname = 'lib/db/' + urlparse.urlparse(server_url).netloc + '.db'
sql = '' if os.path.exists(dbname) else 'create table domain (domain TEXT primary key)'
conn = sqlite3.connect(dbname)
cursor = conn.cursor()
cursor.execute(sql)

if options.addscan:
    with open("./target.txt") as f:
        for c, url in enumerate(f):
            url = url.strip()
            if url:
                if not url.startswith('http'):
                    url = 'http://' + url
                url_change = urlparse.urlparse(url)
                qurl = url_change.netloc
                cursor.execute('select * from domain where domain=?', (qurl,))
                fetch = cursor.fetchone()
                if fetch:
                    print 'exist %3d: %s' % (c, qurl)
                else:
                    target_id = add_target(url)
                    cursor.execute('insert into domain values (?)', (qurl,))
                    conn.commit()
                    print 'add %3d: %s' % (c, qurl)
if options.start:
    scans = []
    for c, i in enumerate(get_scan()):
        scans.append(i['target']['address'])
    for c, i in enumerate(get_target()):
        if i['address'] not in scans:
            start_target(i['target_id'])
            print 'start %3d: %s' % (c, i['address'])
if options.delete:
    for c, i in enumerate(get_target()):
        delete(i['target_id'])
        qurl = urlparse.urlparse(i['address']).netloc
        cursor.execute('delete from domain where domain=?', (qurl,))
        conn.commit()
        print 'dele %3d: %s' % (c, i['address'])
if options.delscan:
    for c, i in enumerate(get_scan()):
        delscan(i['scan_id'])
        print 'delscan %3d: %s' % (c, i['target']['address'])
if options.down:
    for c, i in enumerate(get_scan()):
        if i['current_session']['status'] == 'completed':
            export(i['current_session']['scan_session_id'])
            print 'down %3d: %s' % (c, i['target']['address'])
if options.clean:
    sub = datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
    move_file('lib/download', 'old', sub)
    move_file('py_report', 'old', sub)
    move_file('target.txt', 'old', sub)
    open('target.txt', 'w')
if options.restart:
    for c, i in enumerate(get_scan()):
        if i['current_session']['status'] == 'failed':
            start_target(i['target_id'])
            delscan(i['scan_id'])
            print 'restart %3d-%6s: %s' % (c, i['current_session']['status'], i['target']['address'])
if options.downclean:
    for c, i in enumerate(get_scan()):
        if i['current_session']['status'] == 'completed':
            export(i['current_session']['scan_session_id'])
            delete(i['target_id'])
            print 'download %3d %6s: %s' % (c, i['current_session']['status'], i['target']['address'])
if options.checktime:
    for c, i in enumerate(get_scan()):
        if i['current_session']['status'] == 'processing':
            _ = datetime.now() - iso8601.parse_date(i['current_session']['start_date']).replace(tzinfo=None)
            if _.seconds > 3600 * options.checktime:
                pausescan(i['scan_id'])
                print 'pausescan %3d: %s' % (c, i['target']['address'])
if options.conf:
    for c, i in enumerate(get_target()):
        config(i['target_id'])
        print 'config %3d: %s' % (c, i['address'])
