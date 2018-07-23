import requests, json, re, sys, time, os, shutil

server_url = "https://127.0.0.1:3443"
apikey = "1986ad8c0a5b3df4d7028d5f3c06e936cf4c53dad7020465b977fdc6a6f1104ce"
headers = {"X-Auth":apikey, "content-type": "application/json"}

requests.packages.urllib3.disable_warnings()
req = requests.Session()

def get_scan():
    next_cursor = '0'
    res = []
    while next_cursor:
        response = requests.get(server_url + "/api/v1/scans?c=" + str(next_cursor), headers=headers, verify=False)
        results = json.loads(response.text)
        next_cursor = results['pagination']['next_cursor']
        for result in results['scans']:
            res.append([result['target']['address'], result['current_session']['scan_session_id'], result['scan_id']])
    return res

def get_target():
    next_cursor = '0'
    res = []
    while next_cursor:
        response = requests.get(server_url + "/api/v1/targets?c=" + str(next_cursor), headers=headers, verify=False)
        results = json.loads(response.text)
        next_cursor = results['pagination']['next_cursor']
        for result in results['targets']:
            res.append([result['address'], result['target_id']])
    return res

def add_target(url):
    data = {"address":url, "description":url, "criticality":"30"}
    res = req.post(server_url + "/api/v1/targets", headers=headers, data=json.dumps(data), verify=False)
    target_id = json.loads(res.text)['target_id']
    return target_id

def start_target(url):
    target_id = add_target(url)
    data = {"target_id":target_id,"profile_id":"11111111-1111-1111-1111-111111111111","schedule": {"disable": False,"start_date":None,"time_sensitive": False}}
    res = req.post(server_url + "/api/v1/scans", headers=headers, data=json.dumps(data), verify=False)

def download(name, url):
    with open("lib/download/" + name, "w") as f:
        res = req.get(server_url + url, headers=headers, verify=False)
        f.write(res.content)


def add_scan():
    with open("./target.txt") as f:
        for i in f:
            url = i.strip()
            if url:
                try:
                    start_target(url)
                except:
                    print 'err:', url

def export(ids):
    data = {"export_id": "21111111-1111-1111-1111-111111111111", "source": {"list_type": "scan_result", "id_list": [ids]}}
    res = req.post(server_url + "/api/v1/exports", headers=headers, data=json.dumps(data), verify=False)
    results = json.loads(res.text)
    report_id = results['report_id']
    res = req.get(server_url + "/api/v1/exports/" + report_id, headers=headers, verify=False)
    results = json.loads(res.text)
    name = results['source']['description']
    url = results['download']
    while not url:
        res = req.get(server_url + "/api/v1/exports/" + report_id, headers=headers, verify=False)
        results = json.loads(res.text)
        name = results['source']['description']
        url = results['download']
    name = re.sub("https?://", "", name.split(";")[0]).replace(":",".").split("/")[0] + ".xml"
    download(name, url[0])

def stop(ids):
    res = req.delete(server_url + "/api/v1/scans/" + ids, headers=headers, verify=False)

def delete(ids):
    res = req.delete(server_url + "/api/v1/targets/" + ids, headers=headers, verify=False)

def move_file(f, file_aim, file_sub=time.strftime('%Y_%m_%d_%H_%M_%S')):
    if os.path.isfile(f):
        file_aim_name = os.path.join(file_aim, file_sub, f)
        file_aim_dir = os.path.dirname(file_aim_name)
        if not os.path.exists(file_aim_dir):
            os.makedirs(file_aim_dir)
        # file_aim_name = os.path.join(file_aim, '_'.join([file_sub, f.replace(os.sep, '_')]))
        shutil.move(f, file_aim_name)
    else:
        file_list = os.listdir(f)
        for ff in file_list:
            ff = os.path.join(f, ff)
            move_file(ff, file_aim)

if len(sys.argv) > 1:
    if sys.argv[1] == "add":
        add_scan()
    elif sys.argv[1] == 'delete':
        for c, (i, j) in enumerate(get_target()):
            delete(j)
            print 'dele %3d: %s' % (c, i)
    elif sys.argv[1] == 'stop':
        for c, (i, j, o) in enumerate(get_scan()):
            stop(o)
            print 'stop %3d: %s' % (c, i)
    elif sys.argv[1] == "down":
        for c, (i, j, o) in enumerate(get_scan()):
            export(j)
            print 'down %3d: %s' % (c, j)
    elif sys.argv[1] == 'clean':
        sub = time.strftime('%Y_%m_%d_%H_%M_%S')
        move_file('lib/download', 'old', sub)
        move_file('py_report', 'old', sub)
        move_file('target.txt', 'old', sub)
        open('target.txt', 'w')