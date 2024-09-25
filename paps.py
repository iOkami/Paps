#!/usr/bin/env python3

import sys
import requests
import json
import hashlib
import sys
from base64 import b64encode
# NOTE: This is to suppress the insecure connection warning for certificate verification.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
    global usuario, senha, url, sessionKey, discovery
    usuario = sys.argv[1]
    senha = sys.argv[2]
    url = "https://" + sys.argv[3]
    discovery = sys.argv[4]

    sessionKey = login()
    if sessionKey != "Invalid sessionkey":
        if discovery == "sysinfo":
            SysInfo()

        elif discovery == "volumes":
            Volumes()

        elif discovery == "volumestatistics":
            VolumeStatistics()

        elif discovery == "pools":
            Pools()

        elif discovery == "powersupplies":
            PowerSupplies()

        elif discovery == "disks":
            Disks()
        
        elif discovery == "fans":
            Fans()
            
        elif discovery == "sensorstatus":
            Sensors()

        else:
            print("Discovery não encontrado")
    else:
        print("Invalid session key. Unable to obtain system information.")

def basic_auth(username, password):
	token = b64encode(f"{username}:{password}".encode('utf-8')).decode("ascii")
	return f'Basic {token}'

def login():
    # Login and obtain the session key.
    headers = {'datatype': 'json', 'Authorization': basic_auth(usuario, senha)}
    # r = requests.get(url + '/api/login/', headers=headers, verify=False)

    hash_input = f"{usuario}{senha}"
    md5_hash = hashlib.md5(hash_input.encode()).hexdigest()

    r = requests.get(url + f'/api/login/{md5_hash}', headers=headers, verify=False)

    response = json.loads(r.content)
    return(response['status'][0]['response'])

def SysInfo():
    # Obtain the health of the system.
    headers = {'sessionKey': sessionKey, 'datatype': 'json'}
    r = requests.get(url + '/api/show/system', headers=headers, verify=False)
    response = json.loads(r.content)
    response = json.dumps(response, separators=(',',':'))
    print(response)
    
def Volumes():
    # Obtain the health of the system.
    headers = {'sessionKey': sessionKey, 'datatype': 'json'}
    r = requests.get(url + '/api/show/volumes', headers=headers, verify=False)
    response = json.loads(r.content)
    response = response['volumes']
    response = json.dumps(response, separators=(',',':'))
    print(response)

def VolumeStatistics():
    # Obtain the health of the system.
    headers = {'sessionKey': sessionKey, 'datatype': 'json'}
    r = requests.get(url + '/api/show/volume-statistics', headers=headers, verify=False)
    response = json.loads(r.content)
    response = response['volume-statistics']
    response = json.dumps(response, separators=(',',':'))
    print(response)

def Pools():
    # Obtain the health of the system.
    headers = {'sessionKey': sessionKey, 'datatype': 'json'}
    r = requests.get(url + '/api/show/pools', headers=headers, verify=False)
    response = json.loads(r.content)
    response = response['pools']
    response = json.dumps(response, separators=(',',':'))
    print(response)

def PowerSupplies():
    # Obtain the health of the system.
    headers = {'sessionKey': sessionKey, 'datatype': 'json'}
    r = requests.get(url + '/api/show/power-supplies', headers=headers, verify=False)
    response = json.loads(r.content)
    response = response['power-supplies']
    response = json.dumps(response, separators=(',',':'))
    print(response)

def Disks():
    # Obtain the health of the system.
    headers = {'sessionKey': sessionKey, 'datatype': 'json'}
    r = requests.get(url + '/api/show/disks', headers=headers, verify=False)
    response = json.loads(r.content)
    response = response['drives']
    response = json.dumps(response, separators=(',',':'))
    print(response)

def Fans():
    # Obtain the health of the system.
    headers = {'sessionKey': sessionKey, 'datatype': 'json'}
    r = requests.get(url + '/api/show/fans', headers=headers, verify=False)
    response = json.loads(r.content)
    response = response['fan']
    response = json.dumps(response, separators=(',',':'))
    print(response)

def Sensors():
    # Obtain the health of the system.
    headers = {'sessionKey': sessionKey, 'datatype': 'json'}
    r = requests.get(url + '/api/show/sensor-status', headers=headers, verify=False)
    response = json.loads(r.content)
    response = response['sensors']
    response = json.dumps(response, separators=(',',':'))
    print(response)

main()
