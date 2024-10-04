#!/usr/bin/env python3
# HIT - Versao: 1

import sys
import requests
import json
import hashlib
import sys
import argparse
import xml.etree.ElementTree as ET
# import pyperclip

# NOTE: This is to suppress the insecure connection warning for certificate verification.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def dd(text):
    print(text)
    # pyperclip.copy(text)
    sys.exit(1)

def main():
    args = getArgs()
    for ip in [args.controllera, args.controllerb]:
        try:
            root = ET.fromstring(login(args.https, ip, args.user, args.password))
            element_response = root.find('.//PROPERTY[@name="response"]').text
            element_responseType = root.find('.//PROPERTY[@name="response-type"]').text

            if element_responseType.upper() != "ERROR":
                response = apiRequest(args.https, ip, args.endpoint, element_response)
                break
            else:
                response = element_responseType

        except Exception as e:
            response = e
            continue

    if args.endpoint == "/api/show/disks":
        response = filterXML(response, ["durable-id","enclosure-id","architecture-numeric","health-numeric","led-status-numeric","temperature-status-numeric","temperature-status-numeric", "ssd-life-left-numeric"])

    print(response)

def login(https, apiIP, usuario, senha):
    # headers = {'datatype':'json'}
    # headers = {'Content-Type': 'application/json'}
    hash_input = f"{usuario}_{senha}"
    md5_hash = hashlib.md5(hash_input.encode()).hexdigest()
    r = requests.get(f'{https}://{apiIP}/api/login/{md5_hash}', verify=False, timeout=10)
    return(r.text)

def apiRequest(https, apiIP, apiEndpoint, sessionKey):
    # headers = {'sessionKey': sessionKey,
            #    'Content-Type': 'application/json'} #, 'datatype': 'json'}
    # headers = {'sessionKey': sessionKey, 'datatype':'json'}
    headers = {'Cookie': f'wbisessionkey={sessionKey}'}


    r = requests.get(f"{https}://{apiIP}{apiEndpoint}", headers=headers, verify=False)
    return(r.text)

def filterXML(xml, propertyList):    
    # xml_file_path = '/tmp/paps.xml'
    # tree = ET.parse(xml_file_path)
    # root = tree.getroot()
    root = ET.fromstring(xml)
    json_element = []
    for obj in root.findall(".//OBJECT[@basetype='drives']"):
        json_obj = {}

        for property in propertyList:
            propertyValue = obj.find(f".//PROPERTY[@name='{property}']")
            json_obj[property] = propertyValue.text if propertyValue is not None and propertyValue.text is not None else "N/A"


        json_element.append(json_obj)

    return(json.dumps(json_element))

# def getDisks(xml):
#     root = ET.fromstring(xml)
#     json_element = []

#     for obj in root.findall(".//OBJECT[@basetype='drives']"):

#         json_element.append({
#             "durableid": obj.findall(".//PROPERTY[@name='durable-id']")[0].text,
#             "enclosure-id": obj.findall(".//PROPERTY[@name='enclosure-id']")[0].text,
#             "architecture-numeric": obj.findall(".//PROPERTY[@name='architecture-numeric']")[0].text,
#             "health-numeric": obj.findall(".//PROPERTY[@name='health-numeric']")[0].text,
#             "led-status-numeric": obj.findall(".//PROPERTY[@name='led-status-numeric']")[0].text,
#             "status": obj.findall(".//PROPERTY[@name='status']")[0].text,
#             "temperature-numeric": obj.findall(".//PROPERTY[@name='temperature-numeric']")[0].text,
#             "temperature-status-numeric": obj.findall(".//PROPERTY[@name='temperature-status-numeric']")[0].text,
#             "ssd-life-left-numeric": obj.findall(".//PROPERTY[@name='ssd-life-left-numeric']")[0].text,
#         })

#     return json.dumps(json_element)

def getArgs():
    parser = argparse.ArgumentParser(description='HIT - Monitoramento Storage DS')

    parser.add_argument('-a', '--controllera', required=True, action='store', help='IP Controller A')
    parser.add_argument('-b', '--controllerb', required=False, action='store', default=None ,help='IP Controller B')
    parser.add_argument('-u', '--user', required=True, action='store', help='Controller Userr')
    parser.add_argument('-p', '--password', required=True, action='store', help='Controller Password')
    parser.add_argument('-e', '--endpoint', required=True, action='store', help='API Endpoint')
    parser.add_argument('-H', '--https', required=False, action='store', default='https', help='Https')
    # parser.add_argument('-f', '--filter', required=False, action='store', default=None, help='Filter')

    args = parser.parse_args()

    return args

# filterXML()
main()
