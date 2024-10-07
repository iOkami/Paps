#!/usr/bin/env python3
# HIT - Versao: 1.1

import sys
import requests
import json
import hashlib
import sys
import argparse
import xml.etree.ElementTree as ET

# NOTE: This is to suppress the insecure connection warning for certificate verification.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
    args = getArgs()
    for ip in [args.controllera, args.controllerb]:
        try:
            loginResponse = login(args.https, ip, args.user, args.password)
            root = ET.fromstring(loginResponse)
            element_response = root.find('.//PROPERTY[@name="response"]').text
            element_responseType = root.find('.//PROPERTY[@name="response-type"]').text

            if element_responseType.upper() != "ERROR":
                response = apiRequest(args.https, ip, args.endpoint, element_response)
                logout(args.https, ip, element_response)
                break
            else:
                response = loginResponse

        except Exception as e:
            response = e
            continue

    if element_responseType.upper() != "ERROR":
        if args.filter == "json":
            response = convertToJson(response)
        elif args.filter != None:
            response = filterXML(response, args.filter.split("/"))

    print(response)

def login(https, apiIP, usuario, senha):
    hash_input = f"{usuario}_{senha}"
    md5_hash = hashlib.md5(hash_input.encode()).hexdigest()
    r = requests.get(f'{https}://{apiIP}/api/login/{md5_hash}', verify=False, timeout=10)
    return(r.text)

def logout(https, apiIP, sessionKey):
    headers = {'Cookie': f'wbisessionkey={sessionKey}'}
    r = requests.get(f'{https}://{apiIP}/api/exit', headers=headers, verify=False)
    return(r.text)

def apiRequest(https, apiIP, apiEndpoint, sessionKey):
    headers = {'Cookie': f'wbisessionkey={sessionKey}'}

    r = requests.get(f"{https}://{apiIP}{apiEndpoint}", headers=headers, verify=False)
    return(r.text)

def filterXML(xml, propertyList):    
    root = ET.fromstring(xml)
    json_element = []

    for obj in root.findall(".//OBJECT"):
        json_obj = {}

        for property in propertyList:
            propertyValue = obj.find(f".//PROPERTY[@name='{property}']")
            json_obj[property] = propertyValue.text if propertyValue is not None and propertyValue.text is not None else "N/A"

        json_element.append(json_obj)

    return(json.dumps(json_element))

def convertToJson(xml):    
    root = ET.fromstring(xml)
    json_element = []

    for obj in root.findall(".//OBJECT"):
        json_obj = {}
        for property in obj.findall(".//PROPERTY"):
            json_obj[property.get('name')] = property.text

        json_element.append(json_obj)

    return(json.dumps(json_element))

def getArgs():
    parser = argparse.ArgumentParser(description='HIT - Monitoramento Storage DS')
    parser.add_argument('-a', '--controllera', required=True, action='store', help='IP Controller A')
    parser.add_argument('-b', '--controllerb', required=False, action='store', default=None ,help='IP Controller B')
    parser.add_argument('-u', '--user', required=True, action='store', help='Controller Userr')
    parser.add_argument('-p', '--password', required=True, action='store', help='Controller Password')
    parser.add_argument('-e', '--endpoint', required=True, action='store', help='API Endpoint')
    parser.add_argument('-H', '--https', required=False, action='store', default='https', help='Https')
    parser.add_argument('-f', '--filter', required=False, action='store', default=None, help='Filter')
    args = parser.parse_args()

    return args

main()
