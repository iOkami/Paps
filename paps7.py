#!/usr/bin/env python3
# HIT - Versao: 1.1

import sys
import requests
import json
import hashlib
import sys
import argparse
import subprocess
import xml.etree.ElementTree as ET

try:
    import xmltodict
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "xmltodict"])
    
# NOTE: This is to suppress the insecure connection warning for certificate verification.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
    args = get_args()

    response = check_session(args.https, args.endpoint)
    
    if  response == False:
        for ip in [args.controllera, args.controllerb]:
            try:
                root = ET.fromstring(login(args.https, ip, args.user, args.password))
                element_response = root.find('.//PROPERTY[@name="response"]').text
                element_responseType = root.find('.//PROPERTY[@name="response-type"]').text

                if element_responseType.upper() != "ERROR":
                    save_session(f"{ip}:{element_response}")
                    response = api_request(args.https, ip, args.endpoint, element_response)
                    # logout(args.https, ip, element_response)
                    break
                else:
                    response = element_responseType

            except Exception as e:
                response = e
                print(f"\n{response}")
                continue

    response = xmltodict.parse(response)['RESPONSE']["OBJECT"]

    filter_keys = None
    if args.filter != None:
        filter_keys = args.filter.split("/")

    response = filter_data(response, filter_keys)
    print(json.dumps(response))

def login(https, apiIP, usuario, senha):
    hash_input = f"{usuario}_{senha}"
    md5_hash = hashlib.md5(hash_input.encode()).hexdigest()
    r = requests.get(f'{https}://{apiIP}/api/login/{md5_hash}', verify=False, timeout=10)
    return(r.text)

def logout(https, apiIP, sessionKey):
    headers = {'Cookie': f'wbisessionkey={sessionKey}'}
    r = requests.get(f'{https}://{apiIP}/api/exit', headers=headers, verify=False)
    return(r.text)

def api_request(https, apiIP, apiEndpoint, sessionKey):
    headers = {'Cookie': f'wbisessionkey={sessionKey}'}
    r = requests.get(f"{https}://{apiIP}{apiEndpoint}", headers=headers, verify=False)
    return(r.text)

def check_session(https, endpoint):
    try:
        with open('/tmp/HIT-HPE-MSA.txt', "r") as file:
            file_content = file.read().split(":")
            ip = file_content[0]
            token = file_content[1]

        response = api_request(https, ip, endpoint, token)
        
        return(response)
    
    except Exception as e:
        return(False)

def save_session(data):
    with open('/tmp/HIT-HPE-MSA.txt', "w") as file:
        file.write(data)

def filter_data(json_data, keys):
    response = []
    
    for obj in json_data:
        resultado = {}

        propriedades = obj.get("PROPERTY", [])

        for propriedade in propriedades:
            
            nome = propriedade.get("@name")
            

            if keys == None:
                resultado[nome] = propriedade.get("#text", "N/A")
            elif nome in keys:
                resultado[nome] = propriedade.get("#text", "N/A")


        objetos = obj.get("OBJECT", False)

        if objetos:
            # sys.exit(json.dumps(objetos))
            resultado[objetos['@name']] = filter_data([objetos], None)

        if len(resultado) > 0:
            response.append(resultado)
    return response

def get_args():
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
