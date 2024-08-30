import sys
import requests
import json
import hashlib
# NOTE: This is to suppress the insecure connection warning for certificate
# verification.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
USE_BASIC_AUTH = 1
url = "http://192.168.10.238"
username = "hit"
password = "Hit#1234"
# if USE_BASIC_AUTH == 1:
#     # HTTP basic authentication
headers = {'datatype':'json'}
r = requests.get(url + '/api/login', auth=(username, password), headers=headers, verify=False)
# r = requests.get(f'{url}/api/login/d34f7553a8c4e0b07fb98c375a236496', verify=False)

# else:
    # SHA-256 authentication
# auth_bytes = bytes(username + '_' + password, 'utf-8')
# auth_string = hashlib.sha256(auth_bytes).hexdigest()
# headers = {'datatype':'json'}
# r = requests.get(url + '/api/login/' + auth_string, headers=headers, verify=False )
print(r)
print(r.text)
# # Extract session key from response
# response = json.loads(r.content.decode('utf-8'))
# sessionKey = response['status'][0]['response']

# print(sessionKey)
# # Obtain the health of the system
# headers = {'sessionKey': sessionKey, 'datatype':'json'}
# r = requests.get(url+'/api/show/system', headers=headers, verify=False)

# print(r)
# print(r.text)

# print(r.content.decode('utf-8'))
# response = json.loads(r.content)
# print("Health = " + response['system'][0]['health'])
