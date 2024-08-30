import sys
import requests
import json
import hashlib

# NOTE: This is to suppress the insecure connection warning for certificate
# verification.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
USE_BASIC_AUTH = 1
url = "http://192.168.10.198"
username = "hit"
password = "Hit#1234"
# if USE_BASIC_AUTH == 1:
#     # HTTP basic authentication
headers = {'datatype':'json'}
r = requests.get(url + '/api/login', auth=(username, password), headers=headers, verify=False)
# r = requests.get(f'{url}/api/login/d34f7553a8c4e0b07fb98c375a236496', verify=False)

print(r)
print(r.text)
