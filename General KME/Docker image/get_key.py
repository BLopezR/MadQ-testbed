import requests
from flask import jsonify
import ast
import json

def get_key_idq(dic, device, size, KSID):
    CERT_FILE_A = './ETSIA.pem'
    CERT_FILE_B = './ETSIB.pem'
    KEY_FILE_A = './ETSIA-key.pem'
    KEY_FILE_B = './ETSIB-key.pem'
    #CA_CERT_FILE = './ChrisCA.pem'
    ip = next((elem_data for color in dic.values() for node in color.values() for name, elem_data in node.get("elements", {}).items() if name == device), None)[0]
    cons = next((elem_data for color in dic.values() for node in color.values() for name, elem_data in node.get("elements", {}).items() if name == device), None)[1]

    if KSID == None:
        url = f"https://{ip}:443/api/v1/keys/{cons}/enc_keys?size={size}"

        if 'B' in cons:
            try:
                response = requests.get(url, cert=(CERT_FILE_A, KEY_FILE_A), verify=False)
            except requests.exceptions.RequestException as e:
                response = {'error': str(e)}
        
        elif "A" in cons:
            try:
                response = requests.get(url, cert=(CERT_FILE_B, KEY_FILE_B), verify=False)
            except requests.exceptions.RequestException as e:
                response = {'error': str(e)}

    else:
        url = f'https://{ip}:443/api/v1/keys/{cons}/dec_keys'
        data = {
                "key_IDs": [
                    {"key_ID": f"{KSID}"}
                ]
                }
        if "B" in cons:
            try:
                response = requests.post(url, json=data, headers = {"Content-Type": "application/json"}, cert=(CERT_FILE_A, KEY_FILE_A), verify=False)
            except requests.exceptions.RequestException as e:
                response = {'error': str(e)}
        elif "A" in cons:
            try:
                response = requests.post(url, json=data, headers = {"Content-Type": "application/json"}, cert=(CERT_FILE_B, KEY_FILE_B), verify=False)
            except requests.exceptions.RequestException as e:
                response = {'error': str(e)}
    return response.content

def get_key_qd2(dic, device, neighbour, size, KSID):
    ip = next((elem_data for color in dic.values() for node in color.values() for name, elem_data in node.get("elements", {}).items() if name == device), None)[0]
    nei_qnode = "q"+neighbour

    if KSID == None:
        url = f"http://{ip}:8000/api/v1/keys/{nei_qnode}/enc_keys?size={size}"
        try:
            response = requests.get(url)
            outer_list = json.loads(response.content.decode('utf-8'))
            key_data = ast.literal_eval(outer_list[0])
            key = key_data['key']
            key_ID = key_data['key_ID']
        except requests.exceptions.RequestException as e:
            key = {'error': str(e)}
            key_ID = None

    else:
        url = f'http://{ip}:8000/api/v1/keys/{nei_qnode}/dec_keys?key_ID={KSID}'
        try:
            response = requests.get(url)
            outer_list = json.loads(response.content.decode('utf-8'))
            key_data = ast.literal_eval(outer_list[0])
            key = key_data['key']
            key_ID = None
        except requests.exceptions.RequestException as e:
            key = {'error': str(e)}
            key_ID = None

    return key, key_ID

def get_key_pqkd(dic, device, size, KSID):
    ip = next((elem_data for color in dic.values() for node in color.values() for name, elem_data in node.get("elements", {}).items() if name == device), None)[0]
    sae = next((elem_data for color in dic.values() for node in color.values() for name, elem_data in node.get("elements", {}).items() if name == device), None)[1]

    if KSID == None:
        url = f"http://{ip}:8082/api/v1/keys/{sae}/enc_keys?size={size}"
        try:
            response = requests.get(url)
        except requests.exceptions.RequestException as e:
            response = {'error': str(e)}

    else:
        url = f'http://{ip}:8082/api/v1/keys/{sae}/dec_keys?key_ID={KSID}'
        try:
            response = requests.get(url)
        except requests.exceptions.RequestException as e:
            response = {'error': str(e)}
    return response.content