from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Certificados. En realidad el de CA no se utiliza porque no se verifican (habrá que solucionarlo en algún momento)
CERT_FILE_A = './ETSIA.pem'
CERT_FILE_B = './ETSIB.pem'
KEY_FILE_A = './ETSIA-key.pem'
KEY_FILE_B = './ETSIB-key.pem'
CA_CERT_FILE = './ChrisCA.pem'

# IPs de los IDQ (master y slave)
KMSS_IP = '10.4.32.12:443'
KMSM_IP = '10.4.32.11:443'

# Método get key (Alice)
@app.route('/api/v1/keys/CONSBT/enc_keys', methods=['GET'])
def get_key():

    url = f'https://{KMSM_IP}/api/v1/keys/CONSBT/enc_keys'
    try:
        response = requests.get(url, cert=(CERT_FILE_A, KEY_FILE_A), verify=False)
        return response.content, response.status_code, dict(response.headers)
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

# Método get key with ID (Bob)
@app.route('/api/v1/keys/CONSAT/dec_keys', methods=['POST'])
def post_key_with_ID():

    url = f'https://{KMSS_IP}/api/v1/keys/CONSAT/dec_keys'
    data = request.json 
    try:
        response = requests.post(url, json=data, cert=(CERT_FILE_B, KEY_FILE_B), verify=False)
        return response.content, response.status_code, dict(response.headers)
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # El puerto por defecto es el 5000
    app.run(host='0.0.0.0', debug=True)