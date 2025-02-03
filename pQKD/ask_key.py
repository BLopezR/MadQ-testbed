import requests

# API URL
url = "https://10.4.32.43:8082/api/v1/keys/AliceSAE/enc_keys"

# Certificate and private key files (must be in directory)
# Tengo que en la imagen de docker poner la clave desencriptada 
# directamente o poner la encriptada y añadir una linea de comando 
# en la imagen que la desencripte, que es esta:
# openssl rsa -in qbck-client.key -out qbck-client-decrypted.key -passin pass:password2
cert = ("qbck-client.crt", "qbck-client-decrypted.key")
cafile = "qbck-ca.crt"

try:
    # Make a GET request with certificate authentication
    response = requests.get(url, cert=cert, verify=cafile)

    # Parse response as JSON
    response_json = response.json()


    # Check if the request was successful
    if response.status_code == 200:
        print("Successful response:")
        print(response_json)

        # Extract key
        key = response_json['keys'][0]['key']

        # Extract key ID
        ksid = response_json['keys'][0]['key_ID']
    else:
        print(f"Request error: {response.status_code}")
        print(response.text)

except requests.exceptions.RequestException as e:
    print(f"Connection error: {e}")