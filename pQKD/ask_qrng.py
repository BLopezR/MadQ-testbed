import requests

# API URL for second request
url_qrng = "http://10.4.32.43:8085/qrng/base64?size=16"

try:
    # Make a GET request
    response_qrng = requests.get(url_qrng)

    # Parse response as JSON
    response_qrng_json = response_qrng.json()

    # Store and print the response text
    print("QRNG Response:", response_qrng_json)

    # Extract 'result' key
    ete_key = response_qrng_json['result']
    print(ete_key)

except requests.exceptions.RequestException as e:
    print(f"QRNG Connection error: {e}")
except ValueError as e:
    print(f"Error parsing JSON: {e}")