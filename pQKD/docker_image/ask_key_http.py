import requests

# API URL
url = "http://10.4.32.43:8082/api/v1/keys/AliceSAE/enc_keys"


try:
    # Make a GET request with certificate authentication
    response = requests.get(url)

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