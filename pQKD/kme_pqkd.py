import socket
import threading
import requests
import json

# API URL
API_URL = "https://10.4.32.43:8082/api/v1/keys/AliceSAE/enc_keys"

# Certificate and private key
CERT = ("qbck-client.crt", "qbck-client-decrypted.key")
CA_CERT = "qbck-ca.crt"

# Server settings
HOST = "0.0.0.0"
PORT = 65432  # Change if needed

def get_key_from_pqkd():
    """Retreives a key from the remote API."""
    try:
        # Make GET request
        response = requests.get(API_URL, cert=CERT, verify=CA_CERT)
        response.raise_for_status()  # Raise error for bad response

        # Parse response JSON
        response_json = response.json()
        key = response_json['keys'][0]['key']
        ksid = response_json['keys'][0]['key_ID']

        print(f"Retreived key: {key}")
        print(f"Key ID: {ksid}")

        return key, ksid

    except requests.exceptions.RequestException as e:
        print(f"Error fetching key: {e}")
        return None, None

def key_socket():
    """Socket server that listens for key requests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        print(f"Key server running on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connection from {addr}")

                # Retrieve key when a request is received
                retreiving = True
                while retreiving:
                    key, ksid = get_key_from_pqkd()
                    retreiving = False

                if key and ksid:
                    response_data = json.dumps({"key": key, "ksid": ksid})
                    conn.sendall(response_data.encode())
                else:
                    conn.sendall(b"Error: Failed to retrieve key.")

if __name__ == "__main__":
    # Start server thread
    server_thread = threading.Thread(target=key_socket, daemon=True)
    server_thread.start()

    try:
        server_thread.join()
    except KeyboardInterrupt:
        print("\nServer shutting down.")

