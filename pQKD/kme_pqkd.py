import socket
import threading
import requests
import json

"""Esto ahora mismo está de forma que en la prueba se tiene que hacer la petición a Bob y luego
hacer el get key with ID a Alice. Habría que generalizarlo para que se le pudiese hacer a cualquiera. 
Pero no sé bien cómo hacer esta trampa. Puede ser con las IPs de los KMEs que así sepan con quien están
conectados o algo nose"""

# API URLs
API_URL = "https://10.4.32.43:8082/api/v1/keys/AliceSAE/enc_keys"
API_URL_KSID = "https://10.4.32.42:8082/api/v1/keys/BobSAE/dec_keys?key_ID="

# Certificate and private key
CERT = ("qbck-client.crt", "qbck-client-decrypted.key")
CA_CERT = "qbck-ca.crt"

# Server settings
HOST = "0.0.0.0"
PORT = 65432  # Change if needed

def get_key_from_pqkd(ksid = None):
    """Retrieves a key from the remote API, using different endpoints based on request type."""
    try:
        url = API_URL_KSID + ksid if ksid else API_URL
        
        # Make GET request
        response = requests.get(url, cert=CERT, verify=CA_CERT)
        response.raise_for_status()  # Raise error for bad response

        # Parse response JSON
        response_json = response.json()
        key = response_json['keys'][0]['key']
        ksid = response_json['keys'][0]['key_ID']

        print(f"Retrieved key: {key}")
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
                
                # Receive data from client
                data = conn.recv(1024).decode()
                ksid = data if data else None
                
                key, ksid = get_key_from_pqkd(ksid=ksid)
                
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
