import requests
from flask import Flask, request, jsonify

# Hay que instalar flask, requests

app = Flask(__name__)

# Mapping of KME IPs to corresponding pQKD IPs
KME_TO_DEVICE_MAP = {
    "10.4.33.41": "10.4.32.42",  # Alice, KME 1
    "10.4.33.75": "10.4.32.43"   # Bob, KME extra
}

# Server configuration
PORT = 5000

# Flask expects a route with this format and when it gets one, it extracts target and action
# Action refers to either encrypt (when petition is get_key) or decrypt (when petition is 
# get_ket_with_id)
@app.route("/api/v1/keys/<path:full_path>", methods=["GET"])
def forward_request(full_path):
    """
    Receives any request to /api/v1/keys/* and forwards it to the correct external device.
    Keeps the same path and query parameters, only changing the IP.
    """

    # Get the IP of the KME (the server's own IP)
    kme_ip = request.host.split(":")[0]  # Extract IP from the request URL
    print(f"Received request at KME {kme_ip} for path: {full_path} with params: {request.args}")

    # Check if the KME IP is recognized
    if kme_ip not in KME_TO_DEVICE_MAP:
        return jsonify({"error": "Unrecognized KME IP"}), 400

    # Get the pQKD's IP
    pqkd_ip = KME_TO_DEVICE_MAP[kme_ip]
    base_url = f"http://{pqkd_ip}:8082/api/v1/keys/{full_path}"
    query_string = "&".join([f"{key}={value}" for key, value in request.args.items()])
    target_url = f"{base_url}?{query_string}" if query_string else base_url  # Only add "?" if there are parameters

    print(f"Forwarding request to: {target_url}")  # Debugging output

    try:
        # Forward the request with all query parameters
        response = requests.get(target_url)
        response.raise_for_status()

        # Return the external response to the client
        return jsonify(response.json())

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"External request failed: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)  # Running with SSL