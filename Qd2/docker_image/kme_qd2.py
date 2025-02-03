import onetimepad
from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import socket
from qd2_client.qd2_etsi_004_client import Client004, Status
from urllib.parse import urlparse
import secrets
import threading
import csv

qclient = Client004()
size = 16

kme_name = "kme-"
ip = "10.244.0."
mv_ip = "10.4.32."

# Clave: IP de la MV del KME. Valores: IP del qnode, nombre de la app, ip del KME anterior y la IP del
# KME en el siguiente salto
dic_ips = {
    "10.4.32.221": ["10.4.32.207", "app1@qnode1", "10.4.32.96"],
    "10.4.32.96": ["10.4.32.121", "app2@qnode2", "10.4.32.221", "10.4.32.144"],
    "10.4.32.144": ["10.4.32.107", "app5@qnode5", "10.4.32.96", "10.4.32.227"],
    "10.4.32.227": ["10.4.32.153", "app7@qnode7", "10.4.32.144", "10.4.32.236"],
    "10.4.32.236": ["10.4.32.252", "app6@qnode6", "10.4.32.227"]
}

qclient.connect(dic_ips[mv_ip][0])

new_ksid = threading.Event()
change_path = threading.Event()
received_ete = threading.Event()

def ksid_socket():
    global prev_ksid

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 65431))
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                recibiendo = True
                while recibiendo:
                    data = conn.recv(1024)
                    prev_ksid = data
                    recibiendo = False
                new_ksid.set()

def key_socket():
    global end_to_end_encrypted

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 65433))
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                recibiendo = True
                while recibiendo:
                    end_to_end_encrypted = conn.recv(1024).hex()
                    recibiendo = False
                received_ete.set()

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global end_to_end
        global end_to_end_encrypted

        parsed_path = urlparse(self.path) #In theory, the url request must follow the ETSI 014 standard, an example would be: http://KME_IP/api/v1/keys/APP_ID/enc_keys?src=SRC_kme_name&dst=DST_kme_name&size=16
        path_list = parsed_path[2].split("/")
        request_param = parsed_path[4].split("&")

        app_ID = path_list[4]
        src = request_param[0].split("=")[1]
        dst = request_param[1].split("=")[1]
        size = int(request_param[2].split("=")[1])
        print(f"Request from app {app_ID}. Request soruce: {src}, request destination: {dst}, key size: {size}")

        if src == mv_ip: #Case in which the application made the request to the "first" KME
            end_to_end = secrets.token_bytes(size) #Initial KME has to create the end-to-end key
            next_kme_ip = dic_ips[mv_ip][2]

            #Start key stream with the next KME
            response = qclient.open_connect(dic_ips[mv_ip][1], dic_ips[next_kme_ip][1], key_chunk_size=size, ttl=100000, ksid=None)
            ksid1 = response["ksid"]
            print("Key stream response with next kme: ", response)
            #Send the key stream ID to the next KME
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((next_kme_ip, 30001))
                data = ksid1
                s.sendall(data)
            time.sleep(2)
            #Retrieve quantum key from the key stream
            while True:
                response = qclient.get_key(ksid1)
                if response["status"]==Status.SUCCESSFUL:
                    key = response["key_buffer"]
                    break
            print("Retrieved quantum key: ", key)
            #Encrypt end-to-end key using OTP and send it to the next KME
            end_to_end_encrypted = onetimepad.encrypt(end_to_end.hex(), key.hex())
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((next_kme_ip, 30003))
                s.sendall(bytes.fromhex(end_to_end_encrypted))

        elif dst == mv_ip: #Case in which the application made the request to the "last" KME
            #Wait for a ksid
            new_ksid.wait()
            prev_kme_ip = dic_ips[mv_ip][2]
            response = qclient.open_connect(dic_ips[prev_kme_ip][1], dic_ips[mv_ip][1], key_chunk_size=size, ttl=100000, ksid=prev_ksid)
            print("Key stream response with previous kme: ", response)
            while True:
                response = qclient.get_key(prev_ksid)
                if response["status"]==Status.SUCCESSFUL:
                    key = response["key_buffer"]
                    break
            print("Retireved quantum key: ", key)
            #Wait for the encrypted end-to-end key
            received_ete.wait()
            end_to_end = bytes.fromhex(onetimepad.decrypt(end_to_end_encrypted, key.hex()))

            #Send response to the application
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        response_content = f"Key: {end_to_end}"
        self.wfile.write(response_content.encode())

def forwarding_ete():
    global end_to_end_encrypted

    while True:
        new_ksid.wait()
        previous_kme_ip = dic_ips[mv_ip][2]
        # Obtain common key with previous kme
        response = qclient.open_connect(dic_ips[previous_kme_ip][1],  dic_ips[mv_ip][1], key_chunk_size=size, ttl=100000, ksid=prev_ksid)
        print("Key stream response with previous kme: ", response)
        while True:
            response = qclient.get_key(prev_ksid)
            if response["status"]==Status.SUCCESSFUL:
                key1 = response["key_buffer"]
                break
        print("Retireved quantum key: ", key1)

        # Receive encrypted end to end key from previous kme
        received_ete.wait()
        end_to_end = bytes.fromhex(onetimepad.decrypt(end_to_end_encrypted, key1.hex()))
        next_kme = dic_ips[mv_ip][3]
        # Connect with next qnode
        response = qclient.open_connect(dic_ips[mv_ip][1], dic_ips[next_kme][1], key_chunk_size=size, ttl=100000, ksid=None)
        ksid2 = response["ksid"]
        print("Key stream response with next kme: ", response)
        #Send the key stream ID to the next KME
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((next_kme, 30001))
            data = ksid2
            s.sendall(data)
        time.sleep(2)
        #Retrieve quantum key (common with next kme) from the key stream
        while True:
            response = qclient.get_key(ksid2)
            if response["status"]==Status.SUCCESSFUL:
                key2 = response["key_buffer"]
                break
        print("Retireved quantum key: ", key2)
        #Encrypt end-to-end key using OTP and send it to the next KME
        end_to_end_encrypted = onetimepad.encrypt(end_to_end.hex(), key2.hex())
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((next_kme, 30003))
            s.sendall(bytes.fromhex(end_to_end_encrypted))

if __name__=="__main__":

    ksid_socket_thread = threading.Thread(target=ksid_socket)
    key_socket_thread = threading.Thread(target=key_socket)

    ksid_socket_thread.start()
    key_socket_thread.start()


    if kme_name=="kme-1" or kme_name=="kme-5": # if kme is an end one
        http_host = ip
        http_port = 65435
        webServer = HTTPServer((http_host, http_port), MyHandler)
        http_server_thread = threading.Thread(target=webServer.serve_forever())
        print("Server started http://%s:%s"%(http_host, http_port))

        try:
            http_server_thread.start()
        except KeyboardInterrupt:
            pass

        webServer.server_close()
        print("Server stopped")

    else:
        fwd_thread = threading.Thread(target=forwarding_ete)
        fwd_thread.start()