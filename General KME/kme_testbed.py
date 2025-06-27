import onetimepad
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import time
import socket
from urllib.parse import urlparse
import secrets
import threading
import networkx as nx 
from collections import OrderedDict
import json
import base64
from queue import Queue
import uuid
import yaml
from get_key import *

# General information
with open('topology.yaml', 'r') as file:
    dic_ips = yaml.safe_load(file)

kme_dic = {}
for color_group in dic_ips.values():
    for node, data in color_group.items():
        for key, value in data["elements"].items():
            if key.startswith("kme"):
                kme_dic[node] = value[0]
                break

#Specific information
hostname = socket.gethostname()
my_node = "node"+hostname[4]
my_ip = kme_dic[my_node]

#Threaded ecosystem
thread_local = threading.local()

#Graph of the network to choose paths
G = nx.MultiGraph()

# Add nodes
for color, nodes in dic_ips.items():
    for node in nodes:
        G.add_node(node, color=color)

# Add edges with domain info
for color_group in dic_ips.values():
    for node, properties in color_group.items():
        for neighbor in properties["neighbours"]:
            if neighbor in G:
                G.add_edge(node, neighbor, interdomain=(G.nodes[node]["color"] != G.nodes[neighbor]["color"]))

my_color = G.nodes[my_node]["color"]
neighbor_colors_function = lambda G, target_color: {
    G.nodes[nbr]["color"]
    for node in G.nodes
    if G.nodes[node]["color"] == target_color
    for nbr in G.neighbors(node)
    if G.nodes[nbr]["color"] != target_color
}
neighbor_colors = neighbor_colors_function(G, my_color)

#Sockets for receiving information
reply_queues = {}
def next_hop_information_socket():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 65432))
        s.listen()
        while True:
            conn, addr = s.accept()
            prev_hop_information_handler_thread= threading.Thread(target=next_hop_information_handler, args=(conn,addr),daemon=True)
            prev_hop_information_handler_thread.start()

queue_created = threading.Event()
def next_hop_information_handler(conn, addr):
    with conn:
        print(f"Connected by {addr}")
        buffer = b'' #The message can be long so this is a way to be sure we are getting it complete
        while True:
            part = conn.recv(4096)
            if not part:
                break
            buffer += part
            message, buffer = buffer.split(b'\n', 1) #The sender side ends the message with a line break
            break
        data = json.loads(message.decode('utf-8'))
        petition_id = data[0]
        next_hop = data[1]
        size = data[2]
        dst = data[3]
        print(f'Information received: \npetition id: {petition_id}\nnext hop: {next_hop}\nsize: {size}')
        thread_local.q = Queue()
        thread_local.q_id = petition_id
        reply_queues[petition_id] = thread_local.q
        print(f"Queue {petition_id} created")
        queue_created.set()
        if size != 0:
            fwd_thread = threading.Thread(target=midle_actor, args=(petition_id, next_hop, size, dst, thread_local.q), daemon=True)
            print("Starting middle actor thread")
            fwd_thread.start()

def prev_hop_information_socket():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 65431))
        s.listen()
        while True:
            conn, prev_node = s.accept()
            prev_hop_information_handler_thread= threading.Thread(target=prev_hop_information_handler, args=(conn, prev_node),daemon=True)
            prev_hop_information_handler_thread.start()

def prev_hop_information_handler(conn, prev_node):
    with conn:
        print(f"Connected by {prev_node[0]}")
        buffer = b'' #The message can be long so this is a way to be sure we are getting it complete
        while True:
            part = conn.recv(4096)
            if not part:
                break
            buffer += part
            message, buffer = buffer.split(b'\n', 1) #The sender side ends the message with a line break
            break
        data = json.loads(message.decode('utf-8'))
        petition_id = data[0]
        prev_ksid = data[1]
        ete_key_encripted = data[2]
        print(f'Informaiton received: \nkey ID: {prev_ksid}\nete_key encripted: {ete_key_encripted}')
        q = reply_queues.get(petition_id)
        if q:
            q.put((prev_ksid, ete_key_encripted, prev_node[0]))
            print(f'Information added to queue {petition_id}')

#HTTP Server

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):

        parsed_path = urlparse(self.path) #The url request must follow the ETSI 014 standard, an example would be: http://KME_IP/api/v1/keys/enc_keys?src=SRC_node&dst=DST_node&size=16&id=8271
        request_param = parsed_path[4].split("&")
        src = [item.split("=")[1] for item in request_param if item.startswith("src")]
        dst = [item.split("=")[1] for item in request_param if item.startswith("dst")]
        size = [int(s.split("=")[1]) for s in [item for item in request_param if item.startswith("size")]]
        id= [item.split("=")[1] for item in request_param if item.startswith("id")]
        print(f"Key request received. Request soruce: {src[0]}, request destination: {dst[0]}, key size: {size}, id: {id[0]}")

        #Right now only one src and one dst is supported
        if my_node == src[0]:
            ete_key = initial_actor(src[0], dst[0], size[0], id[0])
            print("Starting initial actor thread")

        elif my_node == dst[0]:
                ete_key = end_actor(size[0], id[0])
                print('Starting end actor thread')

        response_ete = base64.b64encode(ete_key).decode('ascii')
        response_content = json.dumps({"key": response_ete}).encode('utf-8')
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", str(len(response_content)))
        self.end_headers()
        self.wfile.write(response_content)

def initial_actor(src, dst, sz, id):
    ete_key = secrets.token_bytes(sz)
    
    choice = nx.shortest_path(G, source=src, target=dst) #Se computa el camino completo pero solo se utiliza el mismo color + una frontera
    cropped = [choice[0]]
    for node in choice[1:]:
        node_color = G.nodes[node]['color']
        print(node, node_color)
        if node_color == my_color:
            cropped.append(node)
        else:
            cropped.append(node)  # allow ending on the first different color
            break

    chosen_path = OrderedDict({
        node: kme_dic[node]
        for node in cropped[1:] 
        if node in kme_dic
    })
    
    print(f"Chosen path: {chosen_path}")
    my_next_hop = chosen_path.popitem(last=False)
    my_device = dic_ips[my_color][my_node]["neighbours"][my_next_hop[0]]
    next_hop = my_next_hop
    for hop in chosen_path.items(): #Src KME sends to every KME in the path its next hop
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((next_hop[1], 65432))
            data_hop = [id, [item for item in hop], sz, dst]
            data_hop_send = json.dumps(data_hop).encode('utf-8')+b'\n'
            s.sendall(data_hop_send)
            time.sleep(1)
        next_hop = hop

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((next_hop[1], 65432))
            data_hop = [id, None, sz, dst]
            data_hop_send = json.dumps(data_hop).encode('utf-8')+b'\n'
            s.sendall(data_hop_send)

    if my_device.startswith("pqkd"):
        print(f"Requesting key from {my_device}")
        response = get_key_pqkd(dic=dic_ips, device=my_device, size=sz, KSID=None)
        data = json.loads(response.decode('utf-8'))
        first_key_info = data["keys"][0]
        key = first_key_info["key"].encode()
        key_ID = first_key_info["key_ID"]
    elif my_device.startswith("qd2"):
        print(f"Requesting key from {my_device}")
        key_0, key_ID = get_key_qd2(dic=dic_ips, device=my_device, neighbour=my_next_hop[0], size=sz, KSID=None)
        key = key_0.encode()
    elif my_device.startswith("idq"):
        print(f"Requesting key from {my_device}")
        response = get_key_idq(dic=dic_ips, device=my_device, size=sz, KSID=None)
        data = json.loads(response.decode('utf-8'))
        first_key_info = data["keys"][0]
        key = first_key_info["key"].encode()
        key_ID = first_key_info["key_ID"]

    ete_key_encripted = onetimepad.encrypt(ete_key.hex(), key.hex())
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: #Sends the KSID and the end to end key encripted to the next hop
        print(f'Sending the ete_key encripted to {my_next_hop}')
        s.connect((my_next_hop[1], 65431))
        data = [id, key_ID, ete_key_encripted]
        data_send = json.dumps(data).encode('utf-8')+b'\n'

        s.sendall(data_send)
    return ete_key

def midle_actor(petition_id, my_next_hop, size, dst, reply_q):
    
    prev_ksid, ete_key_encripted, prev_node_ip_middle = reply_q.get()
       
    prev_node = next((key for key, val in kme_dic.items() if val == prev_node_ip_middle), None)
    my_device = dic_ips[my_color][my_node]["neighbours"][prev_node]

    if my_device.startswith("pqkd"):
        print(f"Requesting key from {my_device}")
        response = get_key_pqkd(dic=dic_ips, device=my_device, size=size, KSID=prev_ksid)
        data = json.loads(response.decode('utf-8'))
        first_key_info = data["keys"][0]
        key = first_key_info["key"].encode()
        key_ID = first_key_info["key_ID"]

    elif my_device.startswith("qd2"):
        print(f"Requesting key from {my_device}")
        key_0, key_ID = get_key_qd2(dic=dic_ips, device=my_device, neighbour=prev_node, size=size, KSID=prev_ksid)
        key = key_0.encode()

    elif my_device.startswith("idq"):
        print(f"Requesting key from {my_device}")
        response = get_key_idq(dic=dic_ips, device=my_device, size=size, KSID=prev_ksid)
        data = json.loads(response.decode('utf-8'))
        first_key_info = data["keys"][0]
        key = first_key_info["key"].encode()
        key_ID = first_key_info["key_ID"]

    dec_hex = onetimepad.decrypt(ete_key_encripted, key.hex())
    ete_key = bytes.fromhex(dec_hex)

    if my_next_hop == None:
        choice = nx.shortest_path(G, source=my_node, target=dst) #Se computa el camino completo pero solo se utiliza el mismo color + una frontera
        cropped = [choice[0]]
        for node in choice[1:]:
            node_color = G.nodes[node]['color']
            print(node, node_color)
            if node_color == my_color:
                cropped.append(node)
            else:
                cropped.append(node)  # allow ending on the first different color
                break

        chosen_path = OrderedDict({
            node: kme_dic[node]
            for node in cropped[1:] 
            if node in kme_dic
        })
        my_next_hop = chosen_path.popitem(last=False)
        my_device = dic_ips[my_color][my_node]["neighbours"][my_next_hop[0]]
        next_hop = my_next_hop
        for hop in chosen_path.items(): #Src KME sends to every KME in the path its next hop
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((next_hop[1], 65432))
                data_hop = [id, [item for item in hop], size, dst]
                data_hop_send = json.dumps(data_hop).encode('utf-8')+b'\n'
                s.sendall(data_hop_send)
                time.sleep(1)
            next_hop = hop

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((next_hop[1], 65432))
                    data_hop = [id, None, size, dst]
                    data_hop_send = json.dumps(data_hop).encode('utf-8')+b'\n'
                    s.sendall(data_hop_send)

    my_device = dic_ips[my_color][my_node]["neighbours"][my_next_hop[0]]

    if my_device.startswith("pqkd"):
            print(f"Requesting key from {my_device}")
            response = get_key_pqkd(dic=dic_ips, device=my_device, size=size, KSID=None)
            data = json.loads(response.decode('utf-8'))
            first_key_info = data["keys"][0]
            key = first_key_info["key"].encode()
            key_ID = first_key_info["key_ID"]

    elif my_device.startswith("qd2"):
            print(f"Requesting key from {my_device}")
            key_0, key_ID = get_key_qd2(dic=dic_ips, device=my_device, neighbour=next_hop[0], size=size, KSID=None)
            key = key_0.encode()

    elif my_device.startswith("idq"):
            print(f"Requesting key from {my_device}")
            response = get_key_idq(dic=dic_ips, device=my_device, size=size, KSID=None)
            data = json.loads(response.decode('utf-8'))
            first_key_info = data["keys"][0]
            key = first_key_info["key"].encode()
            key_ID = first_key_info["key_ID"]

    ete_key_encripted = onetimepad.encrypt(ete_key.hex(), key.hex())

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((my_next_hop[1], 65431))
        data = [petition_id, key_ID, ete_key_encripted]
        data_send = json.dumps(data).encode('utf-8')+b'\n'
        s.sendall(data_send)

def end_actor(sz, id):
    queue_created.wait()
    queue_created.clear()
    reply_q = reply_queues.get(id)
    prev_ksid, ete_key_encripted, prev_node_ip = reply_q.get()

    prev_node = next((key for key, val in kme_dic.items() if val == prev_node_ip), None)
    my_device = dic_ips[my_color][my_node]["neighbours"][prev_node]

    if my_device.startswith("pqkd"):
        print(f"Requesting key from {my_device}")
        response = get_key_pqkd(dic=dic_ips, device=my_device, size=sz, KSID=prev_ksid)
        data = json.loads(response.decode('utf-8'))
        first_key_info = data["keys"][0]
        key = first_key_info["key"].encode()
        key_ID = first_key_info["key_ID"]

    elif my_device.startswith("qd2"):
        print(f"Requesting key from {my_device}")
        key_0, key_ID = get_key_qd2(dic=dic_ips, device=my_device, neighbour=prev_node, size=sz, KSID=prev_ksid)
        key = key_0.encode()

    elif my_device.startswith("idq"):
        print(f"Requesting key from {my_device}")
        response = get_key_idq(dic=dic_ips, device=my_device, size=sz, KSID=prev_ksid)
        data = json.loads(response.decode('utf-8'))
        first_key_info = data["keys"][0]
        key = first_key_info["key"].encode()
        key_ID = first_key_info["key_ID"]
    
    dec_hex = onetimepad.decrypt(ete_key_encripted, key.hex())
    ete_key = bytes.fromhex(dec_hex)

    return ete_key

if __name__=="__main__":

    next_hop_socket_thread = threading.Thread(target=next_hop_information_socket, daemon=True)
    next_hop_socket_thread.start()
    prev_hop_socket_thread = threading.Thread(target=prev_hop_information_socket, daemon = True)
    prev_hop_socket_thread.start()


    http_host = my_ip
    http_port = 65435
    webServer = ThreadedHTTPServer((http_host, http_port), MyHandler)
    http_server_thread = threading.Thread(target=webServer.serve_forever)

    try:
        http_server_thread.start()
        print("Server started http://%s:%s"%(http_host, http_port))
    except KeyboardInterrupt:
        webServer.shutdown()
        webServer.server_close()
        print("Server stopped")