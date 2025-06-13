import socket
import base64
import json
import os
import ssl
import time,uuid
import platform
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import colorama
colorama.init()

# Define some ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Config
CAFILE    = "ca.pem"
CLIENT_CERT = "client.pem"
CLIENT_KEY  = "client.key"
SERVER_NAME = "your.server.name"  # must match CN in server cert
TIME_WINDOW = 30

def create_ssl_context():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CAFILE)
    ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    ctx.check_hostname = True
    return ctx


# Load server's public RSA key
def load_server_public_key():
    with open("server_public.pem", "rb") as key_file:
        return RSA.import_key(key_file.read())

# Encrypt the AES key using the server's public key
def encrypt_aes_key(aes_key, server_public_key):
    cipher_rsa = PKCS1_OAEP.new(server_public_key)
    return base64.b64encode(cipher_rsa.encrypt(aes_key)).decode()


def start_secure_client(host='192.168.188.148', port=5555):
    server_public_key = load_server_public_key()
    sslctx = create_ssl_context()
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = sslctx.wrap_socket(raw, server_hostname=SERVER_NAME)
    conn.connect((host, port))

    # ----- Encrypted Authentication Phase -----
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    ts = str(time.time())
    nonce = uuid.uuid4().hex
    creds = f"{username},{password},{ts},{nonce}".encode()
    cipher_rsa = PKCS1_OAEP.new(load_server_public_key())
    enc = base64.b64encode(cipher_rsa.encrypt(creds))
    conn.sendall(enc)
    # ----- End Auth Phase ----

    # Generate AES key and send it encrypted to the server
    aes_key = get_random_bytes(16)
    encrypted_aes_key = encrypt_aes_key(aes_key, server_public_key)
    conn.sendall(encrypted_aes_key.encode())
    print(f"{BLUE}Secure AES key sent to server")

    # Command loop
    while True:
        command = input(f"{GREEN}{username}{MAGENTA}@{CYAN}{host}{RESET}: ")
        if command.lower() == 'exit':
            break

        # If the command starts with "sudo", prompt for the sudo password,
        # package the command (without 'sudo') and password in a JSON message.
        if command.strip().startswith("sudo"):
            cmd_stripped = command.strip()[5:].strip()
            sudo_password = input("Enter sudo password: ")
            msg_dict = {"type": "sudo", "command": cmd_stripped, "sudo_password": sudo_password}
            message = json.dumps(msg_dict)
        else:
            message = command

        # Encrypt the message with AES (using EAX mode)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        encrypted_message, tag = cipher_aes.encrypt_and_digest(message.encode())
        payload = cipher_aes.nonce + tag + encrypted_message
        conn.sendall(base64.b64encode(payload))

        # Receive and decrypt the server response.
        raw_len = conn.recv(4)
        if not raw_len:
             break
        msg_len = int.from_bytes(raw_len, 'big')

        # 2) Now read exactly msg_len bytes
        data_b64 = b''
        while len(data_b64) < msg_len:
            chunk = conn.recv(msg_len - len(data_b64))
            if not chunk:
                 raise RuntimeError("Connection closed mid-message")
            data_b64 += chunk

# 3) Decode & decrypt as before
        data = base64.b64decode(data_b64)
        nonce = data[:16]
        tag   = data[16:32]
        ciphertext = data[32:]
        cipher_response = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher_response.decrypt_and_verify(ciphertext, tag).decode()
        print(plaintext)
        print("-" * 50)

    conn.close()

if __name__ == "__main__":
    start_secure_client()
