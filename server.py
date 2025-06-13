import socket
import threading
import json
import base64
import bcrypt
import os
import time
import ssl
import logging
import subprocess  # to run sudo commands
import shlex       # for proper command splitting
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Logging setup
logging.basicConfig(filename="access.log", level=logging.INFO,
                    format="%(asctime)s - %(message)s")

# Replay protection store (in‑memory)
REPLAYED_NONCES = set()

# Config
CERTFILE = "server.pem"
KEYFILE  = "server.key"
CAFILE   = "ca.pem"
TIME_WINDOW = 30  # seconds


# Brute-force tracking
FAILED_ATTEMPTS = {}
BLOCKED_IPS = {}

def create_ssl_context():
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    ctx.load_verify_locations(cafile=CAFILE)
    ctx.verify_mode = ssl.CERT_REQUIRED  # demand client cert
    return ctx

# Load user credentials from JSON file
def load_users():
    try:
        with open("users.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

# Verify the password using bcrypt (for login and sudo validation)
def verify_password(username, password):
    users = load_users()
    if username in users:
        stored_hash = users[username]['password']
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    return False

# Get the role from users.json (default "user")
def get_user_role(username):
    users = load_users()
    return users.get(username, {}).get("role", "user")

# Check if an IP is blocked
def is_ip_blocked(ip):
    return BLOCKED_IPS.get(ip, 0) > time.time()

# Register a failed login attempt and block IP if needed
def register_failed_attempt(ip):
    FAILED_ATTEMPTS[ip] = FAILED_ATTEMPTS.get(ip, 0) + 1
    if FAILED_ATTEMPTS[ip] >= 3:
        BLOCKED_IPS[ip] = time.time() + 60  # block for 1 minute
        logging.warning(f"Blocked IP {ip} due to multiple failed login attempts")

# Load the server's private RSA key
def load_server_private_key():
    with open("server_private.pem", "rb") as key_file:
        return RSA.import_key(key_file.read())

# Decrypt the AES key sent by the client
def decrypt_aes_key(encrypted_key, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(base64.b64decode(encrypted_key))

# List of admin-only commands for fallback
ADMIN_COMMANDS = ['shutdown', 'reboot', 'kill', 'apt', 'dpkg', 'rm', 'useradd', 'usermod', 'sudo']
def is_admin_command(command):
    return any(command.strip().startswith(admin_cmd) for admin_cmd in ADMIN_COMMANDS)

# Client handler thread function
def handle_client(client_socket, addr, server_private_key):
    ip = addr[0]
    print(f"Connection from {addr}")

    # Check IP block
    if is_ip_blocked(ip):
        try:
            client_socket.send("Your IP is blocked due to multiple failed login attempts. Please try again later.".encode())
        except Exception as e:
            logging.error(f"Error sending block message to {ip}: {e}")
        client_socket.close()
        return

    # Initialize session cwd
    cwd = os.getcwd()

    try:
        # ---------- Authentication Phase ----------
        enc = client_socket.recv(512)  # enough for RSA-encrypted creds
        creds = PKCS1_OAEP.new(server_private_key).decrypt(base64.b64decode(enc)).decode()
        username, password, ts_s, nonce = creds.split(",", 3)
        ts = float(ts_s)
        # Check timestamp freshness
        if abs(time.time() - ts) > TIME_WINDOW or nonce in REPLAYED_NONCES:
            raise Exception("Replay or stale")
        REPLAYED_NONCES.add(nonce)
        if not verify_password(username, password):
            logging.warning(f"Failed login attempt from {ip} for user '{username}'")
            register_failed_attempt(ip)
            client_socket.send("AUTH_FAILED".encode())
            client_socket.close()
            return

        # Successful auth
        role = get_user_role(username)
        logging.info(f"User '{username}' (role: {role}) authenticated from {ip}")
        FAILED_ATTEMPTS[ip] = 0

        # ---------- AES Key Exchange ----------
        encrypted_aes_key = client_socket.recv(512).decode()
        aes_key = decrypt_aes_key(encrypted_aes_key, server_private_key)
        print("Secure AES key established")

        stored_hash = load_users()[username]['password']

        # ---------- Command Processing Loop ----------
        while True:
            data = client_socket.recv(2048)
            if not data:
                break

            # Decrypt incoming message
            packet = base64.b64decode(data)
            if len(packet) < 32:
                logging.error("Received data too short to process command.")
                continue
            nonce, tag, encrypted_cmd = packet[:16], packet[16:32], packet[32:]
            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            try:
                command = cipher.decrypt_and_verify(encrypted_cmd, tag).decode()
            except Exception as e:
                logging.error(f"Decryption failed for {username}@{ip}: {e}")
                continue

            print(f"[{username}] Received command: {command}")
            result = ""

            # Handle cd commands
            if command.strip().startswith("cd"):
                parts = command.strip().split(maxsplit=1)
                if len(parts) == 1:
                    result = f"Current directory: {cwd}"
                else:
                    new_dir = parts[1].strip()
                    try:
                        new_cwd = os.path.abspath(os.path.join(cwd, new_dir))
                        if os.path.isdir(new_cwd) and ((role == "admin" and hasattr(os, "geteuid") and os.geteuid() == 0) or os.access(new_cwd, os.R_OK | os.X_OK)):
                            cwd = new_cwd
                            result = f"Directory changed to: {cwd}"
                        else:
                            result = f"cd: permission denied or no such directory: {new_dir}"
                    except Exception as e:
                        result = f"cd: error: {e}"
            else:
                # Attempt sudo JSON
                is_sudo = False
                try:
                    msg = json.loads(command)
                    if msg.get("type") == "sudo":
                        is_sudo = True
                        cmd_to_run = msg.get("command", "")
                        sudo_pwd = msg.get("sudo_password", "")
                        if cmd_to_run.strip().startswith("cd"):
                            result = "Error: Use plain 'cd' command without sudo."
                        elif not bcrypt.checkpw(sudo_pwd.encode(), stored_hash.encode()):
                            result = "sudo: Authentication failed"
                            logging.warning(f"sudo auth failed for '{username}'")
                        else:
                            proc = subprocess.run(
                                ["sudo", "-S", "-p", ""] + shlex.split(cmd_to_run),
                                input=f"{sudo_pwd}\n",
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                                cwd=cwd
                            )
                            result = proc.stdout + proc.stderr
                except json.JSONDecodeError:
                    pass

                # Normal command execution
                if not is_sudo:
                    if role != "admin" and is_admin_command(command):
                        result = f"{username} is not in the sudoers file. This incident will be reported."
                        logging.warning(f"Unauthorized admin command by '{username}': {command}")
                    else:
                        proc = subprocess.run(
                            command,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            cwd=cwd
                        )
                        result = proc.stdout + proc.stderr

            # Encrypt and send the result back to the client
            response_cipher = AES.new(aes_key, AES.MODE_EAX)
            enc_result, resp_tag = response_cipher.encrypt_and_digest(result.encode())
            response_packet = response_cipher.nonce + resp_tag + enc_result
            client_socket.sendall(base64.b64encode(response_packet))

    except Exception as e:
        logging.error(f"Error handling client {ip}: {e}")
    finally:
        client_socket.close()


def start_secure_server(host='0.0.0.0', port=5555):
    server_key = load_server_private_key()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    sslctx = create_ssl_context()
    print(f"Server listening on {host}:{port}...")

    while True:
        client_sock, addr = server.accept()
        try:
            conn = sslctx.wrap_socket(client_sock, server_side=True)
            threading.Thread(target=handle_client, args=(conn, addr, server_key), daemon=True).start()
        except ssl.SSLError as e:
            print("SSL error:", e)
            client_sock.close()

if __name__ == "__main__":
    start_secure_server()
