import os
import sys
import secrets
import time
import subprocess
from connection_management import ConnectionManager
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives.hashes import SHA256

class SecureServer:
    def __init__(self):
        self.connection_manager = ConnectionManager(HOST, PORT, CERTFILE, KEYFILE, CAFILE)
        self.sessions = {}
        self.BASE_DIR = os.path.abspath("../server-side")
        self.key_dir = os.path.abspath("../server-side/servers/server_storage/keys")

        self.__register_new_server()

    def __register_new_client(self):
       """
       If a new client is created then they need to register with the CA and generate a certificate and
       their own public and private keys for communication to the server.

       Need to run the bash script gen_client.sh passing in the clientID to generate the keys and certificate 
       for the client.
       """
       ca_cert_path = os.path.join(self.BASE_DIR, "../ca/ca.crt")
       ca_key_path = os.path.join(self.BASE_DIR, "../ca/ca.key")
       key_dir = self.key_dir  # Already absolute based on BASE_DIR

       # Ensure paths are absolute in case the script is run from a different directory
       ca_cert_path = os.path.abspath(ca_cert_path)
       ca_key_path = os.path.abspath(ca_key_path)

       script_path = os.path.join(self.BASE_DIR, "../server-side/src/gen_client.sh")
       subprocess.run([script_path, ca_cert_path, ca_key_path, key_dir], check=True)