import os
import threading
import struct
import subprocess
from connection_management import ConnectionManager
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

HOST = 'localhost'
PORT = 9000
CERTFILE = os.path.abspath("../server_storage/keys/server.crt")
KEYFILE = os.path.abspath("../server_storage/keys/server_private.key")
CAFILE = os.path.abspath("../server_storage/keys/ca.crt")

JWT_ALGORITHM = 'HS256'

UPLOAD_FILE = 1
RETRIEVE_FILE = 2
SHARE_FILE = 3

PACKET_FORMAT = "!B16s16s16s32s"
PACKET_FORMAT_SHARE = "!B16s16s16s16s32s"

class SecureServer:
    def __init__(self):
        self.connection_manager = ConnectionManager(HOST, PORT, CERTFILE, KEYFILE, CAFILE)
        self.sessions = {}
        self.BASE_DIR = os.path.abspath("../")
        self.key_dir = os.path.abspath("../server_storage/keys")

        self.__register_new_server()

    def __register_new_server(self):
       """
       If a new server is created then they need to register with the CA and generate a certificate and
       their own public and private keys for communication to the server.

       Need to run the bash script gen_server.sh passing in the clientID to generate the keys and certificate 
       for the client.
       """
       ca_cert_path = os.path.join(self.BASE_DIR, "../ca/ca.crt")
       ca_key_path = os.path.join(self.BASE_DIR, "../ca/ca.key")
       key_dir = self.key_dir 

       # Ensure paths are absolute in case the script is run from a different directory
       ca_cert_path = os.path.abspath(ca_cert_path)
       ca_key_path = os.path.abspath(ca_key_path)

       script_path = os.path.join(self.BASE_DIR, "../server-side/src/gen_server.sh")
       subprocess.run([script_path, ca_cert_path, ca_key_path, key_dir], check=True)
        

    def start(self):
        server_socket = self.connection_manager.create_secure_server_socket()
        print(f"Server listening on {HOST}:{PORT}...")

        while True:
            client_connection, client_address = server_socket.accept()
            print(f"Connection from {client_address} established")
            client_thread = threading.Thread(target=self.handle_client, args=(client_connection, client_address))
            client_thread.start()

    def handle_client(self, connection, client_address):
        try:
            # Perform ephemeral key exchange using ECDHE
            server_private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
            server_public_key_bytes = server_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            print("Ephemeral key exchange complete")

            # Send server's public key to client
            self.connection_manager.send_packet(connection, server_public_key_bytes)

            print("Server Public Key sent to Client ...")

            # Receive client's ephemeral public key
            client_public_key_bytes = self.connection_manager.receive_packet(connection)
            client_public_key = serialization.load_pem_public_key(client_public_key_bytes, backend=default_backend())

            print("Clients Public Key received...")

            # Generate shared secret and derive session key
            shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_secret)

            print("Session Key derived")

            # Immediately discard server's ephemeral private key to prevent misuse
            del server_private_key

            # Listen for packets from the client
            while True:
                secure_packet = self.connection_manager.receive_packet(connection)
                if not secure_packet:
                    break
                # Process the secure packet
                self.process_packet(secure_packet, session_key, client_address, connection)

        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            connection.close()

    def process_packet(self, packet, session_key, client_address, connection):
        """
        Processes an incoming packet by parsing it, validating its structure,
        and saving the encrypted file data for testing purposes.
        """
        try:

            parsed_packet = self.parse_packet(packet)

            operation = parsed_packet["operation"]

            if operation == UPLOAD_FILE:

                client_id = parsed_packet["client_id"]
                filename = parsed_packet["filename"]
                iv = parsed_packet["iv"]
                mac = parsed_packet["hmac"]
                ciphertext = parsed_packet["data"]

                # Log extracted metadata
                print(f"Operation: {operation}")
                print(f"Client ID: {client_id}")
                print(f"Filename: {filename}")
                print(f"IV: {iv.hex()}")
                print(f"Ciphertext Length: {len(ciphertext)}")
                print(f"HMAC: {mac.hex()}")

                # Save the encrypted file for review
                output_dir = os.path.abspath(f"../server_storage/{client_id}")
                os.makedirs(output_dir, exist_ok=True)

                encrypted_file_path = os.path.join(output_dir, f"{filename}")
                with open(encrypted_file_path, 'wb') as f:
                    f.write(ciphertext)

                print(f"Encrypted file saved at: {encrypted_file_path}")

                # Optionally save IV and HMAC for further testing
                metadata_path = os.path.join(output_dir, f"metadata_{filename}.txt")
                with open(metadata_path, 'w') as f:
                    f.write(f"IV: {iv.hex()}\n")
                    f.write(f"HMAC: {mac.hex()}\n")
                    f.write(f"Allowed_User: {client_id}")

                print(f"Metadata saved at: {metadata_path}")

                # Acknowledge receipt to the client
                print(f"File '{filename}' from client {client_address} processed successfully.")

            elif operation == RETRIEVE_FILE:

                client_id = parsed_packet["client_id"]
                filename = parsed_packet["filename"]
                
                # Get file, and metadata values to send in packet back to Client
                filepath = os.path.abspath(f"../server_storage/{client_id}/{filename}")
                print(filepath)
                if not os.path.exists(filepath):
                    print(f"File '{filename}' not found.")
                    return
                with open(filepath, 'rb') as file:
                    ciphertext = file.read()

                # Get metadata for file
                meta_filepath = os.path.abspath(f"../server_storage/{client_id}/metadata_{filename}.txt")
                values = {}

                with open(meta_filepath, 'r') as file:
                    for line in file:
                        key, value = line.strip().split(': ')
                        if key == 'IV' or key == 'HMAC':
                            # Convert the hex string into bytes
                            values[key] = bytes.fromhex(value)

                    # Ensure both IV and HMAC are present
                    if 'IV' not in values or 'HMAC' not in values:
                        raise ValueError("Metadata file is missing IV or HMAC values.")

                mac = values['HMAC']
                iv_ret = values['IV']

                client_id_bytes = client_id.encode('utf-8')
                filename_bytes = filename.encode('utf-8')
        
                packet = self.construct_packet(operation, client_id, filename, iv_ret, mac, ciphertext)


                self.connection_manager.send_packet(connection, packet)
                print(f"File sent to Client after request for '{filename}' from Client.")

            elif operation == SHARE_FILE:

                parsed_packet = self.parse_packet_share(packet)
                client_id = parsed_packet["client_id"]
                filename = parsed_packet["filename"]
                allowed_user = parsed_packet["allowed_user"]  # Target client to share with

                # Log extracted metadata
                print(f"Operation: {operation}")
                print(f"Client ID: {client_id}")
                print(f"Filename: {filename}")
                print(f"Allowed user: {allowed_user}")
                

                # Path to the metadata file for the shared file
                metadata_path = os.path.abspath(f"../server_storage/{client_id}/metadata_{filename}.txt")
                if not os.path.exists(metadata_path):
                    print(f"Metadata for file '{filename}' not found. Cannot share.")
                    return

                # Read and update the allowed_users list in the metadata
                try:
                    values = {}
                    allowed_users = []

                    with open(metadata_path, 'r') as file:
                        for line in file:
                            key, value = line.strip().split(': ', 1)
                            if key == "IV" or key == "HMAC":
                                values[key] = bytes.fromhex(value)  # Convert IV and HMAC from hex to bytes
                            elif key == "Allowed_User":
                                allowed_users = value.split(', ')  # Parse the allowed users into a list

                    # Check if the requesting client is the owner
                    if not allowed_users or allowed_users[0] != client_id:
                        print(f"Unauthorized share attempt by '{client_id}'. Only the owner can share.")
                        return

                    # Add the new client to the allowed_users list if not already present
                    if allowed_user not in allowed_users:
                        allowed_users.append(allowed_user)

                    # Update the metadata file
                    with open(metadata_path, 'w') as file:
                        file.write(f"IV: {values['IV'].hex()}\n")  # Write IV back to file
                        file.write(f"HMAC: {values['HMAC'].hex()}\n")  # Write HMAC back to file
                        file.write(f"Allowed_User: {', '.join(allowed_users)}\n")  # Write updated allowed users list


                    print(f"File '{filename}' shared successfully with '{allowed_user}'.")

                except Exception as e:
                    print(f"Error processing SHARE_FILE for '{filename}': {e}")

        except Exception as e:
            print(f"Error processing packet from {client_address}: {e}")


    def parse_packet(self, packet):
        header_size = struct.calcsize(PACKET_FORMAT)
        header = packet[:header_size]
        data = packet[header_size:]

        operation, client_id, filename, iv, hmac = struct.unpack(PACKET_FORMAT, header)

        client_id = client_id.decode('utf-8').rstrip('\x00')
        filename = filename.decode('utf-8').rstrip('\x00')

        parsed_packet = {
            "operation": operation,
            "client_id": client_id,
            "filename": filename,
            "iv": iv,
            "hmac": hmac,
            "data": data
        }

        return parsed_packet
    
    def construct_packet(self, operation, client_id, filename, iv, mac, data):
        """
        Constructs a secure packet to send to the server.
        Supports both upload and retrieve operations.
        """
        try:

            # Encode filename to bytes and prepend with its length
            filename_bytes = filename.encode('utf-8').ljust(16, b'\x00')[:16]
            client_id_bytes = client_id.encode('utf-8').ljust(16, b'\x00')[:16]

            header = struct.pack (
                PACKET_FORMAT, 
                operation,
                client_id_bytes,
                filename_bytes,
                iv,
                mac
            )

            packet = header + data

            print(f"Packet constructed for operation {operation} with file '{filename}'.")
            return packet

        except Exception as e:
            print(f"Error constructing packet: {e}")
            raise

    def construct_packet_share(self, operation, client_id, filename, iv, allowed_user, mac, data):
        """
        Constructs a secure packet to send to the server.
        Supports both upload and retrieve operations.
        """
        try:

            # Encode filename to bytes and prepend with its length
            filename_bytes = filename.encode('utf-8').ljust(16, b'\x00')[:16]
            client_id_bytes = client_id.encode('utf-8').ljust(16, b'\x00')[:16]
            allowed_user_bytes = allowed_user.encode('utf-8').ljust(16, b'\x00')[:16]

            header = struct.pack (
                PACKET_FORMAT_SHARE, 
                operation,
                client_id_bytes,
                filename_bytes,
                iv,
                allowed_user_bytes, 
                mac
            )

            packet = header + data

            print(f"Packet constructed for operation {operation} with file '{filename}'.")
            return packet

        except Exception as e:
            print(f"Error constructing packet: {e}")
            raise

    def parse_packet_share(self, packet):
        
        header_size = struct.calcsize(PACKET_FORMAT_SHARE)
        header = packet[:header_size]
        data = packet[header_size:]

        operation, client_id, filename, iv, allowed_user, hmac = struct.unpack(PACKET_FORMAT_SHARE, header)

        client_id = client_id.decode('utf-8').rstrip('\x00')
        filename = filename.decode('utf-8').rstrip('\x00')
        allowed_user = allowed_user.decode('utf-8').rstrip('\x00')
        

        parsed_packet = {
            "operation": operation,
            "client_id": client_id,
            "filename": filename,
            "iv": iv,
            "allowed_user": allowed_user,
            "hmac": hmac,
            "data": data
        }

        return parsed_packet

if __name__ == "__main__":
    server = SecureServer()
    server.start()
