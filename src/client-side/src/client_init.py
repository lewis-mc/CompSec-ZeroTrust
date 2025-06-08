import os
import subprocess
import struct
from connection_management import ConnectionManager
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HOST = 'localhost'
PORT = 9000
JWT_ALGORITHM = 'HS256'

UPLOAD_FILE = 1
RETRIEVE_FILE = 2
SHARE_FILE = 3

PACKET_FORMAT = "!B16s16s16s32s"
PACKET_FORMAT_SHARE = "!B16s16s16s16s32s"

class Client:
    def __init__(self, client_id):
        self.client_id = client_id
        self.BASE_DIR = os.path.abspath("../")
        self.key_dir = os.path.abspath("../clients/" + client_id + "/keys")
        self.__register_new_client()
    
    def __register_new_client(self):
        """
        If a new client is created, register with the CA and generate certificates and keys.
        """
        ca_cert_path = os.path.join(self.BASE_DIR, "../ca/ca.crt")
        ca_key_path = os.path.join(self.BASE_DIR, "../ca/ca.key")
        key_dir = self.key_dir 

        # Ensure paths are absolute
        ca_cert_path = os.path.abspath(ca_cert_path)
        ca_key_path = os.path.abspath(ca_key_path)

        client_key_path = os.path.abspath(f"../clients/{self.client_id}/keys/{self.client_id}_private.key")
        client_cert_file = os.path.abspath(f"../clients/{self.client_id}/keys/{self.client_id}.crt")
        ca_cert_file = os.path.abspath(f"../clients/{self.client_id}/keys/ca.crt")

        script_path = os.path.join(self.BASE_DIR, "../client-side/src/gen_client.sh")
        subprocess.run([script_path, self.client_id, ca_cert_path, ca_key_path, key_dir], check=True)

        os.makedirs(os.path.abspath(f"../clients/{self.client_id}/keys"), exist_ok=True)
        os.makedirs(os.path.abspath(f"../clients/{self.client_id}/storage"), exist_ok=True)
        os.makedirs(os.path.abspath(f"../clients/{self.client_id}/retrieved"), exist_ok=True)
        
        self.connection_manager = ConnectionManager(HOST, PORT, client_cert_file, client_key_path, ca_cert_file)
        

    
    def start(self):
        secure_connection = self.connection_manager.create_secure_connection()
        try:
            self.handle_server(secure_connection)
        except Exception as e:
            print(f"Error handling server: {e}")
        finally:
            secure_connection.close()
    
    def handle_server(self, connection):
        """
        Function to handle client-server interactions.
        """
        try:
            # Generate Client's Ephemeral Key Pair
            client_privat_ephemeral_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
            client_public_ephemeral_key_bytes = client_privat_ephemeral_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Load RSA private key for Client to sign the public key


            # Receive Server's Ephemeral Public Key
            server_public_key_bytes = self.connection_manager.receive_packet(connection)
            server_public_key = serialization.load_pem_public_key(server_public_key_bytes, backend=default_backend())
            print("Server Public Key received.")

            # Send Client's Ephemeral Public Key to Server
            self.connection_manager.send_packet(connection, client_public_ephemeral_key_bytes)
            print("Client Public Key sent to Server.")

            # Generate Shared Secret and Derive Session Key
            shared_secret = client_privat_ephemeral_key.exchange(ec.ECDH(), server_public_key)
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_secret)
            self.session_key = session_key

            # Step 5: Immediately Discard Ephemeral Keys
            # del client_private_key

            print("handshake complete")
        except Exception as e:
            print(f"Error during server communication: {e}")
        
        while True:
            input_val = input("Select operation to perform:\n1: Upload file (usage: '1 <file_name>')\n2:Retrieve file (usage: '2 <file_name>')\n\n")
            try:
                inputs = input_val.split(" ")
                if int(inputs[0]) == UPLOAD_FILE:
                    self.upload_file_to_server(connection, str(inputs[1]))
                elif int(inputs[0]) == RETRIEVE_FILE:
                    self.retrieve_file(connection, str(inputs[1]))
                elif int(inputs[0]) == SHARE_FILE:
                    self.share_file(connection, inputs[1], inputs[2])

            except ValueError:
                print("The input is not an integer")
        

    def upload_file_to_server(self, connection, filename):
        """
        Upload a file to the server.
        """
        try:
            filepath = os.path.abspath(f"../clients/{self.client_id}/storage/{filename}")
            print(filepath)
            if not os.path.exists(filepath):
                print(f"File '{filename}' not found.")
                return
            
            with open(filepath, 'rb') as file:
                plaintext = file.read()

            # For upload, encrypt the file and compute its MAC
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.session_key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            # Compute HMAC for integrity verification
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(ciphertext)
            mac = h.finalize()

            packet = self.construct_packet(UPLOAD_FILE, self.client_id, filename, iv, mac, ciphertext)

            self.connection_manager.send_packet(connection, packet)

        except Exception as e:
            print("Error")
        
        # To be implemented: securely send file data to the server using session key
        return

    def retrieve_file(self, connection, filename):
        """
        Retrieve a file from the server securely.
        """
        try:
            # Construct the secure packet for retrieval
            packet = self.construct_packet(RETRIEVE_FILE, self.client_id, filename, (b'\x00' * 16), (b'\x00' * 32), b'')

            # Send the request to the server
            self.connection_manager.send_packet(connection, packet)
            print(f"File retrieval request for '{filename}' sent to server.")

            # Receive the response packet
            response_packet = self.connection_manager.receive_packet(connection)

            parsed_packet = self.parse_packet(response_packet)

            operation = parsed_packet["operation"]
            client_id = parsed_packet["client_id"]
            filename_received = parsed_packet["filename"]
            iv = parsed_packet["iv"]
            mac = parsed_packet["hmac"]
            ciphertext = parsed_packet["data"]

            # Verify file integrity
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(bytes(ciphertext))
            h.verify(bytes(mac))
            print("File integrity verified.")

            # Decrypt the file
            cipher = Cipher(algorithms.AES(self.session_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Save the file locally
            output_path = os.path.abspath(f"../clients/{client_id}/retrieved/{filename}")
            with open(output_path, 'wb') as file:
                file.write(plaintext)

            print(f"File '{filename_received}' successfully retrieved and saved as '{output_path}'.")

        except Exception as e:
            print(f"Error retrieving file: {e}")


    def share_file(self, connection, filename, target_client):
        """
        Share a file with another Client.
        Sends a request to the server to add the target_client to the file's allowed_users list.
        """
        try:
            # Construct a packet for the SHARE_FILE operation
            iv = os.urandom(16)  # Generate a random IV for the share operation
            mac = b'\x00' * 32  # Placeholder MAC for now, since no file data is shared
            data = b''  # No additional data for this operation

            # Construct the share packet
            packet = self.construct_packet_share(
                SHARE_FILE, self.client_id, filename, iv, target_client, mac, data
            )

            # Send the packet to the server
            self.connection_manager.send_packet(connection, packet)
            print(f"Share request for '{filename}' sent to server to share with '{target_client}'.")



        except Exception as e:
            print(f"Error sharing file '{filename}' with '{target_client}': {e}")

    
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