import socket
import ssl
import struct

class ConnectionManager:
   def __init__(self, host, port, certfile, keyfile, cafile):
       self.host = host
       self.port = port
       self.certfile = certfile
       self.keyfile = keyfile
       self.cafile = cafile

   def create_secure_server_socket(self):
       """Create a secure server socket using SSL."""
       context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
       context.verify_mode = ssl.CERT_REQUIRED
       context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
       context.load_verify_locations(self.cafile)
       
       server_socket = socket.create_server((self.host, self.port))
       ssl_server_socket = context.wrap_socket(server_socket, server_side=True)
       return ssl_server_socket

   def send_packet(self, connection, data):
       """
       Send data preceded by its length, packed into 4 bytes.
       
       This allows the receiver to know how much data to expect.

       Args:
           connection: The socket connection to send data over.
           data: The data to send.
       """
       # send data len first
       data_length = len(data)
       connection.sendall(struct.pack('>I', data_length))
       print(f"Sending {data_length} bytes of data")
       # send data
       connection.sendall(data)

   def receive_packet(self, connection):
       """
       Receive data preceded by its length, then receive the data based on the said length.
       """
       # receive data length first
       data_length_bytes = connection.recv(4)
       if not data_length_bytes:
           return None
       data_length = struct.unpack('>I', data_length_bytes)[0]

       # then receive the data based on the said length
       return self.receive_exactly(connection, data_length)

   def receive_exactly(self, connection, num_bytes):
       """
       Ensure we read exactly 'num_bytes' from the connection.
       """
       data = bytearray()
       while len(data) < num_bytes:
           packet = connection.recv(num_bytes - len(data))
           if not packet:
               raise ConnectionError("Socket connection broken")
           data.extend(packet)

       print(f"Received {num_bytes} bytes of data")
       return data

   def create_secure_connection(self):
       """Establish a secure connection using SSL."""
       context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
       context.verify_mode = ssl.CERT_REQUIRED
       context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
       context.load_verify_locations(self.cafile)
       
       # Establish socket connection and wrap it in SSL
       sock = socket.create_connection((self.host, self.port))
       ssock = context.wrap_socket(sock, server_hostname=self.host)
       return ssock