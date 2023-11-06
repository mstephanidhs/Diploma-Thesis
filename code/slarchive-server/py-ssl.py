import socket
import logging

from OpenSSL import SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from encryption import constants

# Configure logging
logging.basicConfig(filename='.\\logs\\ssl_connection.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create a socket
# socket.AF_INET: This specifies the address family to be used for the socket. In this case, it's AF_INET, which stands for IPv4. This means the socket will be used for Internet Protocol version 4 (IPv4) communication.
# socket.SOCK_STREAM: This specifies the type of socket to be created. In this case, it's SOCK_STREAM, which indicates a TCP (Transmission Control Protocol) socket. TCP is a reliable, connection-oriented protocol used for stream-oriented data transfer.
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client_socket.connect(('127.0.0.1', 8443)) # Connect to the server

# Create an SSL context for the server
# ssl.PROTOCOL_SSLv23, represents SSLv23, a flexible protocol that can negotiate various versions of SSL/TLS.
context = SSL.Context(SSL.SSLv23_METHOD)

# Wrap the socket with an SSL connection
ssl_socket = SSL.Connection(context, client_socket)
ssl_socket.set_connect_state()
ssl_socket.set_tlsext_host_name(b'localhost') # server's hostname

try:
  ssl_socket.do_handshake()
  logging.info("Handshake was successful!")
  
  # Receive the server's public key
  server_public_key = ssl_socket.recv(4096)
  
  # Import the server's public key for encryption
  server_key = RSA.import_key(server_public_key)
  
  # Convert integers to bytes
  # bit.length() -> calculates the number of bits required to represent 
  # rounds up the number of bits to the nearest byte. 
  # ensures that enough bytes will be allocated to represent the integer.
  master_key_bytes = constants.master_key.to_bytes((constants.master_key.bit_length() + 7) // 8, byteorder='big')
  iv_bytes = constants.init_value.to_bytes((constants.init_value.bit_length() + 7) // 8, byteorder='big')
  
  # Encrypt the master key and IV with the server's public key
  cipher = PKCS1_OAEP.new(server_key)
  encrypted_master_key = cipher.encrypt(master_key_bytes)
  encrypted_iv = cipher.encrypt(iv_bytes)
  
  # Send the encrypted master key and IV to the server
  ssl_socket.send(encrypted_master_key)
  ssl_socket.send(encrypted_iv)
  
  logging.info("Master Key and IV were successfully sent.")
 
except SSL.Error as e:
  logging.error(f"TLS handshake error: {e}")
except Exception as e:
  logging.error(f"An error occurred: {e}")
  
# Close the SSL connection and the client socket
# ssl_socket.shutdown()
# ssl_socket.close()
# client_socket.close()

