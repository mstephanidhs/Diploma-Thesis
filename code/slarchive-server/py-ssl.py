import socket
from OpenSSL import SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from encryption import constants

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
  print("Handshake was successful!")
  
  # Receive the server's public key
  server_public_key = ssl_socket.recv(4096)
  print(server_public_key)
  
  # Import the server's public key for encryption
  server_key = RSA.import_key(server_public_key)
  
  print(server_key)
  
  master_key = get_random_bytes(32)  # 256 bits
  iv = get_random_bytes(12)  # 96 bits
  
  # Encrypt the master key and IV with the server's public key
  cipher = PKCS1_OAEP.new(server_key)
  encrypted_master_key = cipher.encrypt(master_key)
  encrypted_iv = cipher.encrypt(iv)
  
  # Send the encrypted master key and IV to the server
  # Break the encrypted data into chunks and send them
  chunk_size = 256

  for i in range(0, len(encrypted_master_key), chunk_size):
      print('sending data...')
      ssl_socket.send(encrypted_master_key[i:i+chunk_size])

  for i in range(0, len(encrypted_iv), chunk_size):
      print('sending data...')
      ssl_socket.send(encrypted_iv[i:i+chunk_size])

  
except SSL.Error as e:
  print(f"TLS handshake error: {e}")
except Exception as e:
    print(f"An error occurred: {e}")
  
# Close the SSL connection and the client socket
ssl_socket.shutdown()
ssl_socket.close()
client_socket.close()

