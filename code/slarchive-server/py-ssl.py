import socket
from OpenSSL import SSL

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
  
  # secure data transfer
  ssl_socket.send(b"Hello, server!")
  data = ssl_socket.recv(1024)
  print(f"Received data from server: {data.decode('utf-8')}")
  
except SSL.Error as e:
  print(f"TLS handshake error: {e}")
  
# Close the SSL connection and the client socket
ssl_socket.shutdown()
ssl_socket.close()
client_socket.close()

