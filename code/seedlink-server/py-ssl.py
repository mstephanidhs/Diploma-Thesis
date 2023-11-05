import socket
from OpenSSL import SSL

# Create a socket
# socket.AF_INET: This specifies the address family to be used for the socket. In this case, it's AF_INET, which stands for IPv4. This means the socket will be used for Internet Protocol version 4 (IPv4) communication.
# socket.SOCK_STREAM: This specifies the type of socket to be created. In this case, it's SOCK_STREAM, which indicates a TCP (Transmission Control Protocol) socket. TCP is a reliable, connection-oriented protocol used for stream-oriented data transfer.
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 0.0.0.0, it's binding to all available network interfaces and can accept incoming connections from any IP address.
server_socket.bind(('0.0.0.0', 8443)) # Bind to a specific host and port
server_socket.listen(1) # Listen for incoming connections

# Create an SSL context for the server
# ssl.PROTOCOL_SSLv23, represents SSLv23, a flexible protocol that can negotiate various versions of SSL/TLS.
context = SSL.Context(SSL.SSLv23_METHOD)

# Execute the below command in order to execute the server-certs needed
# openssl req -x509 -nodes -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem -days 365
context.use_privatekey_file('.\\server_cred\\server-key.pem')
context.use_certificate_file('.\\server_cred\\server-cert.pem')

print("Server is listening on port 8443...")

while True:
  client_socket, client_address = server_socket.accept()
  print(f'Accepted connection from {client_address}')
  
  # Wrap the client socket in an SSL connection
  ssl_socket = SSL.Connection(context, client_socket)
  ssl_socket.set_accept_state()
  
  try:
    ssl_socket.do_handshake()
    
    # Secure data transfer
    data = ssl_socket.recv(1024)
    if data:
      print(f"Received data from client: {data.decode('utf-8')}")
      ssl_socket.send(b"Hello, client!")
    
  except SSL.Error as e:
    print(f"TLS handshake error: {e}")
    
  # Close the SSL connection and the client socket
  ssl_socket.shutdown()
  ssl_socket.close()
  client_socket.close()