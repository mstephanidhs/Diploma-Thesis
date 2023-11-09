import socket
import logging

from OpenSSL import SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

import constants

import obspy

from processor import TraceProcessor

# Configure logging
logging.basicConfig(filename='.\\logs\\ssl_connection.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

# Execute the below command in order to produce the server-certs needed
# openssl req -x509 -nodes -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem -days 365
context.use_privatekey_file('.\\..\\server_cred\\server-key.pem')
context.use_certificate_file('.\\..\\server_cred\\server-cert.pem')

print("Server is listening on port 8443...")

while True:
  client_socket, client_address = server_socket.accept()
  logging.info(f'Accepted connection from {client_address}')
  
  # Wrap the client socket in an SSL connection
  ssl_socket = SSL.Connection(context, client_socket)
  ssl_socket.set_accept_state()
  
  try:
    ssl_socket.do_handshake()
    logging.info("Handshake was successful!")
    
    # Send the server's public key to the client after the handshake
    server_public_key = open('.\\..\\server_cred\\server-cert.pem', 'rb').read()
    ssl_socket.send(server_public_key)

    # Securely receive the client's encrypted master key and IV
    encrypted_master_key = ssl_socket.recv(256)
    encrypted_iv = ssl_socket.recv(256)

    # Decrypt the master key and IV using the server's private key
    server_private_key = RSA.importKey(open('.\\..\\server_cred\\server-key.pem').read())
    cipher = PKCS1_OAEP.new(server_private_key)
    master_key = cipher.decrypt(encrypted_master_key)
    iv = cipher.decrypt(encrypted_iv)
    
    logging.info("Received successfully Master Key and IV.")
    print("Received successfully the Master Key and IV.")
    
    # Convert the decrypted values to hexadecimal strings
    master_key_hex = binascii.hexlify(master_key).decode('utf-8')
    iv_hex = binascii.hexlify(iv).decode('utf-8')
    
    print("Master Key", master_key_hex)
    print('IV: ', iv_hex)
    
    # Receive the total data size as a 4-byte integer
    encrypted_total_size = ssl_socket.recv(4096)
    total_size_bytes = cipher.decrypt(encrypted_total_size)
    print(total_size_bytes)
    total_data_size = int.from_bytes(total_size_bytes, byteorder='big')
    print(total_data_size)
    
    # Receive the chunk size from the client
    encrypted_chunk_size = ssl_socket.recv(4096)  # Assuming a 4-byte chunk size
    chunk_size_bytes = cipher.decrypt(encrypted_chunk_size)
    chunk_size = int.from_bytes(chunk_size_bytes, byteorder='big')
    print("Received chunk size")

    # Create a variable to store the received data
    received_data = b""

    while len(received_data) < total_data_size:
        # Receive a chunk of data based on the received 'chunk_size'
        chunk = ssl_socket.recv(chunk_size)

        # Append the received chunk to the existing data
        received_data += chunk
      
    print("Received encrypted data")
        
    processor = TraceProcessor(constants.master_key, constants.init_value)
    
    decrypted_data = processor.decrypt_trace(received_data)
    
    print('Decrypted data')
    
    restored_trace_json_bytes, trace_data_binary = processor.split_trace(decrypted_data)
    
    print('Data splitted')
    
    restored_trace = obspy.Trace()
    
    processor.convert_json_to_stats(restored_trace, restored_trace_json_bytes)
    processor.convert_binary_to_data(restored_trace, trace_data_binary, 'data')
    
    print("Data ready")
    
    print(restored_trace.stats)
    print(restored_trace.data)
    
  except SSL.Error as e:
    logging.error(f"TLS handshake error: {e}")
  except Exception as e:
    logging.error(f"An error occurred: {e}")
    
  # Close the SSL connection and the client socket
  ssl_socket.shutdown()
  ssl_socket.close()
  client_socket.close()