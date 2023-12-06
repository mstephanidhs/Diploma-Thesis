import socket
import sys
import logging

from OpenSSL import SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Configure logging
logging.basicConfig(filename='.\\logs\\ssl_connection.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SSLClient:
  
  def __init__(self, master_key, init_value, encrypted_data, max_chunk_size = 8192):
    self.client_socket = None
    self.ssl_socket = None
    self.master_key = master_key
    self.init_value = init_value
    self.encrypted_data = encrypted_data
    self.max_chunk_size = max_chunk_size
    
  def connect(self):
    # Create a socket
    # socket.AF_INET: This specifies the address family to be used for the socket. In this case, it's AF_INET, which stands for IPv4. This means the socket will be used for Internet Protocol version 4 (IPv4) communication.
    # socket.SOCK_STREAM: This specifies the type of socket to be created. In this case, it's SOCK_STREAM, which indicates a TCP (Transmission Control Protocol) socket. TCP is a reliable, connection-oriented protocol used for stream-oriented data transfer.
    self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.client_socket.connect(('127.0.0.1', 8443)) # Connect to the server
    
  def establish_ssl_connection(self):
    # Create an SSL context for the server
    # ssl.PROTOCOL_SSLv23, represents SSLv23, a flexible protocol that can negotiate various versions of SSL/TLS.
    context = SSL.Context(SSL.SSLv23_METHOD)
    
    # Wrap the socket with an SSL connection
    self.ssl_socket = SSL.Connection(context, self.client_socket)
    self.ssl_socket.set_connect_state()
    self.ssl_socket.set_tlsext_host_name(b'localhost') # server's hostname
    
    self.ssl_socket.do_handshake()
    logging.info("Handshake was successful!")
    
  def calculate_chunk_size(self, total_size, max_chunk_size):
    # Determine the number of chunks based on the total size and a maximum chunk size
    num_chunks = (total_size + max_chunk_size - 1) // max_chunk_size

    # Calculate the chunk size to evenly divide the data
    chunk_size = total_size // num_chunks

    return chunk_size
  
  def send_total_data_size(self, total_data_size, cipher):   
    # Send the total data size as a 4-byte integer
    total_size_bytes = total_data_size.to_bytes(4, byteorder='big')
    encrypted_total_size = cipher.encrypt(total_size_bytes)
    
    self.ssl_socket.send(encrypted_total_size)
  
  def send_master_key_and_iv(self, cipher):
    # Convert master key and init value to bytes
    master_key_bytes = self.master_key.to_bytes(16, byteorder='big')
    init_value_bytes = self.init_value.to_bytes(16, byteorder='big')
    
    # Encrypt the master key and init value
    encrypted_master_key = cipher.encrypt(master_key_bytes)
    encrypted_init_value = cipher.encrypt(init_value_bytes)
    
    # Send the encrypted master key and init value
    self.ssl_socket.send(encrypted_master_key)
    self.ssl_socket.send(encrypted_init_value)
    
  def calculate_and_send_chunk_size_bytes(self, total_data_size, cipher):
    # Calculate the chunk size
    chunk_size = self.calculate_chunk_size(total_data_size, self.max_chunk_size)
    # In bytes
    chunk_size_bytes = chunk_size.to_bytes(4, byteorder='big')
    
    encrypted_chunk_size = cipher.encrypt(chunk_size_bytes)
    self.ssl_socket.send(encrypted_chunk_size)
    
    return chunk_size
  
  def send_chunk_encrypted_data(self, total_data_size,chunk_size):
    # Initialize an index for tracking progress
    index = 0
    
    while index < total_data_size:
      # Extract a chunk of data
      chunk = self.encrypted_data[index:(index + chunk_size)]

      # Send the chunk
      self.ssl_socket.send(chunk) 
      
      # Update the index to the next chunk
      index += len(chunk)
  
  def send_encrypted_data(self):
    # Receive the server's public key
    server_public_key = self.ssl_socket.recv(4096)
    
    # Import the server's public key for encryption
    server_key = RSA.import_key(server_public_key)
    
    cipher = PKCS1_OAEP.new(server_key)
    
    self.send_master_key_and_iv(cipher)
    
    # Encrypted data size
    total_data_size = len(self.encrypted_data)
    self.send_total_data_size(total_data_size, cipher)
    
    # Chunk size - Assuming a 4-byte chunk size
    chunk_size = self.calculate_and_send_chunk_size_bytes(total_data_size, cipher)
    
    self.send_chunk_encrypted_data(total_data_size, chunk_size)
    
    logging.info('Encrypted data were sent successfully')
    
  def run(self):
    try:
      self.connect()
      self.establish_ssl_connection()
      
      # Send encrypted data to the server
      self.send_encrypted_data()
      
    except SSL.Error as e:
      logging.error(f"TLS handshake error: {e}", exc_info=True)
    except Exception as e:
      logging.error(f"An error occurred: {e}", exc_info=True)
      
    finally:
      self.close()
  
  def close(self):
    try:
        if self.ssl_socket:
            # Close the SSL socket, which implicitly shuts it down
            self.ssl_socket.close()
    except SSL.Error as e:
        # Log the error if it's not the expected exception
        if 'shutdown while in init' not in str(e):
            logging.error(f"Error during SSL socket close: {e}", exc_info=True)
    finally:
        # Close the client socket
        if self.client_socket:
            self.client_socket.close()

        logging.info("SSL Connection closed!")
    
if __name__ == '__main__':
  
  if len(sys.argv) != 3:
    logging.warning('Usage: python ssl_con.py master_key init_value')
    sys.exit(1)
    
  try:
    master_key = int(sys.argv[1])
    init_value = int(sys.argv[2])
  except ValueError:
    logging.warning('Error: Invalid master_key or init_value')
    sys.exit(1)
    
  # Read the encrypted_data from stdin
  encrypted_data = sys.stdin.buffer.read()
  
  client = SSLClient(master_key, init_value, encrypted_data)
  client.run()
    