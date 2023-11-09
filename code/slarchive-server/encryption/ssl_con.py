import socket
import logging
import secrets
import sys

from OpenSSL import SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from encrypt_data import DataEncryption

import constants

class SSLEncryptionClient:
  
  def __init__(self, source_file, max_chunk_size = 8192):
    self.source_file = source_file
    self.client_socket = None
    self.ssl_socket = None
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
  
  def encrypt_data(self):
    script = DataEncryption(self.source_file, constants.master_key, constants.init_value)
    script.configure_logging()
    encrypted_data = script.run()
    
    return encrypted_data
  
  def calculate_total_data_size(self, encrypted_data):
    total_data_size = len(encrypted_data)
    # Send the total data size as a 4-byte integer
    total_size_bytes = total_data_size.to_bytes(4, byteorder='big')
    return total_size_bytes, total_data_size
    
  def calculate_chunk_size_bytes(self, total_data_size):
    # Calculate the chunk size
    chunk_size = self.calculate_chunk_size(total_data_size, self.max_chunk_size)
    # In bytes
    chunk_size_bytes = chunk_size.to_bytes(4, byteorder='big')
    return chunk_size_bytes, chunk_size
  
  def send_chunk_encrypted_data(self, total_data_size, encrypted_data, chunk_size):
    # Initialize an index for tracking progress
    index = 0
    
    while index < total_data_size:
      # Extract a chunk of data
      chunk = encrypted_data[index:(index + chunk_size)]

      # Send the chunk
      self.ssl_socket.send(chunk) 
      
      # Update the index to the next chunk
      index += len(chunk)
      
  def send_encrypted_data(self):
    # Receive the server's public key
    server_public_key = self.ssl_socket.recv(4096)
    
    # Import the server's public key for encryption
    server_key = RSA.import_key(server_public_key)
    
    # Generate a random 128-bit (16-byte) master key
    master_key = secrets.token_hex(16)
    # Generate a random 96-bit (12-byte) initialization vector (IV)
    init_value = secrets.token_hex(12)
    
    # Convert the generated values from hexadecimal strings to bytes
    master_key_bytes = bytes.fromhex(master_key)
    init_value_bytes = bytes.fromhex(init_value)
    
    # Encrypt the master key and IV with the server's public key
    cipher = PKCS1_OAEP.new(server_key)
    encrypted_master_key = cipher.encrypt(master_key_bytes)
    encrypted_init_value = cipher.encrypt(init_value_bytes)
    
    # Send the encrypted master key and IV
    self.ssl_socket.send(encrypted_master_key)
    self.ssl_socket.send(encrypted_init_value)
    
    logging.info("Master Key and IV were successfully sent.")
    
    encrypted_data = self.encrypt_data()
    
    # Send encrypted the data size
    total_size_bytes, total_data_size = self.calculate_total_data_size(encrypted_data)
    encrypted_total_size = cipher.encrypt(total_size_bytes)
    self.ssl_socket.send(encrypted_total_size)
    
    # Chunk Size
    # Assuming a 4-byte chunk size
    chunk_size_bytes, chunk_size = self.calculate_chunk_size_bytes(total_data_size)
    encrypted_chunk_size = cipher.encrypt(chunk_size_bytes)
    self.ssl_socket.send(encrypted_chunk_size)
    
    logging.info("Total Size of Data and Chunk Size were successfully sent.")
    
    self.send_chunk_encrypted_data(total_data_size, encrypted_data, chunk_size)
      
    logging.info("Encrypted data were sent successfully.")
      
  def run(self):
    try:
      self.connect()
      self.establish_ssl_connection()
      
      self.send_encrypted_data()
      
    except SSL.Error as e:
      logging.error(f"TLS handshake error: {e}")
    except Exception as e:
      logging.error(f"An error occurred: {e}")
      
    finally:
      self.close()
      
  def close(self):
    if self.ssl_socket:
      self.ssl_socket.shutdown()
      self.ssl_socket.close()
    if self.client_socket:
      self.client_socket.close()
      
    logging.info("SLL Connection closed!")
      
if __name__ == '__main__':
      
  if len(sys.argv) != 2:
    logging.warning('Usage: python ssl_con.py source_file')
    
  source_file = sys.argv[1]
  
  logging.basicConfig(filename='.\\logs\\ssl_connection.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
  
  client = SSLEncryptionClient(source_file)
  client.run()
    