import logging
import socket
import subprocess

from threading import Lock
from collections import defaultdict
from datetime import datetime
from OpenSSL import SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Configure logging
logging.basicConfig(filename='.\\logs\\ssl_connection.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SSLServer:
  
  def __init__(self, host, port, allowed_ips_file, max_requests=10, time_window_seconds=60, token_bucket_capacity=20, token_fill_rate=2):
    self.host = host
    self.port = port
    self.server_socket = None
    self.context = None
    
    self.allowed_ips = self.load_allowed_ips(allowed_ips_file)

    # Dictionary to store a list of request timestamps for each IP address
    self.request_counts = defaultdict(list)

    # Dictionary to store the token bucket information for each IP address
    # Each entry includes the current number of tokens and the timestamp of the last refill
    self.token_bucket = defaultdict(lambda: {'tokens': token_bucket_capacity, 'last_refill_time': datetime.now()})

    # Maximum number of allowed requests per time window for each IP
    self.max_requests = max_requests

    # Time window duration (in seconds) within which requests are counted
    self.time_window_seconds = time_window_seconds

    # Maximum capacity of the token bucket for each IP
    self.token_bucket_capacity = token_bucket_capacity

    # Rate at which tokens are added to the token bucket (tokens per second)
    self.token_fill_rate = token_fill_rate

    # Time interval (in seconds) at which the token bucket is refilled
    self.token_refill_interval = 1 # seconds

    # Lock to ensure thread-safe token bucket refilling
    self.token_refill_lock = Lock()
    
  def load_allowed_ips(self, allowed_ips_file):
    try:
      with open(allowed_ips_file, 'r') as file:
        return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
      logging.error(f"Allowed IPs file not found: {allowed_ips_file}")
      return []
    
  def create_server_socket(self):
    self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.server_socket.bind((self.host, self.port))
    self.server_socket.listen(1) # Listen for incoming connections
    
  def create_ssl_context(self):
    # Create an SSL context for the server
    # ssl.PROTOCOL_SSLv23, represents SSLv23, a flexible protocol that can negotiate various versions of SSL/TLS.
    self.context = SSL.Context(SSL.SSLv23_METHOD)    
    # Execute the below command in order to produce the server-certs needed
    # openssl req -x509 -nodes -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem -days 365
    self.context.use_privatekey_file('.\\..\\server_cred\\server-key.pem')
    self.context.use_certificate_file('.\\..\\server_cred\\server-cert.pem')
    
  def is_client_allowed(self, client_address):
    return client_address[0] in self.allowed_ips
  
  def is_request_allowed(self, client_address):
    ip = client_address[0]
    current_time = datetime.now()
    
    # Initialize request count for the IP if not present
    if ip not in self.request_counts:
      self.request_counts[ip] = []
      
    # Remove requests older than the time window
    self.request_counts[ip] = [t for t in self.request_counts[ip] if (current_time - t).total_seconds() <= self.time_window_seconds]
    
    # Add the current request time
    self.request_counts[ip].append(current_time)
    
    # Check if the request count exceeds the threshold
    is_allowed = len(self.request_counts[ip]) <= self.max_requests
    
    # If not allowed, remove the IP from allowed_ips
    if not is_allowed and ip in self.allowed_ips:
      self.allowed_ips.remove(ip)

    # Token Bucket Algorithm - Ensures a controlled rate of requests for each IP address

    # Acquire the lock to ensure thread safety during token bucket updates
    with self.token_refill_lock:

      # Calculate the time elapsed since the last token
      time_since_last_refill = (current_time - self.token_bucket[ip]['last_refill_time']).total_seconds()

      # Calculate the number of tokens to add based on the refill interval and fill rate
      tokens_to_add = int(time_since_last_refill / self.token_refill_interval) * self.token_fill_rate

      # Update the token bucket: add new tokens, but ensure it doesn't exceed the capacity
      self.token_bucket[ip]['tokens'] = min(self.token_bucket_capacity, self.token_bucket[ip]['tokens'] + tokens_to_add)

      # Update the timestamp of the last refill to the current time
      self.token_bucket[ip]['last_refill_time'] = current_time

      # Check if there are enough tokens to allow the current request
      if self.token_bucket[ip]['tokens'] >= 1:
        # Consume one token for the current request
        self.token_bucket[ip]['tokens'] -= 1

        # Allow the request since there are enough tokens
        return is_allowed
      else:
        # Deny the request since there are not enough tokens
        return False
      
  def handshake(self, ssl_socket):
    ssl_socket.do_handshake()
    
    # Send the server's public key to the client after the handshake
    server_public_key = open('.\\..\\server_cred\\server-cert.pem', 'rb').read()
    ssl_socket.send(server_public_key)
    
  def private_key_decryption(self):
    # Decrypt the data received using the server's private key
    server_private_key = RSA.importKey(open('.\\..\\server_cred\\server-key.pem').read())
    cipher = PKCS1_OAEP.new(server_private_key)
    
    return cipher
  
  def receive_and_decrypt_master_key_iv(self, ssl_socket, cipher):
    # Securely receive the client's encrypted master key & IV
    encrypted_master_key = ssl_socket.recv(4096)
    encrypted_iv = ssl_socket.recv(4096)
    
    master_key_bytes = cipher.decrypt(encrypted_master_key)
    iv_bytes = cipher.decrypt(encrypted_iv)
    
    # Convert the bytes to integers
    master_key = int.from_bytes(master_key_bytes, byteorder='big')
    iv = int.from_bytes(iv_bytes, byteorder='big')
    
    return master_key, iv
  
  def receive_and_decrypt_total_data_size(self, ssl_socket, cipher):
    # Receive the total data size as a 4-byte integer
    encrypted_total_size = ssl_socket.recv(4096)
    total_size_bytes = cipher.decrypt(encrypted_total_size)
    total_data_size = int.from_bytes(total_size_bytes, byteorder='big')
    
    return total_data_size
  
  def receive_and_decrypt_chunk_size(self, ssl_socket, cipher):
    # Receive the chunk size from the client
    # Assuming a 4-byte chunk size
    encrypted_chunk_size = ssl_socket.recv(4096) 
    chunk_size_bytes = cipher.decrypt(encrypted_chunk_size)
    chunk_size = int.from_bytes(chunk_size_bytes, byteorder='big')
    
    return chunk_size
  
  def receive_encrypted_data(self, total_data_size, chunk_size, ssl_socket):
    #  Create a variable to store the received data
    received_data = b''
    
    while len(received_data) < total_data_size:
      # Receive a chunk of data based on the received chunk_size
      chunk = ssl_socket.recv(chunk_size)
      
      # Append the received chunk to the existing data
      received_data += chunk
      
    logging.info('Received the encrypted data')
    
    return received_data
  
  def start_server(self):
    print('Server is listening on port {}...'.format(self.port))
    while True:
      client_socket, client_address = self.server_socket.accept()
      if not self.is_client_allowed(client_address):
        logging.warning(f'Rejected connection from {client_address}')
        client_socket.close()
        continue
      
      if not self.is_request_allowed(client_address):
        logging.warning(f'Rejected connection from {client_address} due to excessive requests.')
        client_socket.close()
        
        # Remove the IP from allowed_ips
        ip = client_address[0]
        if ip in self.allowed_ips:
          self.allowed_ips.remove(ip)
        continue
        
      logging.info(f'Accepted connection from {client_address}')
      self.handle_client(client_socket)
    
  def handle_client(self, client_socket):
    # Wrap the client socket in an SSL connection
    ssl_socket = SSL.Connection(self.context, client_socket)
    ssl_socket.set_accept_state()
    
    try:
      self.handshake(ssl_socket)
      
      cipher = self.private_key_decryption()
      
      master_key, iv = self.receive_and_decrypt_master_key_iv(ssl_socket, cipher)
      
      total_data_size = self.receive_and_decrypt_total_data_size(ssl_socket, cipher)
      
      chunk_size = self.receive_and_decrypt_chunk_size(ssl_socket, cipher)
      
      received_data = self.receive_encrypted_data(total_data_size, chunk_size, ssl_socket)
      
      # Pass the data to the decryption script
      subprocess.run(['python', '.\\decrypt_data.py', str(master_key), str(iv)], input=received_data, stdout=subprocess.PIPE)
    
    except SSL.Error as e:
      logging.error(f'TLS handshake error: {e}', exc_info=True)
    except Exception as e:
      logging.error(f'An error occured: {e}', exc_info=True)
      
    finally:
      # Close the SSL connection and the client socket
      ssl_socket.shutdown()
      ssl_socket.close()
      client_socket.close()
      
if __name__ == '__main__':
  # 0.0.0.0, it's binding to all available network interfaces and 
  # can accept incoming connections from any IP address.
  server = SSLServer('0.0.0.0', 8443, '.\\..\\allowed_ips.conf') # Bind to a specific host and port
  server.create_server_socket()
  server.create_ssl_context()
  server.start_server()
  