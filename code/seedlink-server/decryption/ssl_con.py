import socket 
import logging
import obspy
import os

from OpenSSL import SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime

from processor import TraceProcessor

class SSLServer:
  def __init__(self, host, port, allowed_ips_file, max_requests=10, time_window_seconds=60):
    self.host = host
    self.port = port
    self.server_socket = None
    self.context = None
    self.allowed_ips = self.load_allowed_ips(allowed_ips_file)
    # Dictionary to store request counts for each IP
    self.request_counts = {}
    self.max_requests = max_requests
    self.time_window_seconds = time_window_seconds
    
    
  def load_allowed_ips(self, allowed_ips_file):
    try:
      with open(allowed_ips_file, 'r') as file:
        return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
      logging.error(f"Allowed IPs file not found: {allowed_ips_file}")
      return []
    
  def configure_logging(self):
    logging.basicConfig(filename='.\\logs\\ssl_connection.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
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
    
  def start_server(self):
    print('Server is listening on port {}...'.format(self.port))
    while True:
      client_socket, client_address = self.server_socket.accept()
      if not self.is_client_allowed(client_address):
        logging.warning(f'Rejected connection from {client_address}')
        rejection_message = 'Connection rejected. Your IP is not allowed.'
        client_socket.send(rejection_message.encode())
        client_socket.close()
        continue
      
      if not self.is_request_allowed(client_address):
        logging.warning(f'Rejected connection from {client_address} due to excessive requests.')
        rejection_message = 'Connection rejected. Too many requests in a short period.'
        client_socket.send(rejection_message.encode())
        client_socket.close()
        
        # Remove the IP from allowed_ips
        ip = client_address[0]
        if ip in self.allowed_ips:
          self.allowed_ips.remove(ip)
        continue
        
      logging.info(f'Accepted connection from {client_address}')
      self.handle_client(client_socket)
      
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
      
    return is_allowed
      
  def decrypt_master_iv(self, encrypted_master_key, encrypted_iv, cipher):
    master_key_bytes = cipher.decrypt(encrypted_master_key)
    iv_bytes = cipher.decrypt(encrypted_iv)
    
    # Convert the bytes to integers
    master_key = int.from_bytes(master_key_bytes, byteorder='big')
    iv = int.from_bytes(iv_bytes, byteorder='big')
    
    logging.info("Received successfully Master Key and IV.")
    
    return master_key, iv
  
  def decrypt_filename(self, encrypted_filename, cipher):
    encrypted_filename_bytes = cipher.decrypt(encrypted_filename)
    filename = encrypted_filename_bytes.decode('utf-8')
    
    return filename
  
  def decrypt_total_data_size(self, encrypted_total_size, cipher):
    total_size_bytes = cipher.decrypt(encrypted_total_size)
    total_data_size = int.from_bytes(total_size_bytes, byteorder='big')
    
    return total_data_size
  
  def decrypt_chunk_size(self, encrypted_chunk_size, cipher):
    chunk_size_bytes = cipher.decrypt(encrypted_chunk_size)
    chunk_size = int.from_bytes(chunk_size_bytes, byteorder='big')
    
    return chunk_size
  
  def receive_encrypted_data(self, total_data_size, chunk_size, ssl_socket):
    # Create a variable to store the received data
    received_data = b""
    
    while len(received_data) < total_data_size:
      # Receive a chunk of data based on the received 'chunk_size'
      chunk = ssl_socket.recv(chunk_size)
      
      # Append the received chunk to the existing data
      received_data += chunk
      
    logging.info("Received the encrypted data")
  
    return received_data
  
  def decrypt_received_data(self, master_key, iv, received_data):
    processor = TraceProcessor(master_key, iv)
    
    decrypted_data = processor.decrypt_trace(received_data)
    
    restored_trace_json_bytes, trace_data_binary = processor.split_trace(decrypted_data)
    
    restored_trace = obspy.Trace()
    
    processor.convert_json_to_stats(restored_trace, restored_trace_json_bytes)
    processor.convert_binary_to_data(restored_trace, trace_data_binary, 'data')
    
    return restored_trace
  
  def store_trace(self, restored_trace, filename):
    # Store the different path that will create the final path to store the trace
    path = []
    
    # Current year
    current_year = datetime.now().year
    path.append(str(current_year))
    
    # Network
    path.append(restored_trace.stats.network)
    
    # Station
    path.append(restored_trace.stats.station)
    
    # Channel & Dataquality
    channel = restored_trace.stats.channel
    dataquality = restored_trace.stats.mseed.dataquality
    chaData = channel + '.' + dataquality
    path.append(chaData)
    
    parts_combined = "\\".join(path)
    
    # Specify the path where the MiniSEED file will be stored
    final_path = '.\\..\\archive' + '\\' + parts_combined
    
    # Create directories if they don't exist
    os.makedirs(final_path, exist_ok=True)
    
    # Append the filename to the final path
    final_path = os.path.join(final_path, filename)
    
    restored_trace.write(final_path, format="MSEED")
    
    logging.info("Trace was stored successfully")
    
  def handle_client(self, client_socket):
    # Wrap the client socket in an SSL connection
    ssl_socket = SSL.Connection(self.context, client_socket)
    ssl_socket.set_accept_state()
    
    try:
      ssl_socket.do_handshake()
      logging.info('Handshake was successful!')
      
      # Send the server's public key to the client after the handshake
      server_public_key = open('.\\..\\server_cred\\server-cert.pem', 'rb').read()
      ssl_socket.send(server_public_key)
      
      # Decrypt the data received using the server's private key
      server_private_key = RSA.importKey(open('.\\..\\server_cred\\server-key.pem').read())
      cipher = PKCS1_OAEP.new(server_private_key)
      
      # Securely receive the client's encrypted master key
      encrypted_master_key = ssl_socket.recv(4096)
      # Securely receive the client's encrypted IV
      encrypted_iv = ssl_socket.recv(4096)
      
      master_key, iv = self.decrypt_master_iv(encrypted_master_key, encrypted_iv, cipher)
      
      # Receive the total data size as a 4-byte integer
      encrypted_total_size = ssl_socket.recv(4096)
      total_data_size = self.decrypt_total_data_size(encrypted_total_size, cipher)
      
      # Receive the chunk size from the client
      # Assuming a 4-byte chunk size
      encrypted_chunk_size = ssl_socket.recv(4096) 
      chunk_size = self.decrypt_chunk_size(encrypted_chunk_size, cipher)
      
      received_data = self.receive_encrypted_data(total_data_size, chunk_size, ssl_socket)
      
      restored_trace = self.decrypt_received_data(master_key, iv, received_data)
      
      encrypted_filename = ssl_socket.recv(4096)
      filename = self.decrypt_filename(encrypted_filename, cipher)
      
      self.store_trace(restored_trace, filename)

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
  server.configure_logging()
  server.create_server_socket()
  server.create_ssl_context()
  server.start_server()