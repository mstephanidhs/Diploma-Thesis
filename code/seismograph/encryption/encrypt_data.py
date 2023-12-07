import sys
import bcrypt
import logging
import os
import obspy
import subprocess

from time import time
from dotenv import load_dotenv
from secrets import token_bytes

from processor import TraceProcessor

# Load environment variables from .env file
load_dotenv()

# Configure the logging
logging.basicConfig(filename='.\\logs\\data_encryption.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DataEncryption:
  
  def __init__(self, source_file):
    self.source_file = source_file
    self.password = self.load_password_from_env()
    
  def load_password_from_env(self):
    password = os.getenv('password')
    if password:
      return password
    else:
      logging.warning('Password not found in the .env file.')
      raise ValueError('Password not found in the environment variable.')

    
  def generate_unique_nonce(self, size):
    timestamp_bytes = int(time()).to_bytes(8, byteorder='big')
    random_bytes = token_bytes(size - 8)
  
    return timestamp_bytes + random_bytes
  
  def derive_key_and_iv(self, password, nonce):
    # Encode the password as bytes
    password_bytes = password.encode('utf-8')
    # Use bcrypt to derive a key of the desired length
    derived_key = bcrypt.kdf(password_bytes, salt=nonce, desired_key_bytes=32, rounds=16)
    
    # Use the first 16 bytes as the master key and the next 12 bytes as the IV
    master_key = int.from_bytes(derived_key[:16], byteorder='big')
    iv = int.from_bytes(derived_key[16:28], byteorder='big')
    
    return master_key, iv
  
  def calculate_total_data_size(self, encrypted_data):
    total_data_size = len(encrypted_data)
    # Send the total data size as a 4-byte integer
    total_size_bytes = total_data_size.to_bytes(4, byteorder='big')
    
    return total_size_bytes, total_data_size
  
  def encrypt(self):
    # Read the source file into a stream
    stream = obspy.read(self.source_file)
    trace = stream[0]
    
    # Generate a random nonce
    nonce = self.generate_unique_nonce(16)
    
    # Derive the master key and IV using a constant secret and the random nonce
    master_key, init_value = self.derive_key_and_iv(self.password, nonce)
    
    # Initialize a TraceProcessor instance
    processor = TraceProcessor(master_key, init_value)
    
    # Convert the data to binary format
    trace_data = trace.data.tobytes()
    trace_json = processor.convert_trace_to_json(trace)
    
    # Encrypt data 
    encrypted_data = processor.encrypt_trace(trace_data, trace_json)
    
    logging.info('Seismic Data were encrypted successfully')
    
    return master_key, init_value, encrypted_data

if __name__ == '__main__':
  
  # if len(sys.argv) != 2:
  #   logging.warning('Usage: python ssl_con.py source_file')
  #   sys.exit(1)
    
  # source_file = sys.argv[1]
  source_file = ".\\..\\archive\\2023\\HP\\UPR\\HHN.D\\HP.UPR..HHN.D.2023.338"

  encryption = DataEncryption(source_file)
  master_key, init_value, encrypted_data = encryption.encrypt()

  # Pass the data to the SSL Connection
  subprocess.run(['python', '.\\ssl_con.py', str(master_key), str(init_value)], input=encrypted_data, stdout=subprocess.PIPE)

    