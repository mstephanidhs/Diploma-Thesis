import logging
import obspy
import os
import sys

from datetime import datetime
from processor import TraceProcessor
from aes_gcm import InvalidTagException

# Configure the logging
logging.basicConfig(filename='.\\logs\\data_encryption.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DataDecryption:
  
  def __init__(self, master_key, init_value, encrypted_data):
    self.master_key = master_key
    self.init_value = init_value
    self.encrypted_data = encrypted_data
    
  def decrypt(self):
    processor = TraceProcessor(self.master_key, self.init_value)
    
    decrypted_data = processor.decrypt_trace(self.encrypted_data)
    
    restored_trace_json_bytes, trace_data_binary = processor.split_trace(decrypted_data)
    
    restored_trace = obspy.Trace()
    
    processor.convert_json_to_stats(restored_trace, restored_trace_json_bytes)
    processor.convert_binary_to_data(restored_trace, trace_data_binary, 'data')
    
    logging.info('Received data were decrypted successfully!')
    
    return restored_trace
  
  def store_trace(self, restored_trace):
    # Store the different path that will create the final path to store the trace
    path = []
    filename_path = []
    
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
    
    filename_path.append(restored_trace.stats.network)
    filename_path.append(restored_trace.stats.station)
    filename_path.append(restored_trace.stats.location)
    filename_path.append(restored_trace.stats.channel)
    filename_path.append(restored_trace.stats.mseed.dataquality)
    filename_path.append(str(current_year))
    
    # Get the current date
    current_date = datetime.now()
    
    # Format the date to include the day of the year with zero-padding
    day_of_year_padded = current_date.strftime("%j")
    filename_path.append(day_of_year_padded)
    
    # Create the actual filename
    filename = ".".join(filename_path)
    
    # Append the filename to the final path
    final_path = os.path.join(final_path, filename)
    
    restored_trace.write(final_path, format="MSEED")
    
    logging.info("Trace was stored successfully")   
    

if __name__ == '__main__':
  
  if len(sys.argv) !=3:
    logging.warning('Usage: python decrypt_data.py master_key init_value')
    sys.exit(1)
    
  try:
    master_key = int(sys.argv[1])
    init_value = int(sys.argv[2])
  except ValueError:
    logging.warning('Error: Invalid master_key or init_value')
    sys.exit(1)
    
  # Read the received_data from stdin
  received_data = sys.stdin.buffer.read()
  
  # Decrypt seismic data
  decryption = DataDecryption(master_key, init_value, received_data)
  
  try:
    restored_trace = decryption.decrypt()
    decryption.store_trace(restored_trace)
  except InvalidTagException as ite:
    logging.error(f'Invalid authentication tag: {ite}')
    sys.exit(1)