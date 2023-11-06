import obspy 
import sys
import logging

import constants
from processor import TraceProcessor

# Configure logging
logging.basicConfig(filename='.\\logs\\encryption.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - source_file: %(filename)s - %(message)s')

if len(sys.argv) != 3:
  logging.warning('Usage: python encryption_script.py source_file target_file')
  sys.exit(1)
  
source_file = sys.argv[1]
target_file = sys.argv[2]

stream = obspy.read(source_file)
trace = stream[0]

# Initialize a TraceProcessor instance
processor = TraceProcessor(constants.master_key, constants.init_value)

# Convert the data to binary format
trace_data = trace.data.tobytes()
trace_json = processor.convert_trace_to_json(trace)

# Encrypt data
encrypted_trace = processor.encrypt_trace(trace_data, trace_json)

# Write the encrypted data
with open(target_file, 'wb') as file:
  file.write(encrypted_trace)
  
# Add a log entry to indicate the encryption process has completed
logging.info(f'Encryption process completed for source file: {source_file}')
