import obspy
import os
import logging

from processor import TraceProcessor

class DataEncryption:
  def __init__(self, source_file, master_key, init_value):
    self.source_file = source_file
    self.master_key = master_key
    self.init_value = init_value
    
  def configure_logging(self):
    log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs', 'data_encryption.log')
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - source_file: %(filename)s - %(message)s')
    
  def run(self):
    # Read the source file into a stream
    stream = obspy.read(self.source_file)
    trace = stream[0]
    
    # Initialize a TraceProcessor instance
    processor = TraceProcessor(self.master_key, self.init_value)
    
    # Convert the data to binary format
    trace_data = trace.data.tobytes()
    trace_json = processor.convert_trace_to_json(trace)
    
    # Encrypt data
    encrypted_data = processor.encrypt_trace(trace_data, trace_json)
  
    # Add a log entry to indicate the encryption process has completed
    message = "Encryption process completed for source file: %s." % self.source_file
    logging.info(message)
    
    return encrypted_data