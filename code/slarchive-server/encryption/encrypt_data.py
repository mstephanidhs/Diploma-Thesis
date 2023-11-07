import obspy
import sys
import logging

from processor import TraceProcessor
import constants

class DataEncryption:
  def __init__(self, source_file):
    self.source_file = source_file
    
  def configure_logging(self):
    logging.basicConfig(filename='.\\logs\\encryption.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - source_file: %(filename)s - %(message)s')
    
  def run(self):
    # Read the source file into a stream
    stream = obspy.read(self.source_file)
    trace = stream[0]
    
    # Initialize a TraceProcessor instance
    processor = TraceProcessor(constants.master_key, constants.init_value)
    
    # Convert the data to binary format
    trace_data = trace.data.tobytes()
    trace_json = processor.convert_trace_to_json(trace)
    
    # Encrypt data
    encrypted_data = processor.encrypt_trace(trace_data, trace_json)
    
    # Add a log entry to indicate the encryption process has completed
    logging.info(f'Encryption process completed for source file: {self.source_file}')
    
    return encrypted_data