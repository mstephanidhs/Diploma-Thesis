import obspy
import os
import logging

from processor import TraceProcessor

class DataEncryption:
  def __init__(self, source_file, master_key, init_value):
    self.source_file = source_file
    self.master_key = master_key
    self.init_value = init_value
    
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
    
    return encrypted_data