import numpy as np
import json

from aes_gcm import AES_GCM
from exception.decryption_error import DecryptionError
from exception.invalid_data_type_error import InvalidDataTypeError

class TraceProcessor:
  
  def __init__(self, master_key, init_value):
    self.master_key = master_key
    self.init_value = init_value
    self.delimiter = b'\x00\xFF\x00\xFF\x00'
    self.type_to_dtype = {
      "data": np.int32,
      "time": np.float64, 
    }
    
  def convert_trace_to_json(self, trace):
      # Converts a trace object and specifically its stats property into a dictionary
        serializable_stats = {
            "network": trace.stats.network,
            "station": trace.stats.station,
            "location": trace.stats.location,
            "channel": trace.stats.channel,
            "starttime": trace.stats.starttime.isoformat(),
            "endtime": trace.stats.endtime.isoformat(),
            "sampling_rate": float(trace.stats.sampling_rate),
            "delta": float(trace.stats.delta),
            "npts": trace.stats.npts,
            "calib": float(trace.stats.calib),
            "_format": trace.stats._format,
            "mseed": {
                "dataquality": trace.stats.mseed.dataquality,
                "number_of_records": trace.stats.mseed.number_of_records,
                "encoding": trace.stats.mseed.encoding,
                "byteorder": trace.stats.mseed.byteorder,
                "record_length": trace.stats.mseed.record_length,
                "filesize": trace.stats.mseed.filesize
            }
        }

        # Converts the dictionary into a JSON string witn an indentation of 2 spaces
        # Then, encodes the JSON string into bytes
        return json.dumps(serializable_stats, indent=2).encode()
      
  def encrypt_trace(self, trace_data, trace_stats):
    trace_combined = trace_stats + self.delimiter + trace_data
    
    # Create an instance of AES_GCM with the master_key
    my_gcm = AES_GCM(self.master_key)
    
    # Encrypt the combined trace data, timed & stats
    encrypted_trace, auth_tag = my_gcm.encrypt(self.init_value, trace_combined)
    
    # Convert auth_tag to a byte representation with a length of 16 bytes and a big-endian byte order
    auth_tag_bytes = auth_tag.to_bytes(16, byteorder='big')
    
    # Combine them both
    encrypted_trace_with_tag = encrypted_trace + auth_tag_bytes
    
    return encrypted_trace_with_tag
  
  def decrypt_trace(self, encrypted_trace):
    my_gcm = AES_GCM(self.master_key)
    
    # Extract the auth tag that is stored at the end of the encrypted_trace
    auth_tag_bytes = encrypted_trace[-16:]
  
    # Convert the auth tag back to an integer
    auth_tag = int.from_bytes(auth_tag_bytes, byteorder='big')
    
    # Decrypt the data (excluding the auth tag)
    return my_gcm.decrypt(self.init_value, encrypted_trace[:-16], auth_tag)
  
  def split_trace(self, combined_data):
    parts = combined_data.split(self.delimiter)
    
    if len(parts) == 2:
      trace_stats, trace_data = parts
    else:
      raise DecryptionError('Decryption failed. Invalid data format.')
    
    return trace_stats, trace_data
  
  def convert_json_to_stats(self, trace, stats_json_bytes):
    # deserialize the JSON string into a dictionary
    restored_stats_dict = json.loads(stats_json_bytes)
    trace.stats.network = restored_stats_dict.get("network", "")
    trace.stats.station = restored_stats_dict.get("station", "")
    trace.stats.location = restored_stats_dict.get("location", "")
    trace.stats.channel = restored_stats_dict.get("channel", "")
    trace.stats.starttime = restored_stats_dict.get("starttime", "")
    trace.stats.sampling_rate = restored_stats_dict.get(
        "sampling_rate", 0.0)
    trace.stats.delta = restored_stats_dict.get("delta", 0.0)
    trace.stats.npts = restored_stats_dict.get("npts", 0)
    trace.stats.calib = restored_stats_dict.get("calib", 1.0)
    trace.stats._format = restored_stats_dict.get("_format", "")
    trace.stats.mseed = {
        "dataquality": restored_stats_dict["mseed"]["dataquality"],
        "number_of_records": restored_stats_dict["mseed"]["number_of_records"],
        "encoding": restored_stats_dict["mseed"]["encoding"],
        "byteorder": restored_stats_dict["mseed"]["byteorder"],
        "record_length": restored_stats_dict["mseed"]["record_length"],
        "filesize": restored_stats_dict["mseed"]["filesize"]
    }
    
  def convert_binary_to_data(self, trace, trace_data_binary, data_type):
    # Check if the data_type is valid
    if data_type in self.data_type_to_dtype:
      dtype = self.data_type_to_dtype[data_type]
      data = np.frombuffer(trace_data_binary, dtype=dtype)
      
      # Set the data to the appropriate attribute of the trace object
      if data_type == "data":
        trace.data = data
      elif data_type == "time":
        trace.times = data
    else:
      raise InvalidDataTypeError(data_type)