import numpy as np
import json
from aes_gcm import AES_GCM


class TraceProcessor:

    def __init__(self, master_key, init_value):
        self.master_key = master_key
        self.init_value = init_value
        # Choose a delimiter that won't occur naturally in the seismic data
        self.delimeter = b'\x00\xFF\x00\xFF\x00'

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
        return json.dumps(serializable_stats, index=2).encode()

    def encrypt_trace(self, trace_data, trace_stats):
        # Using a delimiter in order to split the 2 parts afterwards
        trace_combined = trace_stats + self.delmiter + trace_data
        # Create an instance of AES_GCM with the master key
        my_gcm = AES_GCM(self.master)
        # encrypt the combined trace data and stats
        encrypted_trace, auth_tag = my_gcm.encrypt(
            self.init_value, trace_combined)
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
        # Decrypt the data
        return my_gcm.decrypt(self.init_value, encrypted_trace[:-16], auth_tag)

    def split_trace(self, combined_data):
        # Find the position of the delimeter
        delimiter_position = combined_data.index(self.delimeter)
        # Extract the portion of combined_data that correspond to trace.stats
        trace_json_bytes = combined_data[:delimiter_position]
        # Extract the portion of combined_data that correspond to trace.data
        trace_data_binary = combined_data[delimiter_position +
                                          len(self.delimeter):]
        return trace_json_bytes, trace_data_binary

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

    def convert_binary_to_data(self, trace, trace_data_binary):
        # Converts binary data into a 1-dimensional NumPy array
        # dtype: indicates that the binary data should be interpreted
        # as 32-bit signed integers
        trace.data = np.frombuffer(trace_data_binary, dtype=np.int32)
