import sys
import obspy
import numpy as np

import constants
from processor import TraceProcessor

if len(sys.argv) != 3:
    print("Usage: python encryption_script.py source_file target_file")
    sys.exit(1)

source_file = sys.argv[1]
target_file = sys.argv[2]

stream = obspy.read(source_file)
trace = stream[0]

print(trace.stats)
print(trace.data)

processor = TraceProcessor(constants.master_key, constants.init_value)

trace_data = trace.data.tobytes()
trace_json = processor.convert_trace_to_json(trace)

encrypted_trace = processor.encrypt_trace(trace_data, trace_json)


####### Decryption #######

decrypted_combined_data = processor.decrypt_trace(encrypted_trace)

restored_trace_json_bytes, trace_data_binary = processor.split_trace(
    decrypted_combined_data)

restored_trace = obspy.Trace()
processor.convert_json_to_stats(restored_trace, restored_trace_json_bytes)
processor.convert_binary_to_data(restored_trace, trace_data_binary)

print(restored_trace.stats)
print(restored_trace.data)
