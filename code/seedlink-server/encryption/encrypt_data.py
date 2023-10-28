import sys

import constants
from processor import TraceProcessor

# TODO: After the encryption of the data, need to store them in a mseed format
# NOT READY YET


if len(sys.argv) != 3:
    print("Usage: python encryption_script.py source_file target_file")
    sys.exit(1)

    source_file = sys.argv[1]
    target_file = sys.argv[2]
