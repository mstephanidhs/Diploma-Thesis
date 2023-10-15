import obspy
import sys

from aes_gcm import AES_GCM

if len(sys.argv) != 3:
    print("Usage: python encryption_script.py source_file target_file")

source_file = sys.argv[1]
target_file = sys.argv[2]

# Define IV (initialization vector) and master key
iv = 0xcafebabefacedbaddecaf888
master_key = 0xfeffe9928665731c6d6a8f9467308308

# Read the miniSEED file
stream = obspy.read(source_file)

# Combine all trace data into a single binary string
binary_seismic_data = b"".join([trace.data.tobytes() for trace in stream])

# Create an instance of the AES_GCM class with the master key
aes_gcm = AES_GCM(master_key)

# Encrypt the binary data
encrypted_data, auth_tag = aes_gcm.encrypt(
    init_value=iv, plaintext=binary_seismic_data)

# Write the encrypted data to the desired path
with open(target_file, 'wb') as file:
    file.write(encrypted_data)

# # Decrypt the encrypted data
# decrypted_data = aes_gcm.decrypt(
#     init_value=iv, ciphertext=encrypted_data, auth_tag=auth_tag)
