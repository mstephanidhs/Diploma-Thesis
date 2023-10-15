# Python base image
FROM python:3.8

# Set the working directory
WORKDIR /app

# Copy monitoring and the encryption script and also the 
# aes algorithm into the container
COPY aes_gcm.py encrypt_data.py watch.py /app/

# Install any dependencies required 
RUN pip install watchdog==3.0.0 pycryptodome==3.19.0 obspy==1.4.0

# Run the monitoring script when the container starts
CMD ["python", "watch.py"]

