#!/bin/bash

# Define the log file path
LOG_FILE="./logs/output.log"

# >> is used to append output to the log file
# 2>&1 redirects stderr to stdout, so both stdout and stderr are appended to the log file

# Run Docker Compose with output redirection in the background
docker-compose up -d >> "$LOG_FILE" 2>&1 &

# Check the exit status of Docker Compose
if [ $? -eq 0 ]; then
  echo "Docker Compose started successfully." >> "$LOG_FILE"

  # nohup is used to ensure that the process will continue running even if the terminal session is closed
  # Run python script with output redirection in the background
  nohup python ./encryption/watch.py >> "$LOG_FILE" 2>&1 &

  echo "Python script started successfully." >> "$LOG_FILE"

else 
  echo "Docker Compose failed to start. Check the logs for details." >> "$LOG_FILE"
fi

# This script will continue running until it is stopped manually
echo "Script is running. Press Ctrl+C to stop." >> "$LOG_FILE"
while true; do
  sleep 1
done