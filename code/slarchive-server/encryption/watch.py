import time
import subprocess
import logging

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure the logging
log_file = '.\\logs\\watchdog.log'
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

class OnMyWatch:
  # Set the directory on watch
  watchDirectory = '.\\..\\archive'
  
  def __init__(self):
    self.observer = Observer()
    
  def run(self):
    event_handler = Handler()
    self.observer.schedule(event_handler, self.watchDirectory, recursive=True)
    self.observer.start()
    
    try:
      while True:
        time.sleep(5)
    except:
      self.observer.stop()
      print("Observer Stopped")
      
class Handler(FileSystemEventHandler):
  
  @staticmethod
  def on_modified(event):
    
    # Location of the script to be executed
    encryptionScript = ".\\ssl_con.py"
    
    if not event.is_directory:
      
      message = "Watchdog received event - %s." % event.src_path
      logging.info(message)
      
      # Pass the seismic data to the encryption script
      subprocess.run(['python', encryptionScript, event.src_path])
      
if __name__ == '__main__':
  watch = OnMyWatch()
  watch.run()
    