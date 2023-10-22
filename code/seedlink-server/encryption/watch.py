import time
import re
import os
import subprocess
import logging

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure the logging
log_file = 'watchdog.log'
logging.basicConfig(filename=log_file, level=logging.INFO,
                    format='%(asctime)s - %(message)s')


class OnMyWatch:
    # Set the directory on watch
    watchDirectory = ".\\..\\archive"

    def __init__(self):
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        self.observer.schedule(
            event_handler, self.watchDirectory, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except:
            self.observer.stop()
            print("Observer Stopped")

        self.observer.join()


class Handler(FileSystemEventHandler):

    @staticmethod
    def on_modified(event):

        # The directory where the encrypted data will be stored
        toSaveDirectory = ".\\..\\archive_encrypt"
        # Location of the encryption script
        encryptionScript = ".\\encrypt_data.py"

        if not event.is_directory:

            message = "Watchdog received event - %s." % event.src_path
            logging.info(message)

            # Split the path by backslashes and remove empty parts
            path_parts = [part for part in re.split(
                r'[\\/]', event.src_path) if part]

            # Build the target directory structure in archive_encrypt folder
            target_dir = "\\".join(path_parts[3:-1])
            full_path = os.path.join(toSaveDirectory, target_dir)
            os.makedirs(full_path, exist_ok=True)

            # Pass the seismic data to the encryption script
            subprocess.run(['python', encryptionScript, event.src_path, os.path.join(
                full_path, os.path.basename(event.src_path))])


if __name__ == '__main__':
    watch = OnMyWatch()
    watch.run()
