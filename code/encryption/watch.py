import time
import re
import os
import subprocess

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileDeletedEvent


class OnMyWatch:
    # Set the directory on watch
    watchDirectory = "./archive"

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
    def on_any_event(event):
        # The directory where the encrypted data will be stored
        toSaveDirectory = "./archive_encrypt"
        # Location of the encryption script
        encryptionScript = "./encrypt_data.py"

        # In case of the deletion event, do nothing
        if isinstance(event, FileDeletedEvent):
            return None

        if not event.is_directory:
            # Event is created, you can process it now
            print("Watchdog received event - % s." % event.src_path)

            # Remove the "./" part from the beginning of the path
            path = event.src_path.lstrip("./")

            # Split the path by backslashes and remove empty parts
            path_parts = [part for part in re.split(r'[\\/]', path) if part]

            # Build the target directory structure in archive_encrypt folder
            target_dir = ("\\".join(path_parts[2:len(path_parts)-1]))
            full_path = os.path.join(toSaveDirectory, target_dir)
            os.makedirs(full_path, exist_ok=True)

            # pass the seismic data to the encryption script
            subprocess.run(['python', encryptionScript, event.src_path, os.path.join(
                full_path, os.path.basename(event.src_path))])


if __name__ == '__main__':
    watch = OnMyWatch()
    watch.run()
