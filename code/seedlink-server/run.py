import subprocess
import os
import logging

if __name__ == "__main__":
    try:
      
        # Get the current directory of the script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Configure the logging
        log_file = os.path.join(script_dir, 'decryption', 'logs', 'run.log')
        logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')
        
        # Navigate to the directory containg the watch.py script
        python_script_path = os.path.join(script_dir, 'decryption')

        # Start Python script in another command prompt window
        python_script_process = subprocess.Popen(["start", "cmd", "/k", "python ssl_con.py"], cwd=python_script_path,shell=True)
        
        logging.info("Server started.")
        
        # Start Docker Compose in a new command prompt window
        docker_compose_process = subprocess.Popen(["start", "cmd", "/k", "docker-compose up"], cwd=script_dir,shell=True)
        
        logging.info("Seedlink Container started.")

        # Wait for both processes to finish
        docker_compose_process.wait()
        python_script_process.wait()

    except KeyboardInterrupt:
        # Handle Ctrl+C if needed
        pass

    finally:
        print("Script execution complete.")
