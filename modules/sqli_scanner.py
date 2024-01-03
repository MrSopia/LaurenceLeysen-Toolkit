import subprocess
import logging

# Get the logger configured in the main script
logger = logging.getLogger(__name__)


class sqli_scanner:
    def __init__(self, target_url):
        self.target_url = target_url

    def run_scan(self):
        try:
            command = ["sqlmap", "-u", self.target_url, "--dbs"]
            
            # Use subprocess.Popen to capture and display real-time output
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            
            # Read and logger.info the output line by line
            for line in process.stdout:
                logger.info(line)

            # Wait for the process to complete and get the return code
            process.communicate()
            return process.returncode
        except subprocess.CalledProcessError as e:
            return e.output