import os
import subprocess
import time
import random
import logging
import re
import sys
from datetime import datetime, timedelta

# --- Configuration and Paths --- #
TEST_DURATION_SECONDS = 3600  # Run for 1 hour
LOG_FILE = 'test_harness.log'

def get_base_dir():
    """Gets the base directory, working for both scripts and bundled executables."""
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # If running from a PyInstaller bundled exe
        return os.path.dirname(sys.executable)
    else:
        # If running from a .py script file
        return os.path.dirname(os.path.abspath(__file__))

# Assume all files (harness, malware, process guard, log) are in the same directory.
BASE_DIR = get_base_dir()
PROCESS_GUARD_LOG = os.path.join(BASE_DIR, 'detector.log')
MALWARE_DIR = BASE_DIR

def setup_logging():
    """Sets up logging to a file and the console."""
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
        
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE, mode='w', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

def get_random_exe_from_common_dirs():
    """Gets a random executable file from common directories on Windows."""
    exe_files = []
    system_root = os.environ.get("SystemRoot", "C:\\Windows")
    user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Public")
    common_dirs = [
        system_root,
        os.path.join(system_root, "System32"),
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        os.path.join(user_profile, "Desktop"),
        os.path.join(user_profile, "Downloads"),
        "C:\\Users\\Public"
    ]
    for directory in common_dirs:
        if not os.path.isdir(directory):
            continue
        for root, dirs, files in os.walk(directory):
            for f in files:
                if f.lower().endswith('.exe'):
                    exe_files.append(os.path.join(root, f))
    if exe_files:
        return random.choice(exe_files)
    logging.error("Could not find any executables in common directories.")
    return None

def run_process(full_command):
    logging.info(f"[BENIGN] Executing: {full_command}")
    process = None
    try:
        # Use shell=False to get correct PID
        if isinstance(full_command, str):
            cmd = full_command if full_command.startswith('"') else full_command.split()
        else:
            cmd = full_command
        process = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info(f"Launched process with PID: {process.pid}")
        return process
    except FileNotFoundError:
        logging.error(f"Error: Executable not found for command: {full_command}")
    except Exception as e:
        logging.error(f"Error running {full_command}: {e}")
    return None

def run_malicious():
    exe_path = os.path.join(MALWARE_DIR, 'process_doppelganging.exe')
    full_command = [exe_path, 'mimikatz.exe']
    logging.info(f"[MALICIOUS] Executing: {full_command}")
    try:
        process = subprocess.Popen(full_command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)
        if process.poll() is None:
            subprocess.run(f"taskkill /F /PID {process.pid} /T", check=False, capture_output=True, shell=True)
            time.sleep(1)
            if process.poll() is None:
                # If kill by PID fails, try kill by process name
                logging.warning(f"[MALICIOUS] Could not terminate process_doppelganging.exe by PID, trying by name...")
                result = subprocess.run("taskkill /IM process_doppelganging.exe /F /T", check=False, capture_output=True, shell=True)
                time.sleep(1)
                if process.poll() is None:
                    logging.error(f"[MALICIOUS] Still could not terminate process_doppelganging.exe by name. taskkill output: {result.stdout.decode(errors='ignore')} {result.stderr.decode(errors='ignore')}")
                else:
                    logging.info(f"[MALICIOUS] Terminated process_doppelganging.exe by name successfully.")
            else:
                logging.info(f"[MALICIOUS] Terminated process_doppelganging.exe successfully by PID.")
    except Exception as e:
        logging.error(f"Error running or terminating malicious process process_doppelganging.exe: {e}")

def main():
    """Main function to run the test harness."""
    setup_logging()
    
    # Delete the old ProcessGuard log to ensure fresh results
    if os.path.exists(PROCESS_GUARD_LOG):
        logging.info(f"Deleting old ProcessGuard log file: {PROCESS_GUARD_LOG}")
        try:
            os.remove(PROCESS_GUARD_LOG)
        except OSError as e:
            logging.error(f"Could not delete {PROCESS_GUARD_LOG}: {e}")

    logging.info("--- STARTING RANDOM SYSTEM EXE & MALICIOUS TEST HARNESS ---")
    logging.info(f"Test duration: {TEST_DURATION_SECONDS} seconds")
    logging.info(f"Harness log file: {os.path.abspath(LOG_FILE)}")
    logging.info(f"Monitoring ProcessGuard log at: {PROCESS_GUARD_LOG}")
    logging.info("Please run ProcessGuard in monitoring mode in a separate terminal.")
    logging.info("Suggested command: .\\ProcessGuard.exe --monitor (run from the same directory)")
    
    start_time = datetime.now()
    end_time = start_time + timedelta(seconds=TEST_DURATION_SECONDS)
    benign_count = 0
    malicious_count = 0
    while datetime.now() < end_time:
        # 10% run malicious, 90% run benign
        is_malicious = random.choices([True, False], weights=[0.1, 0.9], k=1)[0]
        if is_malicious:
            run_malicious()
            malicious_count += 1
            logging.info(f"[STATS] Malicious run count: {malicious_count}")
        else:
            exe_path = get_random_exe_from_common_dirs()
            if exe_path:
                time.sleep(10)
                process = run_process([exe_path])
                if process:
                    time.sleep(5)
                    if process.poll() is None:
                        try:
                            subprocess.run(f"taskkill /F /PID {process.pid} /T", check=True, capture_output=True, shell=True)
                            logging.info(f"Terminated benign process (PID: {process.pid}) and its children.")
                        except Exception as e:
                            logging.error(f"Error terminating benign process (PID: {process.pid}): {e}")
                benign_count += 1
                logging.info(f"[STATS] Benign run count: {benign_count}")
        
        # Wait for a random interval before the next action
        sleep_time = random.randint(5, 10)
        logging.info(f"Waiting for {sleep_time} seconds before next action...")
        time.sleep(sleep_time)
        
    logging.info("--- TEST HARNESS FINISHED ---")
    logging.info(f"[SUMMARY] Total benign runs: {benign_count}")
    logging.info(f"[SUMMARY] Total malicious runs: {malicious_count}")

if __name__ == "__main__":
    main()

