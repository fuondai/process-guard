#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Protection module for ProcessGuard
---------------------------------
Implements self-protection mechanisms against malicious termination.
This module ensures that the ProcessGuard can run reliably and restart
itself if terminated.

Uses PowerShell-based watchdog mechanisms - simple approach without WMI.
"""
import os
import sys
import time
import subprocess
import tempfile
import traceback
import threading

# Import utils for admin check
from .utils import is_admin
from .logger import get_logger

class ProcessProtection:
    """Implements self-protection mechanisms for ProcessGuard using Windows Task Scheduler."""
    
    def __init__(self, check_interval=1):
        """Initialize protection with check interval in minutes."""
        self.pid = os.getpid()
        self.check_interval = check_interval  # In minutes
        self.is_protected = False
        self.task_name = "ProcessGuardWatchdog"
        self.logger = get_logger()
    
    def protect_process(self):
        """Apply protection mechanisms to the current process using Task Scheduler."""
        try:
            self.logger.info("Applying process protection mechanisms")
            
            # Skip protection if not running with admin rights
            if not is_admin():
                self.logger.warning("Process protection requires admin rights, skipping")
                return False
            
            # Set up protection using Windows Task Scheduler
            protection_result = self._setup_scheduler_protection()
            if protection_result:
                self.logger.info("Task Scheduler protection applied successfully")
            else:
                self.logger.warning("Failed to apply Task Scheduler protection")
            
            self.is_protected = protection_result
            return self.is_protected
            
        except Exception as e:
            self.logger.error(f"Error applying protection: {str(e)}")
            self.logger.error(traceback.format_exc())
            return False
    
    def _setup_scheduler_protection(self):
        """Set up Windows Task Scheduler to monitor and restart the process if killed."""
        try:
            self.logger.info("Setting up Task Scheduler protection")
            
            # Get information about current process
            exe_path = os.path.abspath(sys.executable)
            app_path = os.path.join(os.getcwd(), "ProcessGuard.exe")
            working_dir = os.getcwd()
            
            # Use ProcessGuard.exe if it exists, otherwise use the Python executable
            if os.path.exists(app_path):
                exe_path = app_path
                self.logger.info("Using ProcessGuard.exe for restart")
            else:
                self.logger.info("Using Python executable for restart")
            
            self.logger.info(f"Process PID: {self.pid}")
            self.logger.info(f"Executable path: {exe_path}")
            self.logger.info(f"Working directory: {working_dir}")
            
            # Create restart batch file with maximum compatibility
            restart_bat_path = os.path.join(tempfile.gettempdir(), "processguard_restart.bat")
            with open(restart_bat_path, 'w') as f:
                f.write(f"@echo off\n")
                f.write(f"echo %DATE% %TIME% - ProcessGuard restart triggered >> {tempfile.gettempdir()}\\pg_restart.log\n")
                
                # Check if ProcessGuard is already running
                f.write(f"tasklist /FI \"IMAGENAME eq ProcessGuard.exe\" | find /i \"ProcessGuard.exe\" > nul\n")
                f.write(f"if errorlevel 1 (\n")
                
                # ProcessGuard is not running, start it
                f.write(f"  echo ProcessGuard is not running, starting it...\n")
                f.write(f"  cd /d \"{working_dir}\"\n")
                
                # If using ProcessGuard.exe
                if os.path.exists(app_path):
                    f.write(f"  start \"ProcessGuard\" /min \"{app_path}\" --monitor -s\n")
                else:
                    # If using Python executable
                    main_py = os.path.join(working_dir, "main.py")
                    f.write(f"  start \"ProcessGuard\" /min \"{exe_path}\" \"{main_py}\" --monitor -s\n")
                
                f.write(f") else (\n")
                f.write(f"  echo ProcessGuard is already running\n")
                f.write(f")\n")
                f.write(f"exit\n")
            
            # Make the batch file executable
            os.chmod(restart_bat_path, 0o755)  # Set to executable
            self.logger.info(f"Created restart batch file: {restart_bat_path}")
            
            # First, remove any existing task with the same name
            self._remove_existing_task()
            
            # Set up a scheduled task to run the batch file every x minutes
            self.logger.info(f"Creating scheduled task to run every {self.check_interval} minute(s)")
            
            # Using SchTasks.exe to create the task
            # IMPORTANT: /SC MINUTE - specifies a minute-based schedule
            # /MO 1 - run every 1 minute (or whatever self.check_interval is)
            # /F - force creation, overwriting any existing task with the same name
            # /RL HIGHEST - run with highest privileges
            task_command = f'schtasks /Create /TN {self.task_name} /TR "{restart_bat_path}" /SC MINUTE /MO {self.check_interval} /F /RL HIGHEST'
            
            self.logger.info(f"Creating task with command: {task_command}")
            
            # Execute the command to create the scheduled task
            result = subprocess.run(task_command, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info("Successfully created scheduled task for watchdog protection")
                
                # Trigger the task once immediately to verify it works
                trigger_command = f'schtasks /Run /TN {self.task_name}'
                subprocess.run(trigger_command, shell=True)
                self.logger.info("Triggered initial run of the watchdog task")
                
                return True
            else:
                self.logger.error(f"Failed to create scheduled task: {result.stderr}")
                return False
            
        except Exception as e:
            self.logger.error(f"Error setting up task scheduler protection: {str(e)}")
            self.logger.error(traceback.format_exc())
            return False
    
    def _remove_existing_task(self):
        """Remove existing task if it already exists."""
        try:
            # Check if task exists
            check_command = f'schtasks /Query /TN {self.task_name} 2>nul'
            result = subprocess.run(check_command, shell=True, capture_output=True)
            
            if result.returncode == 0:
                # Task exists, delete it
                self.logger.info(f"Removing existing scheduled task {self.task_name}")
                delete_command = f'schtasks /Delete /TN {self.task_name} /F'
                subprocess.run(delete_command, shell=True)
                return True
            return False
        except Exception as e:
            self.logger.warning(f"Error checking/removing existing task: {str(e)}")
            # Continue with creation anyway
            return False
            
    def uninstall_protection(self):
        """Remove protection mechanisms completely."""
        try:
            self.logger.info("Uninstalling process protection mechanisms...")
            
            # Remove the scheduled task
            task_removed = self._remove_existing_task()
            
            # Remove the restart batch file if it exists
            restart_bat_path = os.path.join(tempfile.gettempdir(), "processguard_restart.bat")
            if os.path.exists(restart_bat_path):
                try:
                    os.remove(restart_bat_path)
                    self.logger.info(f"Removed restart batch file: {restart_bat_path}")
                except Exception as e:
                    self.logger.warning(f"Failed to remove restart batch file: {str(e)}")
            
            if task_removed:
                self.logger.info("Protection mechanisms successfully uninstalled")
                return True
            else:
                self.logger.info("No active protection mechanisms found to uninstall")
                return True
                
        except Exception as e:
            self.logger.error(f"Error uninstalling protection: {str(e)}")
            self.logger.error(traceback.format_exc())
            return False


def install_protection(check_interval=1):
    """
    Install process protection mechanisms using Windows Task Scheduler.
    
    Args:
        check_interval: Interval in minutes between process existence checks
    
    Returns:
        bool: True if protection was successfully applied
    """
    protection = ProcessProtection(check_interval)
    return protection.protect_process()
    

def uninstall_protection():
    """
    Uninstall all process protection mechanisms.
    
    Returns:
        bool: True if protection was successfully removed
    """
    protection = ProcessProtection()
    return protection.uninstall_protection()
