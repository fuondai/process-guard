#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Monitor module for Process Doppelgänging Detector
-------------------------------------------------
Monitors for new process creation in real-time and scans them for Process Doppelgänging.
"""
import os
import time
import threading
import ctypes
import wmi
import pythoncom  # Import pythoncom for COM initialization
from ctypes import windll
from datetime import datetime

from .logger import get_logger
from .utils import save_to_json

class ProcessMonitor:
    """Monitors for new process creation and detects Process Doppelgänging in real-time."""
    
    def __init__(self, scanner, results_file="results.json", min_threat_level="LOW", auto_kill=False):
        """Initialize the process monitor.
        
        Args:
            scanner: ProcessScanner instance to use for scanning
            results_file: Path to save results to
            min_threat_level: Minimum threat level to log (LOW, MEDIUM, HIGH)
            auto_kill: Whether to automatically kill processes with HIGH threat level
        """
        self.logger = get_logger()
        self.scanner = scanner
        self.results_file = results_file
        self.min_threat_level = min_threat_level
        self.auto_kill = auto_kill
        self.running = False
        self.monitor_thread = None
        self.wmi_interface = None
        self.process_watcher = None
        
    def _monitor_processes(self):
        """Background thread to monitor for new process creation."""
        self.logger.info("Process monitoring thread started")
        
        try:
            # Initialize COM for this thread
            pythoncom.CoInitialize()
            
            # Initialize WMI interface
            self.wmi_interface = wmi.WMI()
            
            # Create a process creation event watcher
            process_watcher = self.wmi_interface.Win32_Process.watch_for(
                "creation"
            )
            
            self.logger.info("Watching for new process creation...")
            
            # Monitor loop
            while self.running:
                try:
                    # Wait for a new process to be created (timeout after 1 second to check if still running)
                    new_process = process_watcher(timeout_ms=1000)
                    
                    if new_process:
                        pid = new_process.ProcessId
                        process_name = new_process.Name
                        
                        self.logger.info(f"New process detected: PID={pid}, Name={process_name}")
                        
                        # Allow the process to initialize fully before scanning
                        time.sleep(0.5)
                        
                        # Scan the new process for Process Doppelgänging indicators
                        result = self.scanner.scan_specific_process(pid)
                        
                        # Check if process has a high enough threat level based on filter
                        threat_level = result.get("threat_level", "LOW") if result else "LOW"
                        
                        # Convert threat levels to numeric values for comparison
                        threat_values = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
                        if result and threat_values.get(threat_level, 0) >= threat_values.get(self.min_threat_level, 0):
                            # Process meets minimum threat level threshold for logging
                            self.logger.warning(f"Suspicious process detected: PID={pid}, Name={process_name}, Threat={threat_level}")
                            
                            # Auto-kill if enabled and threat level is HIGH
                            if self.auto_kill and threat_level == "HIGH":
                                # Prevent killing our own process
                                import os
                                current_pid = os.getpid()
                                
                                if pid == current_pid:
                                    self.logger.warning(f"Skipping auto-kill for our own process (PID={pid})")
                                    result["auto_terminated"] = False
                                    result["skipped_self_termination"] = True
                                else:
                                    from modules.utils import kill_process
                                    kill_success = kill_process(pid)
                                    if kill_success:
                                        self.logger.warning(f"Automatically terminated HIGH threat process: PID={pid}, Name={process_name}")
                                        # Add termination info to the result
                                        result["auto_terminated"] = True
                                    else:
                                        self.logger.error(f"Failed to terminate HIGH threat process: PID={pid}, Name={process_name}")
                                        result["auto_terminated"] = False
                except wmi.x_wmi_timed_out:
                    # This is normal - just a timeout to check if we should still be running
                    pass
                except Exception as e:
                    self.logger.error(f"Error during process monitoring: {e}")
                    time.sleep(1)  # Prevent rapid error loops
        
        except Exception as e:
            self.logger.error(f"Process monitoring thread error: {e}")
        finally:
            # Clean up COM resources when thread exits
            try:
                pythoncom.CoUninitialize()
            except:
                pass
        
        self.logger.info("Process monitoring thread stopped")
    
    def start_monitoring(self):
        """Start monitoring for new processes."""
        if self.running:
            self.logger.warning("Process monitor is already running")
            return False
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_processes)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.logger.info("Process monitor started successfully")
        return True
    
    def stop_monitoring(self):
        """Stop monitoring for new processes."""
        if not self.running:
            self.logger.warning("Process monitor is not running")
            return False
        
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            self.monitor_thread = None
        
        self.logger.info("Process monitor stopped")
        return True
