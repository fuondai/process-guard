#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Scanner module for Process Doppelgänging Detector
-------------------------------------------------
Scans running processes for indicators of Process Doppelgänging.
"""
import os
import psutil
import json
import ctypes
import time
from datetime import datetime
from ctypes import windll, byref, sizeof, c_buffer, Structure, POINTER, WinError
from ctypes.wintypes import DWORD, BOOL, HANDLE, LPVOID, WORD, BYTE

from .utils import (
    is_admin, 
    get_process_memory_info, 
    check_mapped_files, 
    get_process_handles, 
    calculate_suspicion_level,
    save_to_json,
    open_process,
    close_handle,
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ
)
from .logger import get_logger

class ProcessScanner:
    """Scanner for detecting Process Doppelgänging in running processes."""
    
    def __init__(self, admin_rights=False, results_file="results.json"):
        """Initialize the scanner."""
        self.logger = get_logger()
        self.admin_rights = admin_rights
        self.results_file = results_file
        self.results = {
            "scan_time": datetime.now(),
            "admin_rights": admin_rights,
            "suspicious_processes": []
        }
        
        # Create a list to track suspicious processes
        self.suspicious_processes = []
        
        # Initialize native API functions if admin rights are available
        if admin_rights:
            self._init_native_api()
    
    def _init_native_api(self):
        """Initialize Windows native API functions for deeper inspection."""
        try:
            # Get ntdll handle
            self.ntdll = windll.ntdll
            
            # Define necessary native API functions
            self.ntdll.NtQueryInformationProcess.restype = DWORD
            self.ntdll.NtQueryInformationProcess.argtypes = [
                HANDLE, DWORD, LPVOID, DWORD, POINTER(DWORD)
            ]
            
            self.logger.debug("Native API functions initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize native API functions: {e}")
            self.admin_rights = False
    
    def scan_all_processes(self):
        """Scan all running processes for indicators of Process Doppelgänging."""
        self.logger.info("Starting scan of all running processes")
        
        # Reset results for a new scan
        self.results = {
            "scan_time": datetime.now(),
            "admin_rights": self.admin_rights,
            "suspicious_processes": []
        }
        
        # Get all processes
        try:
            processes = list(psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time', 'ppid']))
            self.logger.info(f"Found {len(processes)} running processes to scan")
            
            for proc in processes:
                try:
                    process_info = {
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "cmd": proc.info.get('cmdline', []),
                        "username": proc.info.get('username', ''),
                        "create_time": proc.info.get('create_time', 0),
                        "parent_pid": proc.info.get('ppid', 0)
                    }
                    
                    # Skip system processes with low PIDs if not admin
                    if process_info["pid"] < 10 and not self.admin_rights:
                        continue
                    
                    # Check for Process Doppelgänging indicators
                    indicators = self.check_process_for_doppelganging(process_info["pid"])
                    
                    # Calculate suspicion score
                    suspicion_score = calculate_suspicion_score(indicators)
                    
                    # Add to results if suspicious
                    if suspicion_score > 0:
                        process_info["indicators"] = indicators
                        process_info["suspicion_score"] = suspicion_score
                        self.results["suspicious_processes"].append(process_info)
                        
                        self.logger.warning(
                            f"Suspicious process detected: PID={process_info['pid']}, "
                            f"Name={process_info['name']}, Score={suspicion_score}"
                        )
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    self.logger.error(f"Error scanning process {proc.info['pid']}: {e}")
            
            # Save results to JSON
            if save_to_json(self.results, self.results_file):
                self.logger.info(f"Scan results saved to {self.results_file}")
            else:
                self.logger.error(f"Failed to save scan results to {self.results_file}")
            
            return self.results["suspicious_processes"]
            
        except Exception as e:
            self.logger.error(f"Error during process scan: {e}")
            return []
    
    def check_process_for_doppelganging(self, pid):
        """Check a specific process for Process Doppelgänging indicators."""
        indicators = {
            "has_suspicious_memory": False,
            "has_deleted_file_mapping": False,
            "has_transaction_handles": False,
            "has_section_without_file": False,
            "created_with_section": False,
            "suspicious_parent": False,
            "unnamed_process": False,
            "details": {}
        }
        
        try:
            # Get process info first to check if it's a known safe process
            try:
                process = psutil.Process(pid)
                process_name = process.name().lower()
                
                # Check for unnamed processes - strong indicator of Process Doppelgänging
                if not process_name or process_name == "" or process_name.strip() == "":
                    indicators["unnamed_process"] = True
                    indicators["details"]["unnamed_process"] = "Process has no name - strong indicator of Process Doppelgänging"
                    self.logger.threat("HIGH", f"UNNAMED PROCESS DETECTED - PID: {pid} - HIGH confidence Process Doppelgänging indicator")
                    # Return early with this strong indicator
                    return indicators
                
                # Check for unusual or suspicious process names often used for malware
                suspicious_names = [
                    "svchost",  # if not legitimate svchost (we'll check path later)
                    "csrss",   # if not legitimate csrss
                    "lsass",   # if not legitimate lsass
                    "rundll",  # shortened rundll32
                    "scvhost", # typosquatting of svchost
                    "svch0st", # character replacement
                    "explore", # shortened explorer
                    "iexplore", # IE commonly used
                    "services", # if not the real services
                    "dllhost", # if not legitimate dllhost
                ]
                
                # Check for process name spoofing
                if any(sus_name == process_name or sus_name in process_name for sus_name in suspicious_names):
                    # Verify if it's a legitimate system process by checking its path
                    try:
                        process_path = process.exe().lower()
                        expected_system_path = "c:\\windows\\system32\\"
                        expected_syswow64_path = "c:\\windows\\syswow64\\"
                        
                        # If using a system name but not in system directories, mark as suspicious
                        if not (expected_system_path in process_path or expected_syswow64_path in process_path):
                            indicators["name_spoofing"] = True
                            indicators["details"]["name_spoofing"] = f"Process using system name '{process_name}' but not in system directory: {process_path}"
                    except:
                        pass
                
                # Whitelist of common Windows processes that often have legitimate deleted file mappings
                # or similar behavior that might trigger false positives
                whitelist = [
                    "msedgewebview2.exe",  # Edge WebView frequently uses temp sections
                    "svchost.exe",         # Windows service host frequently has unusual mappings
                    "explorer.exe",        # Windows explorer
                    "runtimebroker.exe",   # Windows runtime broker
                    "searchhost.exe",      # Windows search
                    "startmenuexperiencehost.exe",  # Start menu
                    "shellexperiencehost.exe",      # Shell experience
                    "applicationframehost.exe",     # Application frame
                    "microsoftedge.exe",   # Edge browser
                    "chrome.exe",          # Chrome browser
                    "firefox.exe",         # Firefox browser
                    "wmiprvse.exe",        # WMI Provider Service
                    "wininit.exe",         # Windows initialization
                    "lsass.exe",           # Windows security
                    "fontdrvhost.exe",     # Font driver host
                    "dwm.exe",             # Desktop Window Manager
                    "csrss.exe"            # Client/Server Runtime Subsystem
                ]
                
                # If it's a common Windows process, do more careful analysis before flagging
                is_whitelisted = process_name in whitelist
                
                # For whitelisted processes, we'll require more indicators to flag as suspicious
                # We'll still collect data but apply stricter scoring later
            except Exception as e:
                self.logger.debug(f"Error getting process name for PID {pid}: {e}")
                is_whitelisted = False
                process_name = "unknown"
                
                # If we can't even get the process name but the process exists,
                # that's highly suspicious - possible indicator of Process Doppelgänging
                indicators["unnamed_process"] = True
                indicators["details"]["unnamed_process"] = "Cannot retrieve process name - possible Process Doppelgänging"
            
            # Open a handle to the process
            process_handle = open_process(pid)
            if not process_handle:
                # Cannot open process - could be protected or already terminated
                if indicators["unnamed_process"]:
                    # Unnamed AND can't open - very suspicious
                    return indicators
                return indicators
            
            # Check for suspicious memory regions with error handling
            try:
                memory_regions = get_process_memory_info(pid, self.admin_rights)
                suspicious_regions = [r for r in memory_regions if r.get("Suspicious", False)]
                
                if suspicious_regions:
                    indicators["has_suspicious_memory"] = True
                    indicators["details"]["suspicious_memory"] = suspicious_regions
            except Exception as e:
                self.logger.debug(f"Error getting memory info for PID {pid}: {e}")
            
            # Check for mapped files from non-existent or deleted files with error handling
            try:
                suspicious_mappings = check_mapped_files(pid, self.admin_rights)
                
                # Filter out common benign deleted mappings (for Edge WebView2 and other browsers)
                if is_whitelisted and suspicious_mappings:
                    # Keep only truly suspicious mappings for whitelisted processes
                    filtered_mappings = []
                    for mapping in suspicious_mappings:
                        path = mapping.get("path", "").lower()
                        
                        # Skip common benign patterns
                        if ("$extend\$deleted" in path and process_name == "msedgewebview2.exe") or \
                           (".db-shm" in path and process_name == "svchost.exe") or \
                           ("pagefile.sys" in path and process_name in ["chrome.exe", "msedge.exe", "firefox.exe"]):
                            continue
                        
                        filtered_mappings.append(mapping)
                    
                    suspicious_mappings = filtered_mappings
                
                if suspicious_mappings:
                    indicators["has_deleted_file_mapping"] = True
                    indicators["details"]["suspicious_mappings"] = suspicious_mappings
            except Exception as e:
                self.logger.debug(f"Error checking mapped files for PID {pid}: {e}")
            
            # Check for transaction handles (TmTx) or suspicious section handles with error handling
            if self.admin_rights:
                try:
                    handles = get_process_handles(pid, self.admin_rights)
                    
                    # Process handle results safely
                    transaction_handles = []
                    section_handles = []
                    
                    # Make sure handles is a valid iterable
                    if handles and isinstance(handles, list):
                        transaction_handles = [h for h in handles if isinstance(h, str) and "TmTx" in h]
                        section_handles = [h for h in handles if isinstance(h, str) and "Section" in h]
                    
                    if transaction_handles:
                        indicators["has_transaction_handles"] = True
                        indicators["details"]["transaction_handles"] = transaction_handles
                    
                    # Analyze section handles for potential indicators
                    for handle in section_handles:
                        # If we find Section objects without backing files, that's suspicious
                        if "File" not in handle and "Mutant" not in handle:
                            indicators["has_section_without_file"] = True
                            indicators["details"].setdefault("section_without_file", []).append(handle)
                except Exception as e:
                    self.logger.debug(f"Error checking handles for PID {pid}: {e}")
            
            # Check if process was created using NtCreateProcessEx with a section
            # This is a strong indicator when combined with other factors
            try:
                # Get parent PID safely
                parent_pid = 0
                try:
                    if hasattr(process, 'ppid') and callable(process.ppid):
                        parent_pid = process.ppid()
                except (psutil.AccessDenied, psutil.ZombieProcess, AttributeError) as e:
                    self.logger.debug(f"Cannot access parent PID for process {pid}: {e}")
                
                if parent_pid > 0:
                    try:
                        # Check if parent is suspicious
                        parent_indicators = self.check_parent_process(parent_pid)
                        
                        if parent_indicators and parent_indicators.get("suspicious", False):
                            # For whitelisted processes, only consider parent suspicious if strong indicators
                            if not is_whitelisted or parent_indicators.get("high_confidence", False):
                                indicators["suspicious_parent"] = True
                                indicators["details"]["parent_info"] = parent_indicators
                    except Exception as e:
                        self.logger.debug(f"Error checking parent process for PID {pid}: {e}")
            except Exception as e:
                self.logger.debug(f"Error during parent process analysis for PID {pid}: {e}")
            
            # Store whether this is a whitelisted process for score calculation
            indicators["is_whitelisted"] = is_whitelisted
            indicators["process_name"] = process_name
            
            # Close the handle
            close_handle(process_handle)
            
        except Exception as e:
            self.logger.error(f"Error checking process {pid} for doppelgänging: {e}")
        
        return indicators
    
    def check_parent_process(self, pid):
        """Check if parent process is suspicious (e.g., cmd.exe, powershell.exe)
        Returns information including a high_confidence flag for more reliable detection
        """
        result = {
            "pid": pid,
            "suspicious": False,
            "high_confidence": False,  # New flag for high confidence detections
            "reason": []
        }
        
        # Basic error checking for invalid PIDs
        if not pid or pid <= 0:
            return result
            
        try:
            # Get process with proper error handling
            try:
                process = psutil.Process(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                self.logger.debug(f"Cannot access parent process {pid}: {e}")
                return result
                
            # Get process name with error handling
            try:
                process_name = process.name().lower()
                result["name"] = process_name
            except (psutil.AccessDenied, psutil.ZombieProcess) as e:
                self.logger.debug(f"Cannot get name for parent process {pid}: {e}")
                result["name"] = "<unknown>"
            
            # List of potentially abused processes for launching malware
            suspicious_parents = [
                "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                "rundll32.exe", "regsvr32.exe", "mshta.exe", "schtasks.exe",
                "wmic.exe", "msiexec.exe", "odbcconf.exe", "regasm.exe",
                "regsvcs.exe", "installutil.exe", "cmstp.exe", "certutil.exe"
            ]
            
            # Legitimate parent processes that are often system services
            legitimate_service_parents = [
                "services.exe", "svchost.exe", "smss.exe", "wininit.exe", 
                "csrss.exe", "winlogon.exe", "explorer.exe", "lsass.exe",
                "taskhost.exe", "taskhostw.exe", "sihost.exe", "runtimebroker.exe",
                "userinit.exe", "dwm.exe", "fontdrvhost.exe", "searchindexer.exe"
            ]
            
            # Only flag parent as suspicious if it's in our list AND not a system process
            # with normal children
            if process_name in suspicious_parents:
                # Check if this is a legitimate instance (e.g., system spawned cmd)
                try:
                    parent_parent = psutil.Process(process.ppid())
                    if parent_parent.name().lower() in legitimate_service_parents:
                        # It's less suspicious if this cmd/powershell was launched by a system service
                        # but still worth noting
                        result["suspicious"] = True
                        result["reason"].append(f"Created by potentially abused utility: {process_name} (but launched by system process)")
                    else:
                        # More suspicious if not launched by system
                        result["suspicious"] = True
                        result["high_confidence"] = True
                        result["reason"].append(f"Created by potentially abused utility: {process_name}")
                except:
                    # Can't determine parent's parent, but still suspicious
                    result["suspicious"] = True
                    result["reason"].append(f"Created by potentially abused utility: {process_name}")
                
            # Check command line for suspicious args (e.g., -enc, -w hidden, etc.)
            try:
                cmdline = process.cmdline()
                cmdline_str = " ".join(cmdline).lower()
                
                # High confidence indicators in command line
                high_confidence_args = [
                    "-enc ", "-encodedcommand", "-w hidden", "-windowstyle hidden",
                    "-exec bypass", "-executionpolicy bypass",
                    "iex(", "invoke-expression", "downloadstring", "downloadfile",
                    "bitsadmin /transfer", "certutil -urlcache", "regsvr32 /s /u /i:"
                ]
                
                # Medium confidence indicators
                medium_confidence_args = [
                    "-noprofile", "-noexit", "-noninteractive", "-command", 
                    "-c ", "curl ", "wget ", "net use ", "-sta"
                ]
                
                for arg in high_confidence_args:
                    if arg in cmdline_str:
                        result["suspicious"] = True
                        result["high_confidence"] = True
                        result["reason"].append(f"Highly suspicious command line argument: {arg}")
                
                for arg in medium_confidence_args:
                    if arg in cmdline_str and not result["high_confidence"]:
                        result["suspicious"] = True
                        result["reason"].append(f"Suspicious command line argument: {arg}")
            except:
                pass
                
        except Exception as e:
            self.logger.error(f"Error checking parent process {pid}: {e}")
            
        return result
    
    def scan_specific_process(self, pid):
        """Scan a specific process for Process Doppelgänging indicators."""
        try:
            self.logger.info(f"Scanning process with PID {pid}")
            
            # Check if the process still exists and is accessible
            try:
                process = psutil.Process(pid)
                
                # Get basic process information with error handling for each attribute
                process_info = {"pid": pid}
                
                try:
                    process_info["name"] = process.name()
                except (psutil.AccessDenied, psutil.ZombieProcess) as e:
                    process_info["name"] = "<access-denied>"
                    self.logger.debug(f"Cannot access name for process {pid}: {e}")
                
                try:
                    process_info["cmd"] = process.cmdline()
                except (psutil.AccessDenied, psutil.ZombieProcess) as e:
                    process_info["cmd"] = []
                    self.logger.debug(f"Cannot access cmdline for process {pid}: {e}")
                
                try:
                    process_info["username"] = process.username()
                except (psutil.AccessDenied, psutil.ZombieProcess) as e:
                    process_info["username"] = "<unknown>"
                    self.logger.debug(f"Cannot access username for process {pid}: {e}")
                
                try:
                    process_info["create_time"] = process.create_time()
                except (psutil.AccessDenied, psutil.ZombieProcess) as e:
                    process_info["create_time"] = 0
                    self.logger.debug(f"Cannot access creation time for process {pid}: {e}")
                
                try:
                    process_info["parent_pid"] = process.ppid()
                except (psutil.AccessDenied, psutil.ZombieProcess) as e:
                    process_info["parent_pid"] = 0
                    self.logger.debug(f"Cannot access parent PID for process {pid}: {e}")
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                self.logger.warning(f"Cannot access process {pid}: {e}")
                return None
            
            # Check for indicators with proper error handling
            try:
                indicators = self.check_process_for_doppelganging(pid)
                
                # Calculate suspicion level
                threat_level, suspicion_score, reason = calculate_suspicion_level(indicators)
                
                # Add to process info
                process_info["indicators"] = indicators
                process_info["suspicion_score"] = suspicion_score
                process_info["threat_level"] = threat_level
                process_info["reason"] = reason
                
                # Log results based on threat level
                if threat_level != "LOW":
                    # Use custom threat level logging
                    self.logger.threat(
                        threat_level, 
                        f"PID: {pid} - {process_info['name']} - {reason}"
                    )
                    # Add to both tracking structures
                    self.suspicious_processes.append(process_info)
                    self.results["suspicious_processes"].append(process_info)
                
                return process_info
            except Exception as e:
                self.logger.error(f"Error analyzing process {pid}: {e}")
                return None
            
        except Exception as e:
            self.logger.error(f"Unexpected error scanning process {pid}: {e}")
            return None
            
    def scan_all_processes(self):
        """Scan all running processes for Process Doppelgänging indicators."""
        try:
            self.logger.info("Scanning all running processes")
            
            # Iterate over all running processes
            for proc in psutil.process_iter(['pid', 'name']):
                pid = proc.info['pid']
                self.scan_specific_process(pid)
                
        except Exception as e:
            self.logger.error(f"Error scanning all processes: {e}")
