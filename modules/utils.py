#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Utils module for Process Doppelgänging Detector
-----------------------------------------------
Contains utility functions for the detector.
"""
import os
import ctypes
import sys
import json
import psutil
import struct
import winreg
import subprocess
import random
from ctypes import wintypes, windll, byref, c_void_p, c_buffer, sizeof, POINTER, WinError
from datetime import datetime

# Windows-specific constants and structures
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_ALL_ACCESS = 0x1F0FFF

# Memory Protection Constants
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04

# Section flags
SEC_IMAGE = 0x1000000

# NT API status codes
STATUS_SUCCESS = 0

# Native API functions for deeper inspection when admin rights available
ntdll = windll.ntdll

# Process information structures
class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    """Structure for process basic information"""
    _fields_ = [
        ("ExitStatus", wintypes.LONG),
        ("PebBaseAddress", c_void_p),
        ("AffinityMask", wintypes.LPVOID),
        ("BasePriority", wintypes.LONG),
        ("UniqueProcessId", wintypes.LPVOID),
        ("InheritedFromUniqueProcessId", wintypes.LPVOID)
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """Structure for memory information"""
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

def is_admin():
    """Check if the process has administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def create_stealth_console():
    """Hide console window for stealth operation"""
    hwnd = ctypes.windll.kernel32.GetConsoleWindow()
    if hwnd != 0:
        ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE = 0

def open_process(pid, desired_access=PROCESS_QUERY_INFORMATION | PROCESS_VM_READ):
    """Open a handle to a process"""
    try:
        return ctypes.windll.kernel32.OpenProcess(desired_access, False, pid)
    except:
        return None

def close_handle(handle):
    """Close a handle"""
    if handle:
        ctypes.windll.kernel32.CloseHandle(handle)

def get_process_memory_info(pid, admin=False):
    """Get detailed memory information for a process"""
    memory_regions = []
    
    # Skip if we don't have admin rights for detailed analysis
    if not admin:
        return memory_regions
    
    try:
        # Open the process with required access
        process_handle = open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
        if not process_handle:
            return memory_regions
            
        # Prepare for memory enumeration
        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        
        # Enumerate memory regions
        while True:
            result = ctypes.windll.kernel32.VirtualQueryEx(
                process_handle, 
                address, 
                byref(mbi), 
                sizeof(mbi)
            )
            
            if result == 0:
                break
                
            # Analyze the memory region
            if mbi.Type & 0x1000000:  # MEM_IMAGE
                region_info = {
                    "BaseAddress": hex(mbi.BaseAddress),
                    "AllocationBase": hex(mbi.AllocationBase),
                    "RegionSize": mbi.RegionSize,
                    "Protection": mbi.Protect,
                    "Type": "Image",
                    "Suspicious": False
                }
                
                # Check for suspicious protection flags or section types
                if mbi.Protect == PAGE_EXECUTE_READWRITE:
                    region_info["Suspicious"] = True
                    region_info["Reason"] = "Executable and writable memory (PAGE_EXECUTE_READWRITE)"
                
                memory_regions.append(region_info)
            
            # Move to next region
            address = mbi.BaseAddress + mbi.RegionSize
        
        # Clean up
        close_handle(process_handle)
        
    except Exception as e:
        pass
        
    return memory_regions

def check_mapped_files(pid, admin=False):
    """Check for mapped files that might be suspicious"""
    suspicious_mappings = []
    
    try:
        process = psutil.Process(pid)
        
        # Get memory maps if available
        try:
            maps = process.memory_maps()
            for m in maps:
                mapping = {
                    "path": m.path,
                    "rss": m.rss,
                    "suspicious": False
                }
                
                # Check for deleted files (often indicator of doppelgänging)
                if "(deleted)" in m.path or "pagefile.sys" in m.path.lower():
                    mapping["suspicious"] = True
                    mapping["reason"] = "Mapped from deleted file or pagefile"
                    suspicious_mappings.append(mapping)
                
                # Check for non-existing paths that are still mapped
                if m.path and m.path != "[anon]" and not os.path.exists(m.path):
                    mapping["suspicious"] = True
                    mapping["reason"] = "Mapped file does not exist on disk"
                    suspicious_mappings.append(mapping)
        except:
            # Memory maps might not be available without admin rights
            pass
    except:
        pass
        
    return suspicious_mappings

def get_process_handles(pid, admin=False):
    """Get open handles of a process that might indicate transactional NTFS usage
    Uses native Windows API instead of relying on handle.exe
    """
    handles = []
    
    # Skip if we don't have admin rights
    if not admin:
        return handles
    
    try:
        # Get the process handle with necessary access
        process_handle = open_process(pid, PROCESS_QUERY_INFORMATION)
        if not process_handle:
            return handles
        
        # Since this is a simplified version without direct handle enumeration,
        # we'll use other indicators to infer transaction usage
        
        # Check if the process has unusual section objects (inferred)
        memory_regions = get_process_memory_info(pid, admin)
        for region in memory_regions:
            if region.get("Type", "") == "Image" and region.get("Suspicious", False):
                handles.append(f"Section object at {region.get('BaseAddress', 'unknown')} - {region.get('Reason', 'unknown')}")
        
        # Close the handle
        close_handle(process_handle)
        
    except Exception as e:
        pass
        
    return handles

def save_to_json(data, filepath):
    """Save detection results to JSON file"""
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4, default=str)
        return True
    except Exception as e:
        return False

def calculate_suspicion_level(indicators):
    """Calculate a suspicion level (LOW, MEDIUM, HIGH) based on the indicators found
    Takes into account whether the process is whitelisted and applies different thresholds
    """
    score = 0
    is_whitelisted = indicators.get("is_whitelisted", False)
    process_name = indicators.get("process_name", "unknown")
    
    # Immediate HIGH for unnamed processes - strong indicator of Process Doppelgänging
    if indicators.get("unnamed_process", False):
        return "HIGH", 100, "Unnamed process - Strong Process Doppelgänging indicator"
    
    # Assign weights to different indicators
    reasons = []
    
    if indicators.get("has_suspicious_memory", False):
        if is_whitelisted:
            score += 5
        else:
            score += 10
            reasons.append("Suspicious memory regions")
    
    if indicators.get("has_deleted_file_mapping", False):
        # Check number of suspicious mappings
        mappings = indicators.get("details", {}).get("suspicious_mappings", [])
        if len(mappings) > 0:
            # Edge WebView and some browsers commonly have deleted mappings, so reduce score
            if is_whitelisted and process_name in ["msedgewebview2.exe", "chrome.exe", "firefox.exe", "msedge.exe"]:
                score += 20
            else:
                score += 40
                reasons.append("Deleted file mappings detected")
    
    if indicators.get("has_transaction_handles", False):
        # Transaction handles are very strong indicators
        score += 30
        reasons.append("Transaction handles detected - strong Process Doppelgänging indicator")
    
    if indicators.get("has_section_without_file", False):
        if is_whitelisted:
            score += 20
        else:
            score += 30
            reasons.append("Section handles without backing files detected")
    
    if indicators.get("created_with_section", False):
        score += 20
        reasons.append("Process created with section object")
    
    if indicators.get("suspicious_parent", False):
        parent_info = indicators.get("details", {}).get("parent_info", {})
        if parent_info.get("high_confidence", False):
            score += 15
            reasons.append(f"Highly suspicious parent process: {parent_info.get('name', 'unknown')}")
        else:
            score += 10
            reasons.append(f"Suspicious parent process: {parent_info.get('name', 'unknown')}")
    
    # Multiple indicators together make a stronger case
    indicator_count = sum(1 for ind in ["has_suspicious_memory", "has_deleted_file_mapping", 
                                      "has_transaction_handles", "has_section_without_file", 
                                      "created_with_section", "suspicious_parent"] 
                          if indicators.get(ind, False))
    
    if indicator_count >= 3:
        score += 20
        reasons.append("Multiple suspicious indicators detected")
    
    # For whitelisted processes, require a higher threshold of suspicion
    if is_whitelisted and score < 50:
        # Apply reduction factor to whitelisted processes with low scores
        score = int(score * 0.5)
    
    # Cap score at 100
    score = min(score, 100)
    
    # Convert score to threat level
    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"
    
    # Create a combined reason string
    reason = "; ".join(reasons) if reasons else "Low confidence indicators detected"
    
    return level, score, reason


def register_startup(executable_path):
    """
    Register the application to run at Windows startup.
    Uses registry method (HKCU\Software\Microsoft\Windows\CurrentVersion\Run).
    
    Args:
        executable_path: Full path to the executable that should run at startup
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Open the run registry key
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)
        
        # Set the value - use the executable name as the value name
        exe_name = os.path.basename(executable_path)
        reg_value = f'"{executable_path}" --monitor --stealth -s --min-threat-level MEDIUM'
        
        winreg.SetValueEx(key, "ProcessGuard", 0, winreg.REG_SZ, reg_value)
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"Error registering for startup: {e}")
        return False


def unregister_startup():
    """
    Remove the application from Windows startup.
    
    Returns:
        bool: True if unregistration was successful, False otherwise
    """
    try:
        # Open the registry key
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                           r"Software\Microsoft\Windows\CurrentVersion\Run", 
                           0, winreg.KEY_WRITE)
        
        # Delete the value
        winreg.DeleteValue(key, "ProcessGuard")
        winreg.CloseKey(key)
        return True
    except Exception as e:
        # Key might not exist
        return False


def is_registered_startup():
    """
    Check if application is registered to run at startup.
    
    Returns:
        bool: True if registered, False otherwise
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                           r"Software\Microsoft\Windows\CurrentVersion\Run", 
                           0, winreg.KEY_READ)
        try:
            value, _ = winreg.QueryValueEx(key, "ProcessGuard")
            winreg.CloseKey(key)
            return True
        except:
            winreg.CloseKey(key)
            return False
    except:
        return False


def kill_process(pid):
    """
    Kill a process by its PID.
    
    Args:
        pid: Process ID to kill
        
    Returns:
        bool: True if process was killed successfully, False otherwise
    """
    try:
        process = psutil.Process(pid)
        process.kill()
        return True
    except psutil.NoSuchProcess:
        return False
    except psutil.AccessDenied:
        # Try with higher privileges if available
        try:
            # Windows specific method to forcefully terminate
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], 
                        capture_output=True, check=False)
            return True
        except Exception:
            return False
    except Exception:
        return False


def display_banner(with_version=True):
    """
    Display the ProcessGuard ASCII art banner
    
    Args:
        with_version: Whether to show version information
    """
    # List of colors for ANSI color output
    colors = [
        '\033[31m', # Red
        '\033[32m', # Green
        '\033[34m', # Blue
        '\033[35m', # Magenta
        '\033[36m'  # Cyan
    ]
    
    # Randomly select a color
    color = random.choice(colors)
    reset = '\033[0m'
    
    banner = f"""{color}
    ██████╗ ██████╗  ██████╗  ██████╗███████╗███████╗███████╗
    ██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔════╝██╔════╝
    ██████╔╝██████╔╝██║   ██║██║     █████╗  ███████╗███████╗
    ██╔═══╝ ██╔══██╗██║   ██║██║     ██╔══╝  ╚════██║╚════██║
    ██║     ██║  ██║╚██████╔╝╚██████╗███████╗███████║███████║
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝╚══════╝╚══════╝
                                                             
     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗               
    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗              
    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║              
    ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║              
    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝              
     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝               
{reset}"""
    
    if with_version:
        version_info = f"{color}[---] ProcessGuard v1.0.0 - Doppelgänger Process Detection Tool [---]{reset}"
        banner += "\n" + version_info
        banner += f"\n{color}[---] Bảo vệ Windows khỏi kỹ thuật Process Doppelgänging [---]{reset}"
    
    print(banner)
    
    # Add a small delay for effect
    from time import sleep
    sleep(0.2)
