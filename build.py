#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Build script for Process Doppelgänging Detector
-----------------------------------------------
Creates an executable using PyInstaller.
"""
import os
import sys
import subprocess
import shutil

def build_executable():
    """Build the executable using PyInstaller."""
    print("Building Process Doppelgänging Detector executable...")
    
    # Clean up old build artifacts
    print("Cleaning up old build artifacts...")
    for directory in ["build", "dist"]:
        if os.path.exists(directory):
            print(f"Removing {directory} directory...")
            try:
                shutil.rmtree(directory)
            except Exception as e:
                print(f"Error removing {directory}: {e}")
    
    # Remove old executable if it exists
    if os.path.exists("ProcessGuard.exe"):
        print("Removing old ProcessGuard.exe...")
        try:
            os.remove("ProcessGuard.exe")
        except Exception as e:
            print(f"Error removing ProcessGuard.exe: {e}")
    
    # Ensure PyInstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("PyInstaller not found. Installing...")
        subprocess.call([sys.executable, "-m", "pip", "install", "pyinstaller"])
    
    # Ensure other dependencies are installed
    print("Ensuring dependencies are installed...")
    dependencies = ["psutil", "wmi", "pywin32"]
    for dep in dependencies:
        try:
            __import__(dep)
        except ImportError:
            print(f"Installing {dep}...")
            subprocess.call([sys.executable, "-m", "pip", "install", dep])
    
    # PyInstaller command for executable with explicit modules inclusion
    pyinstaller_cmd = [
        "pyinstaller",
        "--clean",
        "--onefile",
        "--icon=ProcessGuard.ico",  # Add icon
        "--version-file=version_info.txt",  # Add version info
        "--hidden-import=modules.monitor", 
        "--hidden-import=modules.scanner",
        "--hidden-import=modules.utils",
        "--hidden-import=modules.logger",
        "--add-data=modules;modules",  # Include modules directory
        "--name=ProcessGuard",  # New application name
        "main.py"
    ]
    
    # Run PyInstaller
    print("Building executable...")
    subprocess.call(pyinstaller_cmd)
    
    # Copy executable to root directory
    try:
        shutil.copy("dist/ProcessGuard.exe", ".")
        print("Executable built successfully and copied to root directory.")
    except Exception as e:
        print(f"Error copying executable: {e}")
    
    print("Build complete!")

if __name__ == "__main__":
    build_executable()
