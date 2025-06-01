#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Process Doppelgänging Detector
------------------------------
Detects processes that may have been created using Process Doppelgänging technique.
"""
import sys
import time
import argparse
import logging
import ctypes
import os
from datetime import datetime
from ctypes import wintypes

from modules.scanner import ProcessScanner
from modules.monitor import ProcessMonitor
from modules.logger import setup_logger, get_logger
from modules.utils import (is_admin, create_stealth_console, save_to_json,
                          register_startup, unregister_startup, is_registered_startup, kill_process,
                          display_banner)
from modules.protection import install_protection, uninstall_protection

def main():
    """Main entry point for ProcessGuard."""
    # Check for admin privileges but don't enforce them
    admin_status = is_admin()
    
    parser = argparse.ArgumentParser(description='ProcessGuard - Advanced Process Security Monitor')
    parser.add_argument('--scan', action='store_true', help='Scan all running processes')
    parser.add_argument('--monitor', action='store_true', help='Monitor for new processes')
    parser.add_argument('-s', '--service', action='store_true', help='Run as a Windows service/startup application')
    parser.add_argument('-k', '--kill', action='store_true', help='Automatically kill processes with HIGH threat level')
    parser.add_argument('-Q', '--quit', action='store_true', help='Completely terminate ProcessGuard and bypass protection mechanisms')
    parser.add_argument('--min-threat-level', type=str, choices=['LOW', 'MEDIUM', 'HIGH'], default='LOW',
                        help='Minimum threat level to log (LOW, MEDIUM, HIGH)')
    parser.add_argument('--stealth', action='store_true', help='Run in stealth mode (no console)')
    parser.add_argument('--log', type=str, default='detector.log', help='Log file path')
    parser.add_argument('--json', type=str, default='results.json', help='JSON results file path')
    parser.add_argument('--admin', action='store_true', help='Force require admin privileges')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--no-watchdog', action='store_true', help='Internal use - do not start watchdog (used during restart)')
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logger(args.log, log_level)
    logger = get_logger()
    
    # Log admin status with clear indication for user visibility in terminal
    admin_message = "RUNNING WITH ADMIN RIGHTS" if admin_status else "RUNNING WITHOUT ADMIN RIGHTS (LIMITED FUNCTIONALITY)"
    logger.info(f"====== {admin_message} ======")
    logger.info(f"Administrator status: {admin_status}")
    
    # Handle the quit command to completely terminate ProcessGuard first
    # Process -Q flag before anything else to avoid unnecessary operations
    if args.quit:
        logger.info("Force terminating ProcessGuard including protection mechanisms...")
        
        # First, uninstall Task Scheduler protection
        logger.info("Removing Task Scheduler protection...")
        uninstall_result = uninstall_protection()
        if uninstall_result:
            logger.info("Successfully removed Task Scheduler protection")
        else:
            logger.warning("Failed to remove Task Scheduler protection completely")
        
        # Find and kill the watchdog process if it exists (legacy code for compatibility)
        try:
            import psutil
            current_pid = os.getpid()
            # Check if environment variable is set by watchdog
            if os.environ.get("PROCESSGUARD_WATCHDOG") == "1":
                # We were launched by the watchdog, find and kill it
                parent = psutil.Process(current_pid).parent()
                if parent and "watchdog.py" in " ".join(parent.cmdline()):
                    logger.info(f"Terminating watchdog process (PID: {parent.pid})")
                    parent.kill()
            else:
                # Check for any watchdog.py processes monitoring us
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        cmdline = " ".join(proc.info['cmdline'] if proc.info['cmdline'] else [])
                        if "watchdog.py" in cmdline and str(current_pid) in cmdline:
                            logger.info(f"Terminating watchdog process (PID: {proc.info['pid']})")
                            psutil.Process(proc.info['pid']).kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
        except Exception as e:
            logger.error(f"Error while terminating protection mechanisms: {e}")
        
        logger.info("ProcessGuard has been completely terminated")
        return 0
    
    # Install self-protection mechanisms
    # Only apply protection for monitoring or service modes, unless --no-watchdog is specified
    if (args.monitor or args.service) and not args.no_watchdog:
        logger.info("Installing process protection mechanisms...")
        protection_status = install_protection()
        if protection_status:
            logger.info("Process protection mechanisms installed successfully")
        else:
            logger.warning("Failed to install some protection mechanisms")
    elif args.no_watchdog:
        logger.info("Watchdog disabled - running without protection mechanisms")
    
    if args.admin and not admin_status:
        logger.error("Administrator privileges required but not available")
        print("This tool requires administrator privileges. Please restart with admin rights.")
        return 1
    
    # Set stealth mode if requested
    if args.stealth:
        create_stealth_console()
    else:
        # Display the ASCII art banner only in console mode (not stealth)
        # and only when not terminating
        if not args.quit:
            display_banner()
    
    # Initialize the scanner
    scanner = ProcessScanner(admin_status, args.json)
    
    # Default to scan mode if no mode is specified
    run_scan = args.scan or (not args.scan and not args.monitor)
    
    # Run in scan mode
    if run_scan:
        logger.info("Starting scan of running processes")
        scan_results = scanner.scan_all_processes()
        
        # Create results dictionary if scan_results is None or a list
        if scan_results is None:
            # Handle case where scan_all_processes returns None
            results = {
                "suspicious_processes": [],
                "scan_time": datetime.now().isoformat(),
                "admin_rights": is_admin()
            }
            logger.warning("Scan returned no results, creating empty results container")
        elif isinstance(scan_results, list):
            # Convert list to dict if scan_all_processes returns a list
            results = {
                "suspicious_processes": scan_results,
                "scan_time": datetime.now().isoformat(),
                "admin_rights": is_admin()
            }
        else:
            # scan_results is already a dictionary
            results = scan_results
            results["scan_time"] = datetime.now().isoformat()
            results["admin_rights"] = is_admin()
        
        # Display results
        suspicious_procs = results.get("suspicious_processes", [])
        if suspicious_procs and len(suspicious_procs) > 0:
            logger.info(f"Found {len(suspicious_procs)} suspicious processes")
            for proc in suspicious_procs:
                # Log thông tin về các quy trình đáng ngờ
                threat_level = proc.get("threat_level", "LOW")
                pid = proc.get("pid")
                name = proc.get("name")
                reason = proc.get("reason", "Unknown reason")
                # Already logged during scan with the proper threat level
        else:
            logger.info("No suspicious processes detected")
            
        save_to_json(results, "results.json")
        logger.info(f"Scan complete. Results saved to results.json")
        
        # If no arguments provided (double-click scenario), wait for user input
        if not len(sys.argv) > 1:
            print("\nScan complete. Press Enter to exit...")
            input()
        
    # Service registration mode
    if args.service:
        logger.info("Service mode requested")
        exe_path = os.path.abspath(sys.argv[0])
                # Check if already registered
        if is_registered_startup():
            logger.info("Service is already registered to run at startup")
            print("ProcessGuard is already registered to run at startup.")
            
            # Option to unregister
            choice = input("Do you want to unregister from startup? (y/n): ").lower()
            if choice == 'y':
                if unregister_startup():
                    logger.info("Service successfully unregistered from startup")
                    print("ProcessGuard has been removed from startup.")
                else:
                    logger.error("Failed to unregister service from startup")
                    print("Failed to remove from startup.")
        else:
            # Register as a startup service
            if register_startup(exe_path):
                logger.info("Service successfully registered to run at startup")
                print("ProcessGuard will now run at system startup.")
                print("It will run in stealth mode and monitor for suspicious processes.")
            else:
                logger.error("Failed to register service for startup")
                print("Failed to register as startup service. Try running as administrator.")
    
    # Run in monitor mode
    if args.monitor:
        logger.info("Starting process monitor")
        
        # Create monitor with new options
        monitor = ProcessMonitor(
            scanner=scanner, 
            results_file=args.json,
            min_threat_level=args.min_threat_level,
            auto_kill=args.kill
        )
        
        # Start monitoring
        monitor.start_monitoring()
        
        # Print status message about configuration
        if args.kill:
            logger.info(f"Auto-kill is ENABLED for HIGH threat processes")
            
        logger.info(f"Logging processes with threat level >= {args.min_threat_level}")
        
        # Keep the monitor running until user interrupts
        try:
            # If in service mode, don't show this message
            if not args.service and not args.stealth:
                logger.info("Monitor running. Press Ctrl+C to stop...")
                
            # Main monitoring loop
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
            monitor.stop_monitoring()
    
    # Wait for user input is now handled in the scan section directly
    # This section was moved to the beginning of the function to exit immediately when -Q is used
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
