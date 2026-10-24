"""
Project: PyShield-Process-Guard (Mini EDR & Process Security Monitor)
Author: Sukhi Akhter
Description: A lightweight endpoint detection and response (EDR) prototype designed 
             to monitor running system processes, match threat signatures, 
             automatically terminate malicious processes, and log security telemetry.
"""

import os
import time
import psutil

# Configuration: Threat signatures and suspicious keyword blocklist
SUSPICIOUS_KEYWORDS = [
    "malware",
    "keylogger",
    "suspicious_script",
    "hack_tool",
    "unauthorized_access",
]
LOG_FILE = "security_alerts.log"

def log_security_event(message):
    """Logs security telemetry events to both the console and a local audit file."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    formatted_message = f"[{timestamp}] [SECURITY ALERT]: {message}"
    print(formatted_message)
    
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(formatted_message + "\n")
    except IOError as e:
        print(f"Error writing to audit log: {e}")

def monitor_system_processes():
    """Continuously scans running system processes for behavioral threat indicators."""
    print("[*] PyShield Process Guard initialized. Starting real-time system monitoring...")
    
    while True:
        try:
            # Iterate through active system processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                proc_info = proc.info
                proc_name = proc_info.get('name') or ""
                proc_cmdline = proc_info.get('cmdline') or []
                
                # Construct combined behavioral signature string
                target_signature = f"{proc_name} {' '.join(str(arg) for arg in proc_cmdline)}".lower()
                
                # Pattern matching against known indicators of compromise (IoCs)
                for keyword in SUSPICIOUS_KEYWORDS:
                    if keyword in target_signature:
                        pid = proc_info['pid']
                        log_security_event(f"Threat detected! Indicator '{keyword}' matched in process '{proc_name}' (PID: {pid}).")
                        
                        # Automated Incident Response: Terminate the threat
                        try:
                            proc.terminate()
                            proc.wait(timeout=3)
                            log_security_event(f"Successfully terminated malicious process (PID: {pid}).")
                        except psutil.TimeoutExpired:
                            proc.kill()
                            log_security_event(f"Force-killed unresponsive malicious process (PID: {pid}).")
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as err:
                            log_security_event(f"Access restriction or process closure encountered for PID {pid}: {err}")
                            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            print(f"[-] Unexpected error in monitoring loop: {e}")
            
        # Optimize resource consumption with an interval delay
        time.sleep(5)

if __name__ == "__main__":
    print("==================================================")
    print("       PyShield-Process-Guard Security Agent      ")
    print("==================================================")
    try:
        monitor_system_processes()
    except KeyboardInterrupt:
        print("\n[!] Monitoring agent manually terminated by administrator.")
