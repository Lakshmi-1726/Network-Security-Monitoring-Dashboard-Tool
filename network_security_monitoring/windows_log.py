import datetime
import socket
import time
import platform
import requests
import psutil
import subprocess
from collections import defaultdict

import win32evtlog  # from pywin32 




# Example: "http://server Ip/api/collect-event/"
SERVER_URL = "http://172.20.10.2:8000/api/collect-event/"


POLL_INTERVAL_SECONDS = 5

# Process names to treat as suspicious (for demo, we can change this)
SUSPICIOUS_PROCESSES = [
    "mimikatz.exe",
    "nc.exe",
    "ncat.exe",
    "powershell.exe",   
    "malware_demo.exe", 
]

# ---------------------------------------------------------

DEVICE_NAME = platform.node()


LAST_SECURITY_RECORD_ID = 0



def get_ip():
    """Get the local IP address of this Windows machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def send_event(event_type, severity, message):
    """Send one event to the Django backend."""
    data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": event_type,
        "severity": severity,
        "source_ip": get_ip(),
        "device_name": DEVICE_NAME,
        "message": message,
    }

    try:
        res = requests.post(SERVER_URL, json=data, timeout=5)
        print(f"[SENT] {event_type} ({severity}) {res.status_code} | {message}")
    except Exception as e:
        print("[ERROR] Failed to send event:", e)


def monitor_failed_logons():
    """
    Monitor Windows Security event log for failed logons.

    Uses Event ID 4625 (An account failed to log on).
    Requires the script to be run as Administrator to read Security log.
    """
    global LAST_SECURITY_RECORD_ID

    log_type = "Security"
    server = None  

    try:
        handle = win32evtlog.OpenEventLog(server, log_type)
    except Exception as e:
        print(f"[ERROR] Cannot open Security log: {e}")
        return

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    try:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
    except Exception as e:
        print(f"[ERROR] Cannot read Security log: {e}")
        win32evtlog.CloseEventLog(handle)
        return

    if not events:
        win32evtlog.CloseEventLog(handle)
        return

    new_failed_events = []

    for event in events:
        record_id = event.RecordNumber
        event_id = event.EventID & 0xFFFF 

        
        if LAST_SECURITY_RECORD_ID and record_id <= LAST_SECURITY_RECORD_ID:

            break

        # 4625 = failed logon
        if event_id == 4625:
            
            try:
                source_ip = ""
                if event.StringInserts and len(event.StringInserts) >= 19:
                   
                    source_ip = event.StringInserts[18]
                message = f"Failed logon detected (Event 4625){' from ' + source_ip if source_ip else ''}"
            except Exception:
                message = "Failed logon detected (Event 4625)"

            new_failed_events.append((record_id, message))

    
    if new_failed_events:
       
        new_failed_events.sort(key=lambda x: x[0])

        for record_id, message in new_failed_events:
            send_event(
                event_type="login_failure",
                severity="high",
                message=message,
            )
            LAST_SECURITY_RECORD_ID = record_id

    win32evtlog.CloseEventLog(handle)


def monitor_suspicious_processes():
    """
    Monitor running processes for suspicious names.
    For demo: looks for names in SUSPICIOUS_PROCESSES list.
    """
    suspicious_found = []

    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            name = (proc.info.get("name") or "").lower()
            exe = (proc.info.get("exe") or "").lower()
            cmdline = " ".join(proc.info.get("cmdline") or []).lower()

            for bad in SUSPICIOUS_PROCESSES:
                bad_lower = bad.lower()
                if bad_lower in name or bad_lower in exe or bad_lower in cmdline:
                    suspicious_found.append((proc.info.get("pid"), name or exe or bad_lower))
                    break
    except Exception as e:
        print("[ERROR] Process monitoring error:", e)
        return

  
    if suspicious_found:
        for pid, pname in suspicious_found:
            send_event(
                event_type="malware",
                severity="high",
                message=f"Suspicious process detected: {pname} (PID {pid})",
            )
       

def main():
    print(f"[INFO] Starting Windows NSMS agent on {DEVICE_NAME}")
    print(f"[INFO] Sending events to: {SERVER_URL}")
    print("[INFO] Press Ctrl + C to stop.\n")

    while True:
       
        monitor_failed_logons()

        monitor_suspicious_processes()

       
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[INFO] Agent stopped by user.")

