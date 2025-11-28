import requests
import datetime
import socket
import time
import platform
DEVICE_NAME = platform.node()


SERVER_URL = "http://172.20.10.2:8000/api/collect-event/"  # change this Ip whenever we connceted to new network , find ip

def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "0.0.0.0"

def send_event(event_type, severity, message):
    data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": event_type,      
        "severity": severity,          
        "source_ip": get_ip(),
        "device_name": DEVICE_NAME,  
        "message": message 
    }
    try:
        res = requests.post(SERVER_URL, json=data)
        print("Sent:", data, "Status:", res.status_code)
    except Exception as e:
        print("Error sending:", e)

if __name__ == "__main__":
    print("Starting simple agent. Press Ctrl+C to stop.")
    while True:
       # send a heartbeat event every 5 seconds
        send_event("active_user", "low", "User activity heartbeat from endpoint")
        time.sleep(5)
