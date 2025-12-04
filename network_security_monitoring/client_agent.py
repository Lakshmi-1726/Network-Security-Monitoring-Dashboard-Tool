import requests
import datetime
import socket
import time
import socket

DEVICE_NAME = socket.gethostname()
print("Device Name:", DEVICE_NAME)


# Change this if your server IP is different
SERVER_URL = "http://172.20.10.2:8000/api/collect-event/"


def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "0.0.0.0"


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
        print(f"Sent → {event_type} ({severity}) {res.status_code}")
    except Exception as e:
        print("Error sending:", e)


if __name__ == "__main__":
    print("Starting NSMS agent (demo mode)...")

    try:
        while True:
            send_event(
                "malware",  # event_type
                "high",     # severity
                "Real-time demo: Suspicious malware detected on endpoint"
            )
            time.sleep(5)

    except KeyboardInterrupt:
        print("Agent stopped by user.")

