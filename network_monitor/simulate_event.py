import os
import django
import random
import time
from datetime import datetime

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "network_security_monitoring.settings")
django.setup()

from network_monitor.models import NetworkEvent  

EVENT_TYPES = ["login_failure", "connection", "active_user", "port_scan", "malware", "other"]
SEVERITIES = ["low", "medium", "high"]

def generate_event():
    event_type = random.choice(EVENT_TYPES)
    severity = random.choice(SEVERITIES)

    NetworkEvent.objects.create(               
        timestamp=datetime.now(),
        event_type=event_type,
        severity=severity,
        source_ip="192.168.0.10",
        message=f"Simulated {event_type} event with {severity} severity",
        user=None,   
    )

    print("Inserted:", event_type, severity)

if __name__ == "__main__":
    print("Starting real-time dummy event generator...")
    while True:
        generate_event()
        time.sleep(5)
