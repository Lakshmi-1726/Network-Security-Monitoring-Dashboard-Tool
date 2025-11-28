from django.db import models
from django.contrib.auth import get_user_model

class NetworkEvent(models.Model):
    EVENT_TYPES = [
        ('connection', 'Connection'),
        ('login_failure', 'Login Failure'),
        ('active_user', 'Active User'),
        ('port_scan', 'Port Scan'),
        ('malware', 'Malware'),
        ('other', 'Other'),
    ]
    SEVERITY = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    timestamp = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=20, choices=SEVERITY, default='low')
    source_ip = models.GenericIPAddressField()
    device_name = models.CharField(max_length=100, blank=True, null=True)
    message = models.TextField(blank=True)
    user = models.ForeignKey(get_user_model(), null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return f"{self.event_type} - {self.source_ip} - {self.severity} on {self.timestamp:%Y-%m-%d %H:%M:%S}"

class Alert(models.Model):
    event = models.OneToOneField(NetworkEvent, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    acknowledged = models.BooleanField(default=False)

    def __str__(self):
        return f"Alert for {self.event} (ack={self.acknowledged})"
