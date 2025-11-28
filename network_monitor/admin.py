from django.contrib import admin
from .models import NetworkEvent, Alert

@admin.register(NetworkEvent)
class NetworkEventAdmin(admin.ModelAdmin):
    list_display = ('event_type','timestamp','severity','source_ip')
    list_filter = ('event_type','severity','timestamp')

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('event','created_at','acknowledged')
