import csv
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator
from django.db.models import Count
from .models import NetworkEvent, Alert
from .forms import SignUpForm
from django.utils import timezone
from datetime import datetime
import json
from django.views.decorators.csrf import csrf_exempt
from .models import NetworkEvent
from django.db.models import Q
from django.contrib.auth import login as auth_login
from django.contrib import messages




@csrf_exempt
def collect_event(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))

            ts_str = data.get("timestamp")
            timestamp = datetime.fromisoformat(ts_str) if ts_str else datetime.now()

            event_type = data.get("event_type", "other")
            severity = data.get("severity", "low")
            source_ip = data.get("source_ip", "0.0.0.0")
            message = data.get("message", "")

            NetworkEvent.objects.create(
                timestamp=timestamp,
                event_type=event_type,
                severity=severity,
                source_ip=source_ip,
                message=message,
            )

            return JsonResponse({"status": "ok"})
        except Exception as e:
            return JsonResponse({"status": "error", "detail": str(e)}, status=400)

    return JsonResponse({"detail": "Only POST allowed"}, status=405)
@csrf_exempt
def collect_event(request):
    if request.method == "POST":
        data = json.loads(request.body)

        NetworkEvent.objects.create(
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            severity=data["severity"],
            source_ip=data["source_ip"],
            device_name=data.get("device_name", "Unknown Device"),
            message=data["message"]
        )

        return JsonResponse({"status": "success"})

       

@login_required
def alerts(request):
    suspicious_events = NetworkEvent.objects.all().order_by("-timestamp")
    
    context = {
        "suspicious_events": suspicious_events,
        "total_alerts": suspicious_events.count(),
    }
    return render(request, "alerts.html", context)

@login_required
def dashboard(request):
   
    last_10_min = timezone.now() - timezone.timedelta(minutes=10)
    events = Event.objects.filter(timestamp__gte=last_10_min).order_by('-timestamp')

    context = {
        "events": events,
        "failed_logins": events.filter(event_type="LOGIN_FAILED").count(),
        "successful_logins": events.filter(event_type="LOGIN_SUCCESS").count(),
    }
    return render(request, "dashboard.html", context)
def user_login(request):
    
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username')  
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            messages.success(request, f"Welcome back, {user.first_name or user.username}!")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, 'login.html')

def signup(request):
    
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Account created successfully. Please log in.")
            return redirect('login')
    else:
        form = SignUpForm()

    return render(request, 'signup.html', {'form': form})

def user_logout(request):
    logout(request)
    return redirect('login')

@login_required
def dashboard(request):
    total_events = NetworkEvent.objects.count()
    active_users = NetworkEvent.objects.filter(event_type='active_user').count()
    failed_logins = NetworkEvent.objects.filter(event_type='login_failure').count()
    alerts_count = Alert.objects.filter(acknowledged=False).count()

    events_qs = NetworkEvent.objects.order_by('-timestamp')
    paginator = Paginator(events_qs, 10)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    context = {
        'total_events': total_events,
        'active_users': active_users,
        'failed_logins': failed_logins,
        'alerts_count': alerts_count,
        'events_page': page_obj,
    }
    return render(request, 'dashboard.html', context)

@login_required
def alerts_view(request):
    alerts = Alert.objects.select_related('event').order_by('-created_at')
    return render(request, 'alerts.html', {'alerts': alerts})

@login_required
def events_api(request):
    qs = NetworkEvent.objects.all().order_by('-timestamp')
    event_type = request.GET.get('type')
    severity = request.GET.get('severity')
    start = request.GET.get('start')
    end = request.GET.get('end')
    q = request.GET.get('q')

    if event_type:
        qs = qs.filter(event_type=event_type)
    if severity:
        qs = qs.filter(severity=severity)
    if start:
        try:
            start_dt = datetime.fromisoformat(start)
            qs = qs.filter(timestamp__gte=start_dt)
        except Exception:
            pass
    if end:
        try:
            end_dt = datetime.fromisoformat(end)
            qs = qs.filter(timestamp__lte=end_dt)
        except Exception:
            pass
    if q:
        qs = qs.filter(message__icontains=q)

    page = int(request.GET.get('page', 1))
    per = int(request.GET.get('per', 10))
    paginator = Paginator(qs, per)
    page_obj = paginator.get_page(page)
    events = []
    for ev in page_obj:
        events.append({
            'id': ev.id,
            'event_type': ev.event_type,
            'timestamp': ev.timestamp.isoformat(),
            'severity': ev.severity,
            'source_ip': ev.source_ip,
            'message': ev.message,
        })
    return JsonResponse({
        'results': events,
        'page': page_obj.number,
        'num_pages': paginator.num_pages,
        'total': paginator.count,
    })

@login_required
def export_csv(request):
    qs = NetworkEvent.objects.all().order_by('-timestamp')
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="network_events.csv"'
    writer = csv.writer(response)
    writer.writerow(['id','event_type','timestamp','severity','source_ip','message'])
    for ev in qs:
        writer.writerow([ev.id, ev.event_type, ev.timestamp.isoformat(), ev.severity, ev.source_ip, ev.message])
    return response
@login_required
def events_list(request):
    event_type = request.GET.get("type")
    q = request.GET.get("q", "")  #  search value

    events = NetworkEvent.objects.all().order_by("-timestamp")
    title = "All Events"

    if event_type == "login_failure":
        events = events.filter(event_type="login_failure")
        title = "Failed Login Events"

    elif event_type == "active_user":
        events = events.filter(event_type="active_user")
        title = "Active User Events"

    elif event_type == "alerts":
        events = events.filter(
            Q(severity__iexact="high") |
            Q(event_type__in=[
                "login_failure",
                "malware",
                "port_scan",
                "restricted_file_access"
            ])
        )
        title = "Active Alerts"

  
    if q:
        events = events.filter(
            Q(event_type__icontains=q) |
            Q(message__icontains=q) |
            Q(device_name__icontains=q) |
            Q(source_ip__icontains=q)
        )

    context = {
        "events": events,
        "title": title,
        "event_type": event_type,
        "q": q,
    }
    return render(request, "events_list.html", context)
@login_required
def events_stats(request):
    from django.utils.timezone import now, timedelta
    from django.db.models import Count
    end = now()
    start = end - timedelta(days=13)

    qs = NetworkEvent.objects.filter(timestamp__date__gte=start.date(),
                                     timestamp__date__lte=end.date())
    data = qs.extra(select={'day': 'date(timestamp)'}).values('day').annotate(count=Count('id')).order_by('day')

    labels = [x['day'] for x in data]  
    counts = [x['count'] for x in data]

    return JsonResponse({'labels': labels, 'counts': counts})

def about(request):
    return render(request, 'about.html')

def contact(request):
    return render(request, 'contact.html')
