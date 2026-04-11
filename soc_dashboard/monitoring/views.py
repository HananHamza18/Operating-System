from django.shortcuts import render
from .models import Event

from django.db.models import Count

def dashboard(request):
    total_events = Event.objects.count()

    severity_counts = Event.objects.values("severity").annotate(
        count=Count("severity")
    )

    alert_count = Event.objects.filter(event_type="ALERT").count()

    latest_alerts = Event.objects.filter(
        severity="HIGH"
    ).order_by("-timestamp")[:5]

    return render(request, "dashboard.html", {
        "total_events": total_events,
        "severity_counts": severity_counts,
        "alert_count": alert_count,
        "latest_alerts": latest_alerts
    })

def auth_events(request):
    events = Event.objects.filter(
        event_type__in=["AUTH", "ALERT"]
    ).order_by("-timestamp")[:100]

    return render(request, "auth_events.html", {
        "events": events
    })

def process_events(request):
    events = Event.objects.filter(
        event_type__in=["PROCESS_START", "ALERT"]
    ).order_by("-timestamp")[:100]

    return render(request, "process_events.html", {
        "events": events
    })

def filesystem_events(request):
    events = Event.objects.filter(
        event_type__in=[
            "FILE_CREATE",
            "FILE_MODIFY",
            "FILE_DELETE",
            "ALERT"
        ]
    ).order_by("-timestamp")[:100]

    return render(request, "filesystem_events.html", {
        "events": events
    })
