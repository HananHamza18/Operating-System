from django.shortcuts import render
from .models import Event
from django.db.models import Count, Q


def dashboard(request):
    total_events = Event.objects.count()

    severity_counts = Event.objects.values("severity").annotate(
        count=Count("severity")
    )

    alert_count = Event.objects.filter(event_type="ALERT").count()

    latest_alerts = Event.objects.filter(
        severity="HIGH"
    ).order_by("-timestamp")[:5]

    # ── Threat Score ──────────────────────────────────────
    threat_score = 0
    recent_events = Event.objects.order_by("-timestamp")[:100]

    for event in recent_events:
        if event.event_type == "ALERT":
            threat_score += 20
        elif event.event_type == "AUTH_FAIL":
            threat_score += 5
        elif event.event_type == "PRIV_ESC":
            threat_score += 5
        elif event.event_type == "PROCESS_START":
            if "nmap" in event.message.lower():
                threat_score += 25
        elif event.event_type == "FILE_DELETE":
            threat_score += 10

    if threat_score < 20:
        threat_level = "LOW"
    elif threat_score < 50:
        threat_level = "MEDIUM"
    else:
        threat_level = "HIGH"

    return render(request, "dashboard.html", {
        "total_events":    total_events,
        "severity_counts": severity_counts,
        "alert_count":     alert_count,
        "latest_alerts":   latest_alerts,
        "threat_score":    threat_score,
        "threat_level":    threat_level,
    })


def auth_events(request):
    """
    Show all authentication-related events.

    Covers:
      event_type : AUTH_FAIL, AUTH_SUCCESS, PRIV_ESC, ALERT
      source     : ssh, sudo, su, pam, auth

    Previously this only queried source__in=["ssh","sudo"] which
    excluded su, pam, and PRIV_ESC events entirely.
    """
    events = Event.objects.filter(
        Q(event_type__in=["AUTH_FAIL", "AUTH_SUCCESS", "PRIV_ESC"])
        | Q(source__in=["ssh", "sudo", "su", "pam", "auth"])
    ).exclude(
        event_type="PROCESS_START"   # keep process table clean
    ).order_by("-timestamp")[:200]

    return render(request, "auth_events.html", {"events": events})


def process_events(request):
    events = Event.objects.filter(
        event_type__in=["PROCESS_START", "ALERT"]
    ).order_by("-timestamp")[:100]
    return render(request, "process_events.html", {"events": events})


def filesystem_events(request):
    events = Event.objects.filter(
        source="filesystem"
    ).order_by("-timestamp")[:100]
    return render(request, "filesystem_events.html", {"events": events})


def timeline(request):
    events = Event.objects.order_by("-timestamp")[:50]
    return render(request, "timeline.html", {"events": events})


def alerts(request):
    events = Event.objects.filter(
        severity="HIGH"
    ).order_by("-timestamp")[:100]
    return render(request, "alerts.html", {"alerts": events})
