from django.shortcuts import render
from django.http import FileResponse, HttpResponse
from .models import Event
from django.db.models import Count, Q
import os
import sys

# ── Fix import path ───────────────────────────────────────
# Project structure:
#   /home/kali/OS_Project/                  <-- reporting_engine.py lives here
#   /home/kali/OS_Project/soc_dashboard/    <-- Django project root (manage.py)
#   /home/kali/OS_Project/soc_dashboard/monitoring/views.py  <-- this file
#
# We need to go two levels up from this file to reach OS_Project/
_THIS_FILE   = os.path.abspath(__file__)                        # .../monitoring/views.py
_MONITORING  = os.path.dirname(_THIS_FILE)                      # .../monitoring/
_SOC_DASH    = os.path.dirname(_MONITORING)                     # .../soc_dashboard/
_PROJECT_ROOT = os.path.dirname(_SOC_DASH)                      # .../OS_Project/

if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import reporting_engine


# ══════════════════════════════════════════════════════════
#  EXISTING VIEWS
# ══════════════════════════════════════════════════════════

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
    events = Event.objects.filter(
        Q(event_type__in=["AUTH_FAIL", "AUTH_SUCCESS", "PRIV_ESC"])
        | Q(source__in=["ssh", "sudo", "su", "pam", "auth"])
    ).exclude(
        event_type="PROCESS_START"
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


# ══════════════════════════════════════════════════════════
#  REPORT VIEWS
# ══════════════════════════════════════════════════════════

def report(request):
    """
    Web report page — full security report inside the dashboard.
    """
    from datetime import datetime

    score, level  = reporting_engine.threat_score()
    sev           = reporting_engine.severity_breakdown()
    total         = reporting_engine.total_events()
    alerts_count  = reporting_engine.total_alerts()
    types_raw     = reporting_engine.event_type_breakdown()
    high_alerts   = reporting_engine.recent_high_alerts(20)
    auth_evs      = reporting_engine.recent_auth_events(20)
    failed        = reporting_engine.top_failed_users(10)
    generated_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Severity counts with percentage bar
    total_ev = total or 1
    severity_counts = [
        {
            "severity": s,
            "count":    sev.get(s, 0),
            "percent":  round((sev.get(s, 0) / total_ev) * 100),
        }
        for s in ["HIGH", "MEDIUM", "LOW"]
    ]

    # Event type rows — exclude pure noise sources
    EXCLUDE_TYPES = {"AUTH"}          # legacy bad event_type in old data
    event_types = [
        {"event_type": et, "count": cnt}
        for et, cnt in types_raw.items()
        if et not in EXCLUDE_TYPES
    ]

    failed_logins = [{"message": msg, "count": cnt} for msg, cnt in failed]

    # Auto-generated recommendations
    recommendations = _build_recommendations(sev, types_raw)

    return render(request, "report.html", {
        "threat_score":    score,
        "threat_level":    level,
        "total_events":    total,
        "total_alerts":    alerts_count,
        "severity_counts": severity_counts,
        "event_types":     event_types,
        "high_alerts":     high_alerts,
        "auth_events":     auth_evs,
        "failed_logins":   failed_logins,
        "recommendations": recommendations,
        "generated_at":    generated_at,
    })


def report_download(request):
    """
    Generate a PDF report and serve it as a file download.
    """
    import tempfile
    from datetime import datetime

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_report_{ts}.pdf"
    tmp      = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    tmp.close()

    try:
        reporting_engine.generate_pdf_report(tmp.name)
        response = FileResponse(
            open(tmp.name, "rb"),
            content_type="application/pdf",
        )
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response
    except Exception as e:
        return HttpResponse(f"Error generating report: {e}", status=500)
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════
#  SHARED HELPER
# ══════════════════════════════════════════════════════════

def _build_recommendations(sev, types_raw):
    recs = []

    high_count = sev.get("HIGH", 0)
    if high_count > 0:
        recs.append(
            f"[HIGH] {high_count} high severity events detected. "
            "Review all ALERT entries immediately and investigate affected users/processes."
        )

    auth_fail_count = types_raw.get("AUTH_FAIL", 0)
    if auth_fail_count >= 3:
        recs.append(
            f"[AUTH] {auth_fail_count} authentication failures recorded. "
            "Consider enforcing account lockout policies and reviewing SSH access."
        )

    priv_count = types_raw.get("PRIV_ESC", 0)
    if priv_count > 0:
        recs.append(
            f"[PRIV] {priv_count} privilege escalation events (sudo/su) detected. "
            "Verify all sudo usage was authorized."
        )

    file_del = types_raw.get("FILE_DELETE", 0)
    if file_del > 10:
        recs.append(
            f"[FILE] {file_del} file deletions recorded. "
            "Review for mass deletion patterns indicating ransomware activity."
        )

    if not recs:
        recs.append("No critical issues detected. Continue routine monitoring.")

    return recs
