"""
reporting_engine.py
-------------------
Security Logging & Reporting System — Reporting Module

Usage:
  python3 reporting_engine.py            # CLI report
  python3 reporting_engine.py --pdf      # Export PDF
  python3 reporting_engine.py --pdf --out /path/report.pdf
"""

import sqlite3
import argparse
import os
from datetime import datetime

# ── Resolve DB path ───────────────────────────────────────
# reporting_engine.py lives at OS_Project/reporting_engine.py
# security_logs.db lives in the same directory.
_HERE   = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(_HERE, "security_logs.db")

# ── Noise sources excluded from top-sources query
NOISE_SOURCES = {
    "bwrap", "glycin-image-rs", "glycin-svg", "wrapper-2.0",
    "gvfsd-metadata", "python3",
}

AUTH_EVENT_TYPES = ("AUTH_FAIL", "AUTH_SUCCESS", "PRIV_ESC")
AUTH_SOURCES     = ("ssh", "sudo", "su", "pam", "auth")


# ══════════════════════════════════════════════════════════
#  DATABASE HELPERS
# ══════════════════════════════════════════════════════════

def _conn():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def total_events():
    with _conn() as c:
        result = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return result or 0


def severity_breakdown():
    with _conn() as c:
        rows = c.execute(
            "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity"
        ).fetchall()
    return {row["severity"]: row["cnt"] for row in rows}


def event_type_breakdown():
    with _conn() as c:
        rows = c.execute("""
            SELECT event_type, COUNT(*) as cnt
            FROM events
            WHERE event_type NOT IN ('AUTH', 'PROCESS_START_IGNORED')
            GROUP BY event_type
            ORDER BY cnt DESC
        """).fetchall()
    return {row["event_type"]: row["cnt"] for row in rows}


def total_alerts():
    with _conn() as c:
        result = c.execute(
            "SELECT COUNT(*) FROM events WHERE severity='HIGH'"
        ).fetchone()[0]
    return result or 0


def top_failed_users(limit=10):
    with _conn() as c:
        rows = c.execute("""
            SELECT message, COUNT(*) as cnt
            FROM events
            WHERE event_type = 'AUTH_FAIL'
            GROUP BY message
            ORDER BY cnt DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [(row["message"], row["cnt"]) for row in rows]


def top_sources(limit=8):
    placeholders = ",".join("?" * len(NOISE_SOURCES))
    query = f"""
        SELECT source, COUNT(*) as cnt
        FROM events
        WHERE source NOT IN ({placeholders})
        GROUP BY source
        ORDER BY cnt DESC
        LIMIT ?
    """
    with _conn() as c:
        rows = c.execute(query, (*NOISE_SOURCES, limit)).fetchall()
    return [(row["source"], row["cnt"]) for row in rows]


def recent_high_alerts(limit=20):
    with _conn() as c:
        rows = c.execute("""
            SELECT timestamp, event_type, source, message
            FROM events
            WHERE severity = 'HIGH'
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]


def recent_auth_events(limit=20):
    with _conn() as c:
        rows = c.execute("""
            SELECT timestamp, event_type, source, message, severity
            FROM events
            WHERE (
                event_type IN ('AUTH_FAIL', 'AUTH_SUCCESS', 'PRIV_ESC')
                OR source IN ('ssh', 'sudo', 'su', 'pam', 'auth')
            )
            AND event_type != 'PROCESS_START'
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit * 3,)).fetchall()

    # Deduplicate PRIV_ESC: same source+message in same minute = one entry
    seen, deduped = {}, []
    for row in rows:
        d = dict(row)
        if d["event_type"] == "PRIV_ESC":
            key = (d["source"], d["message"])
            if key in seen and d["timestamp"][:16] == seen[key][:16]:
                continue
            seen[key] = d["timestamp"]
        deduped.append(d)
        if len(deduped) >= limit:
            break
    return deduped


def threat_score():
    with _conn() as c:
        rows = c.execute(
            "SELECT event_type FROM events ORDER BY timestamp DESC LIMIT 100"
        ).fetchall()
    score = 0
    for row in rows:
        et = row["event_type"]
        if et == "ALERT":       score += 20
        elif et == "AUTH_FAIL": score += 5
        elif et == "PRIV_ESC":  score += 5
        elif et == "FILE_DELETE": score += 10
    level = "LOW" if score < 20 else "MEDIUM" if score < 50 else "HIGH"
    return score, level


def suspicious_processes(limit=10):
    with _conn() as c:
        rows = c.execute("""
            SELECT timestamp, source, message
            FROM events
            WHERE event_type = 'ALERT' AND source != 'filesystem'
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]


def file_alert_events(limit=10):
    with _conn() as c:
        rows = c.execute("""
            SELECT timestamp, event_type, message
            FROM events
            WHERE source = 'filesystem' AND severity = 'HIGH'
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]


def _build_recommendations(sev, types_raw):
    recs = []
    if sev.get("HIGH", 0) > 0:
        recs.append(
            f"[HIGH] {sev['HIGH']} high severity events detected. "
            "Review all ALERT entries immediately and investigate affected users/processes."
        )
    if types_raw.get("AUTH_FAIL", 0) >= 3:
        recs.append(
            f"[AUTH] {types_raw['AUTH_FAIL']} authentication failures recorded. "
            "Consider enforcing account lockout policies and reviewing SSH access."
        )
    if types_raw.get("PRIV_ESC", 0) > 0:
        recs.append(
            f"[PRIV] {types_raw['PRIV_ESC']} privilege escalation events (sudo/su) detected. "
            "Verify all sudo usage was authorized."
        )
    if types_raw.get("FILE_DELETE", 0) > 10:
        recs.append(
            f"[FILE] {types_raw['FILE_DELETE']} file deletions recorded. "
            "Review for mass deletion patterns indicating ransomware activity."
        )
    if not recs:
        recs.append("No critical issues detected. Continue routine monitoring.")
    return recs


# ══════════════════════════════════════════════════════════
#  CLI REPORT
# ══════════════════════════════════════════════════════════

def show_report():
    score, level = threat_score()
    sev          = severity_breakdown()
    types        = event_type_breakdown()

    print("\n" + "=" * 55)
    print("   SECURITY LOGGING & REPORTING SYSTEM")
    print("   Incident Report —", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 55)
    print(f"\n  Threat Score  : {score}")
    print(f"  Risk Level    : {level}")
    print(f"  Total Events  : {total_events()}")
    print(f"  Total Alerts  : {total_alerts()}")

    print("\n--- Severity Breakdown ---")
    for s in ["HIGH", "MEDIUM", "LOW"]:
        count = sev.get(s, 0)
        print(f"  {s:<8} {count:>6}  {'#' * min(count, 40)}")

    print("\n--- Event Type Breakdown ---")
    for et, cnt in types.items():
        print(f"  {et:<22} {cnt}")

    print("\n--- Top Event Sources ---")
    for src, cnt in top_sources():
        print(f"  {src:<22} {cnt}")

    print("\n--- Recent HIGH Severity Alerts ---")
    alerts = recent_high_alerts(10)
    if alerts:
        for a in alerts:
            print(f"  [{a['timestamp']}] [{a['source'].upper()}] {a['message']}")
    else:
        print("  No high severity alerts.")

    print("\n--- Recent Authentication Events ---")
    auth = recent_auth_events(10)
    if auth:
        for a in auth:
            print(f"  [{a['timestamp']}] [{a['event_type']}] {a['message']}")
    else:
        print("  No authentication events.")

    print("\n--- Top Failed Login Attempts ---")
    failed = top_failed_users(5)
    if failed:
        for msg, cnt in failed:
            print(f"  {cnt}x  {msg}")
    else:
        print("  No failed login events.")

    print("\n--- Recommendations ---")
    for i, rec in enumerate(_build_recommendations(sev, types), 1):
        print(f"  {i}. {rec}")

    print("\n" + "=" * 55 + "\n")


# ══════════════════════════════════════════════════════════
#  PDF REPORT GENERATOR
# ══════════════════════════════════════════════════════════

def generate_pdf_report(output_path=None):
    """
    Generate a professional PDF security report.
    Returns the output file path.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer,
        Table, TableStyle, HRFlowable, PageBreak
    )
    from reportlab.lib.enums import TA_CENTER

    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(_HERE, f"security_report_{ts}.pdf")

    # ── Collect data ──────────────────────────────────────
    score, level  = threat_score()
    sev           = severity_breakdown()
    types         = event_type_breakdown()
    alerts        = recent_high_alerts(20)
    auth_evs      = recent_auth_events(20)
    failed        = top_failed_users(10)
    sources       = top_sources(10)
    proc_alerts   = suspicious_processes(10)
    file_alerts   = file_alert_events(10)
    recs          = _build_recommendations(sev, types)
    generated_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Guard: convert everything to safe strings
    total_ev_str  = str(total_events())
    total_al_str  = str(total_alerts())
    score_str     = str(score)
    level_str     = str(level)

    # ── Colors ────────────────────────────────────────────
    NAVY   = colors.HexColor("#0D1B2A")
    BLUE   = colors.HexColor("#1A56DB")
    CYAN   = colors.HexColor("#0891B2")
    RED    = colors.HexColor("#DC2626")
    AMBER  = colors.HexColor("#D97706")
    GREEN  = colors.HexColor("#16A34A")
    LGRAY  = colors.HexColor("#F1F5F9")
    BORDER = colors.HexColor("#CBD5E1")
    WHITE  = colors.white
    BLACK  = colors.HexColor("#111827")

    LEVEL_COLOR = {"HIGH": RED, "MEDIUM": AMBER, "LOW": GREEN}

    # ── Page geometry ─────────────────────────────────────
    PAGE_W = A4[0]           # 595.27 pt
    MARGIN = 2 * cm          # 56.69 pt each side
    W = PAGE_W - 2 * MARGIN  # 481.89 pt  usable width

    # ── Styles ────────────────────────────────────────────
    def S(name, **kw):
        return ParagraphStyle(name, **kw)

    S_TITLE    = S("TI", fontSize=20, textColor=NAVY, fontName="Helvetica-Bold",
                   alignment=TA_CENTER, spaceAfter=5)
    S_SUBTITLE = S("SU", fontSize=10, textColor=BLUE, fontName="Helvetica",
                   alignment=TA_CENTER, spaceAfter=4)
    S_META     = S("ME", fontSize=8,  textColor=colors.grey, fontName="Helvetica",
                   alignment=TA_CENTER, spaceAfter=14)
    S_H1       = S("H1", fontSize=13, textColor=NAVY, fontName="Helvetica-Bold",
                   spaceBefore=16, spaceAfter=6)
    S_H2       = S("H2", fontSize=10, textColor=BLUE, fontName="Helvetica-Bold",
                   spaceBefore=10, spaceAfter=5)
    S_BODY     = S("BO", fontSize=9,  textColor=BLACK, fontName="Helvetica",
                   spaceAfter=4, leading=13)
    S_SMALL    = S("SM", fontSize=7,  textColor=colors.grey, fontName="Helvetica")

    # ── Table style helper ────────────────────────────────
    def tbl_style(hdr_color=NAVY):
        return TableStyle([
            ("BACKGROUND",     (0, 0), (-1,  0), hdr_color),
            ("TEXTCOLOR",      (0, 0), (-1,  0), WHITE),
            ("FONTNAME",       (0, 0), (-1,  0), "Helvetica-Bold"),
            ("FONTSIZE",       (0, 0), (-1,  0), 9),
            ("FONTNAME",       (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE",       (0, 1), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LGRAY]),
            ("GRID",           (0, 0), (-1, -1), 0.5, BORDER),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LEFTPADDING",    (0, 0), (-1, -1), 7),
            ("RIGHTPADDING",   (0, 0), (-1, -1), 7),
        ])

    def trunc(s, n=65):
        s = str(s) if s is not None else ""
        return s if len(s) <= n else s[:n-3] + "..."

    def no_data(cols):
        return [["No data available"] + [""] * (cols - 1)]

    # ── Build story ───────────────────────────────────────
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=MARGIN,
        title="Security Incident Report",
        author="Security Logging & Reporting System",
    )
    story = []

    # ── Cover ─────────────────────────────────────────────
    story += [
        Spacer(1, cm),
        Paragraph("SECURITY LOGGING &amp; REPORTING SYSTEM", S_TITLE),
        Paragraph("Automated Security Incident Report", S_SUBTITLE),
        Paragraph(f"Generated: {generated_at}  |  Platform: Kali Linux", S_META),
        HRFlowable(width=W, color=BLUE, thickness=2),
        Spacer(1, 0.4*cm),
    ]

    # ── Threat banner ─────────────────────────────────────
    # FIX: all colWidths must sum exactly to W, all cell values
    # must be plain strings (no None) to avoid int(None) crash.
    tc = LEVEL_COLOR.get(level_str, GREEN)
    col4 = W / 4  # 120.47 pt each — four equal columns, total = W exactly

    banner = Table(
        [
            ["THREAT SCORE", "RISK LEVEL", "TOTAL EVENTS", "TOTAL ALERTS"],
            [score_str,      level_str,    total_ev_str,   total_al_str],
        ],
        colWidths=[col4, col4, col4, col4],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME",      (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 1), (-1, 1), 20),
        ("TEXTCOLOR",     (0, 1), (0,  1), tc),
        ("TEXTCOLOR",     (1, 1), (1,  1), tc),
        ("TEXTCOLOR",     (2, 1), (2,  1), BLUE),
        ("TEXTCOLOR",     (3, 1), (3,  1), RED),
        ("BACKGROUND",    (0, 1), (-1, 1), LGRAY),
        ("GRID",          (0, 0), (-1, -1), 1, BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story += [banner, Spacer(1, 0.5*cm)]

    # ── 1. Event Summary ──────────────────────────────────
    story += [
        Paragraph("1. Event Summary", S_H1),
        HRFlowable(width=W, color=BORDER, thickness=0.5),
        Spacer(1, 0.2*cm),
    ]

    # Two side-by-side tables.
    # FIX: widths are computed so left + gap + right = W exactly.
    GAP   = 0.4 * cm          # 11.34 pt spacer column
    HALF  = (W - GAP) / 2     # 235.27 pt each side

    sev_rows = [["Severity", "Count"]]
    for s in ["HIGH", "MEDIUM", "LOW"]:
        sev_rows.append([s, str(sev.get(s, 0))])
    sev_t = Table(sev_rows, colWidths=[HALF * 0.65, HALF * 0.35])
    sev_t.setStyle(tbl_style(NAVY))
    sev_t.setStyle(TableStyle([
        ("TEXTCOLOR", (0, 1), (-1, 1), RED),
        ("TEXTCOLOR", (0, 2), (-1, 2), AMBER),
        ("TEXTCOLOR", (0, 3), (-1, 3), GREEN),
        ("FONTNAME",  (0, 1), (-1, 3), "Helvetica-Bold"),
    ]))

    type_rows = [["Event Type", "Count"]]
    for et, cnt in list(types.items())[:8]:
        type_rows.append([str(et), str(cnt)])
    type_t = Table(type_rows, colWidths=[HALF * 0.72, HALF * 0.28])
    type_t.setStyle(tbl_style(CYAN))

    # Container table: [sev_t | gap | type_t] — widths sum exactly to W
    combined = Table(
        [[sev_t, "", type_t]],
        colWidths=[HALF, GAP, HALF],
    )
    combined.setStyle(TableStyle([
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",(0, 0), (-1, -1), 0),
        ("TOPPADDING",  (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0,0), (-1, -1), 0),
    ]))
    story += [combined, Spacer(1, 0.3*cm)]

    # Top sources table (full width)
    story.append(Paragraph("Top Event Sources", S_H2))
    src_rows = [["Source", "Event Count"]]
    src_rows += [[str(s), str(c)] for s, c in sources] or no_data(2)
    src_t = Table(src_rows, colWidths=[W * 0.55, W * 0.45])
    src_t.setStyle(tbl_style(CYAN))
    story += [src_t, Spacer(1, 0.3*cm)]

    # ── 2. Authentication Events ──────────────────────────
    story += [
        Paragraph("2. Authentication Events", S_H1),
        HRFlowable(width=W, color=BORDER, thickness=0.5),
        Spacer(1, 0.2*cm),
    ]

    story.append(Paragraph("Top Failed Login Attempts", S_H2))
    fail_rows = [["Message", "Count"]]
    fail_rows += [[trunc(m, 72), str(c)] for m, c in failed] or no_data(2)
    fail_t = Table(fail_rows, colWidths=[W * 0.82, W * 0.18])
    fail_t.setStyle(tbl_style(RED))
    story += [fail_t, Spacer(1, 0.3*cm)]

    story.append(Paragraph("Recent Authentication Events", S_H2))
    auth_rows = [["Timestamp", "Type", "Source", "Sev", "Message"]]
    for ev in auth_evs:
        auth_rows.append([
            str(ev.get("timestamp", "")),
            str(ev.get("event_type", "")),
            str(ev.get("source", "")),
            str(ev.get("severity", "")),
            trunc(ev.get("message", ""), 46),
        ])
    if not auth_evs:
        auth_rows += no_data(5)
    # colWidths sum = W exactly: 0.20+0.14+0.10+0.08+0.48 = 1.0
    auth_t = Table(auth_rows,
                   colWidths=[W*0.20, W*0.14, W*0.10, W*0.08, W*0.48])
    auth_t.setStyle(tbl_style(RED))
    for i, ev in enumerate(auth_evs, 1):
        c = LEVEL_COLOR.get(str(ev.get("severity", "")), BLACK)
        auth_t.setStyle(TableStyle([
            ("TEXTCOLOR", (3, i), (3, i), c),
            ("FONTNAME",  (3, i), (3, i), "Helvetica-Bold"),
        ]))
    story += [auth_t, PageBreak()]

    # ── 3. High Severity Alerts ───────────────────────────
    story += [
        Paragraph("3. High Severity Alerts", S_H1),
        HRFlowable(width=W, color=BORDER, thickness=0.5),
        Spacer(1, 0.2*cm),
    ]
    if alerts:
        al_rows = [["Timestamp", "Type", "Source", "Message"]]
        for a in alerts:
            al_rows.append([
                str(a.get("timestamp", "")),
                str(a.get("event_type", "")),
                str(a.get("source", "")),
                trunc(a.get("message", ""), 58),
            ])
        # 0.20+0.16+0.12+0.52 = 1.0
        al_t = Table(al_rows, colWidths=[W*0.20, W*0.16, W*0.12, W*0.52])
        al_t.setStyle(tbl_style(RED))
        story.append(al_t)
    else:
        story.append(Paragraph("No high severity alerts recorded.", S_BODY))
    story.append(Spacer(1, 0.4*cm))

    # ── 4. Suspicious Process Alerts ─────────────────────
    story += [
        Paragraph("4. Suspicious Process Alerts", S_H1),
        HRFlowable(width=W, color=BORDER, thickness=0.5),
        Spacer(1, 0.2*cm),
    ]
    if proc_alerts:
        pr_rows = [["Timestamp", "Process", "Message"]]
        for p in proc_alerts:
            pr_rows.append([
                str(p.get("timestamp", "")),
                str(p.get("source", "")),
                trunc(p.get("message", ""), 63),
            ])
        # 0.22+0.15+0.63 = 1.0
        pr_t = Table(pr_rows, colWidths=[W*0.22, W*0.15, W*0.63])
        pr_t.setStyle(tbl_style(AMBER))
        story.append(pr_t)
    else:
        story.append(Paragraph("No suspicious process alerts recorded.", S_BODY))
    story.append(Spacer(1, 0.4*cm))

    # ── 5. Filesystem Alerts ──────────────────────────────
    story += [
        Paragraph("5. Filesystem Security Alerts", S_H1),
        HRFlowable(width=W, color=BORDER, thickness=0.5),
        Spacer(1, 0.2*cm),
    ]
    if file_alerts:
        fi_rows = [["Timestamp", "Type", "Message"]]
        for f in file_alerts:
            fi_rows.append([
                str(f.get("timestamp", "")),
                str(f.get("event_type", "")),
                trunc(f.get("message", ""), 68),
            ])
        # 0.22+0.16+0.62 = 1.0
        fi_t = Table(fi_rows, colWidths=[W*0.22, W*0.16, W*0.62])
        fi_t.setStyle(tbl_style(CYAN))
        story.append(fi_t)
    else:
        story.append(Paragraph("No filesystem alerts recorded.", S_BODY))
    story.append(Spacer(1, 0.4*cm))

    # ── 6. Recommendations ───────────────────────────────
    story += [
        Paragraph("6. Recommendations", S_H1),
        HRFlowable(width=W, color=BORDER, thickness=0.5),
        Spacer(1, 0.2*cm),
    ]
    rec_rows = [["#", "Recommendation"]]
    for i, r in enumerate(recs, 1):
        rec_rows.append([str(i), str(r)])
    # 0.05+0.95 = 1.0
    rec_t = Table(rec_rows, colWidths=[W*0.05, W*0.95])
    rec_t.setStyle(tbl_style(NAVY))
    story += [rec_t, Spacer(1, 0.5*cm)]

    # ── Footer ────────────────────────────────────────────
    story += [
        HRFlowable(width=W, color=BORDER, thickness=0.5),
        Spacer(1, 0.2*cm),
        Paragraph(
            f"Report generated automatically by the Security Logging &amp; Reporting System "
            f"on {generated_at}. Covers events stored in security_logs.db.",
            S_SMALL
        ),
    ]

    doc.build(story)
    print(f"[+] PDF report saved: {output_path}")
    return output_path


# ══════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Security Logging & Reporting System"
    )
    parser.add_argument("--pdf", action="store_true",
                        help="Export a PDF report")
    parser.add_argument("--out", type=str, default=None,
                        help="Output path for PDF")
    args = parser.parse_args()

    if args.pdf:
        generate_pdf_report(args.out)
    else:
        show_report()
