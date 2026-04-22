#!/bin/bash
# ============================================================
# setup_logging.sh
# Run this ONCE as root before starting the security monitor.
# It enables persistent journald storage and rsyslog so that
# sudo/su/auth events are actually written to disk.
# ============================================================

echo "[*] Enabling persistent journald storage..."
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald
echo "[OK] journald will now persist logs to /var/log/journal"

echo "[*] Enabling rsyslog (provides /var/log/auth.log)..."
apt-get install -y rsyslog > /dev/null 2>&1
systemctl enable rsyslog
systemctl start rsyslog
echo "[OK] rsyslog started — /var/log/auth.log will now be written"

echo ""
echo "[DONE] Logging infrastructure is ready."
echo "       Run your security monitor now."
