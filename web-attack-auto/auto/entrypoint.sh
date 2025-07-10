#!/bin/bash
set -e

touch /var/log/wazuh_automation.log

# Start cron daemon
service cron start

# Keep container running and tail the log file
echo "Wazuh CSV Report Automation started at $(date)"
echo "Cron job scheduled to run daily at 00:00"
echo "Monitoring log file: /var/log/wazuh_automation.log"

# Test run option
if [ "$1" = "test" ]; then
    echo "Running test execution..."
    python3 wazuh_dashboard_reporter.py
    exit 0
fi

# Keep container running
tail -f /var/log/wazuh_automation.log
