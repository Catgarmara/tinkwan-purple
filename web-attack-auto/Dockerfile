FROM python:3.9-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    cron \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the automation script
COPY wazuh_dashboard_reporter.py .
COPY entrypoint.sh .

# Make scripts executable
RUN chmod +x entrypoint.sh
RUN chmod +x wazuh_dashboard_reporter.py

# Create cron job file
RUN echo "0 0 * * * cd /app && python3 wazuh_dashboard_reporter.py >> /var/log/wazuh_automation.log 2>&1" > /etc/cron.d/wazuh-report
RUN chmod 0644 /etc/cron.d/wazuh-report
RUN crontab /etc/cron.d/wazuh-report

# Create log file
RUN touch /var/log/wazuh_automation.log

# Set entrypoint
ENTRYPOINT ["./entrypoint.sh"]
