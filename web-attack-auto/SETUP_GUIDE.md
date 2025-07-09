# Wazuh CSV Report Automation Setup Guide

## Overview
This automation solution generates daily CSV reports from your Wazuh Discover saved searches and sends them to Slack at 00:00 every day.

## Prerequisites
1. Working Wazuh Docker environment
2. Slack Bot Token with file upload permissions
3. Saved search configured in Wazuh Dashboard

## Setup Steps

### 1. Create Automation Directory
```bash
mkdir -p automation/logs
cd automation
```

### 2. Create Required Files
- Copy the provided Dockerfile, requirements.txt, entrypoint.sh, and wazuh_slack_automation.py to the automation directory
- Make entrypoint.sh executable: `chmod +x entrypoint.sh`

### 3. Configure Slack Bot
1. Go to https://api.slack.com/apps
2. Create a new app or use existing one
3. Add Bot Token Scopes:
   - `files:write`
   - `chat:write`
   - `channels:read`
4. Install app to workspace
5. Copy the Bot User OAuth Token (starts with xoxb-)

### 4. Configure Environment Variables
Create a `.env` file in your Wazuh docker directory with:
```
WAZUH_PASSWORD=your_wazuh_password
OPENSEARCH_PASSWORD=your_opensearch_password  
SLACK_BOT_TOKEN=xoxb-your-bot-token
```

### 5. Update Docker Compose
Add the automation service to your existing docker-compose.yml:
```yaml
services:
  # ... your existing Wazuh services ...

  wazuh-report-automation:
    build:
      context: ./automation
      dockerfile: Dockerfile
    container_name: wazuh-report-automation
    environment:
      - WAZUH_API_URL=https://wazuh.manager:55000
      - WAZUH_USERNAME=wazuh
      - WAZUH_PASSWORD=${WAZUH_PASSWORD}
      - OPENSEARCH_URL=https://wazuh.indexer:9200
      - OPENSEARCH_USERNAME=admin
      - OPENSEARCH_PASSWORD=${OPENSEARCH_PASSWORD}
      - SLACK_BOT_TOKEN=${SLACK_BOT_TOKEN}
      - SLACK_CHANNEL=#security-alerts
      - REPORT_TITLE=wazuh_daily_alerts
    depends_on:
      - wazuh.manager
      - wazuh.indexer
    networks:
      - wazuh
    volumes:
      - ./automation/logs:/var/log
    restart: unless-stopped
```

### 6. Deploy and Test
```bash
# Build and start the automation container
docker-compose up -d wazuh-report-automation

# Test the automation (run immediately)
docker-compose exec wazuh-report-automation python3 wazuh_slack_automation.py

# Check logs
docker-compose logs wazuh-report-automation
```

### 7. Customize Query (Optional)
To modify the data being exported, edit the query in `wazuh_slack_automation.py`:
- Adjust the `_source` fields to include/exclude columns
- Modify the query logic for different filtering
- Change the time range (currently yesterday's data)

## Troubleshooting

### Check Container Status
```bash
docker-compose ps wazuh-report-automation
```

### View Logs
```bash
# Container logs
docker-compose logs wazuh-report-automation

# Automation script logs
tail -f automation/logs/wazuh_automation.log
```

### Test Connectivity
```bash
# Test from inside container
docker-compose exec wazuh-report-automation bash

# Test Wazuh API
curl -k -u wazuh:password https://wazuh.manager:55000/security/user/authenticate

# Test OpenSearch
curl -k -u admin:password https://wazuh.indexer:9200/_cluster/health
```

### Common Issues
1. **Authentication errors**: Check WAZUH_PASSWORD and OPENSEARCH_PASSWORD
2. **Network issues**: Ensure containers are on same network
3. **Slack errors**: Verify bot token and channel permissions
4. **No data**: Check if saved search exists and has data

## Customization Options

### Change Schedule
Edit the cron expression in Dockerfile:
```bash
# Daily at 6 AM
RUN echo "0 6 * * * cd /app && python3 wazuh_slack_automation.py >> /var/log/wazuh_automation.log 2>&1" > /etc/cron.d/wazuh-report

# Every 6 hours
RUN echo "0 */6 * * * cd /app && python3 wazuh_slack_automation.py >> /var/log/wazuh_automation.log 2>&1" > /etc/cron.d/wazuh-report
```

### Custom Query
Modify the OpenSearch query in `wazuh_slack_automation.py` to filter specific:
- Rule IDs
- Alert levels
- Agent groups
- Time ranges
- MITRE ATT&CK techniques

### Multiple Reports
Create multiple automation containers with different configurations for different types of reports.
