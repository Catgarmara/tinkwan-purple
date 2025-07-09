# Wazuh Dashboard Reporting API Automation

## Overview
This approach uses the built-in OpenSearch Dashboard Reporting API to generate CSV reports from your saved searches. This is more aligned with the official Wazuh/OpenSearch reporting functionality.

## Prerequisites
1. Wazuh Dashboard with Reporting plugin enabled
2. Saved search configured in Discover
3. Slack Bot Token
4. The saved search ID from your Wazuh Dashboard

## Finding Your Saved Search ID

### Method 1: From URL
1. Go to Wazuh Dashboard → Discover
2. Load your saved search
3. Look at the URL: `https://your-dashboard/app/discover#/view/SAVED_SEARCH_ID`
4. Copy the ID after `/view/`

### Method 2: From Dashboard API
```bash
curl -k -u admin:password \
  "https://localhost:443/api/saved_objects/_find?type=search" \
  -H "osd-xsrf: true"
```

### Method 3: From Browser Developer Tools
1. Go to Discover → Load your saved search
2. Open Developer Tools → Network tab
3. Look for API calls to find the search ID

## Docker Configuration

Update your docker-compose.yml to include the new automation:

```yaml
services:
  # ... existing Wazuh services ...

  wazuh-dashboard-reporter:
    build:
      context: ./automation
      dockerfile: Dockerfile.dashboard
    container_name: wazuh-dashboard-reporter
    environment:
      - WAZUH_DASHBOARD_URL=https://wazuh.dashboard:5601
      - WAZUH_DASHBOARD_USER=admin
      - WAZUH_DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}
      - SLACK_BOT_TOKEN=${SLACK_BOT_TOKEN}
      - SLACK_CHANNEL=#security-alerts
      - SAVED_SEARCH_ID=${SAVED_SEARCH_ID}
    depends_on:
      - wazuh.dashboard
    networks:
      - wazuh
    volumes:
      - ./automation/logs:/var/log
    restart: unless-stopped
```

## Environment Variables

Add to your .env file:
```bash
# Dashboard credentials
DASHBOARD_PASSWORD=your_dashboard_admin_password

# Slack configuration
SLACK_BOT_TOKEN=xoxb-your-bot-token

# Saved search ID from Discover
SAVED_SEARCH_ID=your-saved-search-id-here
```

## Benefits of Dashboard API Approach

1. **Official Integration**: Uses built-in Wazuh Dashboard reporting
2. **Saved Search Support**: Directly uses your configured saved searches
3. **Native Formatting**: Preserves your custom field configurations
4. **Dashboard Consistency**: Same results as manual CSV export
5. **Report Scheduling**: Leverages existing reporting infrastructure

## Troubleshooting

### Getting Saved Search ID
If you can't find your saved search ID:

```bash
# List all saved searches
docker-compose exec wazuh.dashboard curl -k \
  -u admin:password \
  "http://localhost:5601/api/saved_objects/_find?type=search&fields=title" \
  -H "osd-xsrf: true"
```

### Testing Dashboard API
```bash
# Test authentication
curl -k -u admin:password \
  "https://localhost:443/api/status" \
  -H "osd-xsrf: true"

# Test reporting endpoint
curl -k -u admin:password \
  "https://localhost:443/api/reporting/reportDefinitions" \
  -H "osd-xsrf: true"
```

### Common Issues
1. **404 on reporting endpoints**: Reporting plugin may not be installed
2. **CSRF errors**: Always include `osd-xsrf: true` header
3. **Authentication issues**: Verify dashboard credentials
4. **Saved search not found**: Check the search ID and permissions

## Alternative: Manual CSV with API Enhancement

If the reporting API approach doesn't work, you can enhance the direct API approach:

```python
# Enhanced query with custom fields matching your regex
query = {
    "query": {
        "bool": {
            "must": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": "now-1d/d",
                            "lt": "now/d"
                        }
                    }
                }
            ]
        }
    },
    "size": 10000,
    "_source": [
        # Add your custom regex-decoded fields here
        "custom_field_1",
        "custom_field_2",
        # Standard fields
        "data.srcip",
        "data.id",
        "rule.description"
    ],
    "sort": [{"@timestamp": {"order": "desc"}}]
}
```

This approach gives you maximum control over the data structure and field selection.
