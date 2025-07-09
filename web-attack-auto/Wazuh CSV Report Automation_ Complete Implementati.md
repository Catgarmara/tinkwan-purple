# Wazuh CSV Report Automation: Complete Implementation Guide

## Executive Summary

This comprehensive guide provides a complete automation solution for your Wazuh environment to generate daily CSV reports from your custom regex-decoded web logs and automatically deliver them to Slack. The solution leverages your existing Docker-containerized Wazuh infrastructure and provides two implementation approaches to ensure compatibility with your current setup.

![Wazuh CSV Report Automation Workflow](https://pplx-res.cloudinary.com/image/upload/v1752057550/pplx_code_interpreter/1e3f1248_brzjuf.jpg)

Wazuh CSV Report Automation Workflow

## Technical Architecture

The automation solution integrates seamlessly with your existing Docker-containerized Wazuh environment on Azure. It consists of a containerized Python application that runs on a cron schedule, authenticates with your Wazuh services, queries the data using your saved search parameters, generates CSV reports, and delivers them to your designated Slack channel.

### Key Components

- **Automated Scheduler**: Cron-based execution at 00:00 daily
- **Data Extraction**: Direct integration with OpenSearch/Wazuh indexer
- **Report Generation**: CSV formatting with custom field support
- **Slack Integration**: Automated file upload with contextual messaging
- **Error Handling**: Comprehensive logging and failure notifications
- **Container Orchestration**: Docker Compose integration with existing Wazuh stack


## Implementation Solutions

### Solution 1: Direct OpenSearch API Integration (Recommended)

This approach directly queries your Wazuh indexer (OpenSearch) to extract alert data and generate CSV reports. It provides maximum flexibility for incorporating your custom regex-decoded fields and offers precise control over data formatting.

**Benefits:**

- Full control over query parameters and field selection
- Direct access to your regex-processed custom fields
- Independent of Dashboard reporting plugin dependencies
- Optimized performance for large datasets
- Customizable data filtering and aggregation


### Solution 2: Dashboard Reporting API Integration

This alternative leverages the built-in OpenSearch Dashboard reporting functionality to generate reports from your existing saved searches. It maintains consistency with your manual CSV generation process.

**Benefits:**

- Utilizes your existing saved search configurations
- Maintains exact field mappings from your manual exports
- Leverages official Wazuh Dashboard reporting infrastructure
- Preserves your custom regex field formatting


## Deployment Configuration

### Docker Environment Setup

The automation deploys as an additional container in your existing Wazuh Docker environment. It integrates with your current network topology and service dependencies.

### Service Integration

Add the automation service to your existing Docker Compose configuration:

## Configuration Management

### Environment Variables

Secure configuration management using environment variables ensures sensitive credentials are properly handled:

### Slack Bot Configuration

1. **Create Slack Application**
    - Navigate to https://api.slack.com/apps
    - Create new app or configure existing one
    - Configure OAuth scopes: `files:write`, `chat:write`, `channels:read`
2. **Bot Token Setup**
    - Install app to your workspace
    - Copy Bot User OAuth Token (format: `xoxb-...`)
    - Configure channel permissions for target security channel

### Saved Search Identification

For Dashboard API integration, identify your saved search ID:

```bash
# Method 1: Extract from Dashboard URL
# Navigate to: https://your-dashboard/app/discover#/view/SAVED_SEARCH_ID

# Method 2: API Query
curl -k -u admin:password \
  "https://localhost:443/api/saved_objects/_find?type=search" \
  -H "osd-xsrf: true"
```


## Setup and Deployment Guide

### Step-by-Step Implementation

### Alternative Dashboard API Setup

For organizations preferring the Dashboard API approach:

## Testing and Validation

### Initial Testing

1. **Connectivity Verification**

```bash
# Test Wazuh API access
docker-compose exec wazuh-report-automation curl -k \
  -u wazuh:password https://wazuh.manager:55000/security/user/authenticate

# Test OpenSearch access
docker-compose exec wazuh-report-automation curl -k \
  -u admin:password https://wazuh.indexer:9200/_cluster/health
```

2. **Manual Execution Test**

```bash
# Run immediate test
docker-compose exec wazuh-report-automation python3 wazuh_slack_automation.py
```

3. **Slack Integration Verification**
    - Verify bot permissions in target channel
    - Test file upload functionality
    - Confirm message formatting and delivery

### Monitoring and Logging

```bash
# Monitor container status
docker-compose ps wazuh-report-automation

# View automation logs
docker-compose logs -f wazuh-report-automation

# Check cron execution
docker-compose exec wazuh-report-automation crontab -l
```


## Customization Options

### Query Modification

Adapt the OpenSearch query to include your specific regex-decoded fields:

```python
# Custom field mapping for regex-processed data
"_source": [
    "custom_decoded_field_1",
    "custom_decoded_field_2", 
    "data.srcip",
    "rule.description",
    # Add your specific regex fields here
]
```


### Schedule Adjustment

Modify the cron expression in the Dockerfile for different scheduling:

```bash
# Every 6 hours
"0 */6 * * * cd /app && python3 wazuh_slack_automation.py >> /var/log/wazuh_automation.log 2>&1"

# Daily at 6 AM
"0 6 * * * cd /app && python3 wazuh_slack_automation.py >> /var/log/wazuh_automation.log 2>&1"
```


## Troubleshooting Common Issues

### Authentication Problems

- Verify Wazuh API credentials in environment variables
- Check OpenSearch password configuration
- Ensure network connectivity between containers


### Data Export Issues

- Validate saved search ID existence
- Check query syntax and field mappings
- Verify time range parameters


### Slack Delivery Failures

- Confirm bot token validity and permissions
- Verify channel accessibility
- Check file size limitations


## Implementation Recommendations

For your specific environment with custom regex-decoded fields, **Solution 1 (Direct OpenSearch API)** is recommended because:

1. **Custom Field Support**: Direct control over field selection and formatting
2. **Regex Integration**: Easy incorporation of your processed web log fields
3. **Performance Optimization**: Direct indexer access without Dashboard overhead
4. **Maintenance Simplicity**: Fewer dependencies and integration points

This automation solution provides a robust, scalable approach to automate your daily security reporting workflow while maintaining the custom field structure you've developed through regex processing.

<div style="text-align: center">⁂</div>

[^1]: C873B14F-269E-48AA-83BF-3C876220DDFF.jpg

[^2]: On_demand_report_2025-07-07T12_26_33.140Z_9e06ff40-5b2d-11f0-98a9-57eef20da42f.csv

[^3]: https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/generating-system-inventory-reports.html

[^4]: https://www.youtube.com/watch?v=NkungBEZ_T4

[^5]: https://documentation.wazuh.com/current/user-manual/capabilities/container-security/use-cases.html

[^6]: https://www.reddit.com/r/Wazuh/comments/1d36b4n/wazuh_report_generating_csv_is_truncated/

[^7]: https://groups.google.com/g/wazuh/c/l7S32GLV4nw

[^8]: https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html

[^9]: https://github.com/wazuh/wazuh-indexer-reporting

[^10]: https://www.reddit.com/r/Wazuh/comments/1bsxhmr/wazuh_reporting/

[^11]: https://documentation.wazuh.com/current/proof-of-concept-guide/monitoring-docker.html

[^12]: https://groups.google.com/g/wazuh/c/_Fk07bOpMMQ

[^13]: https://documentation.wazuh.com/current/getting-started/components/wazuh-dashboard.html

[^14]: https://github.com/Dileepmairala/wazuh-docker-monitoring

[^15]: https://groups.google.com/g/wazuh/c/x9frGF4gtEI

[^16]: https://groups.google.com/g/wazuh/c/zchuOZkJb8s

[^17]: https://wazuh.com/blog/docker-container-security-monitoring-with-wazuh/

[^18]: https://www.reddit.com/r/Wazuh/comments/1e6l0j4/how_do_i_export_wazuh_events_to_a_csv_file/

[^19]: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/reports.html

[^20]: https://www.linkedin.com/pulse/using-wazuh-313-monitor-docker-containerized-issac-goldstand

[^21]: https://github.com/denis-jdsouza/wazuh-vulnerability-report-maker

[^22]: https://github.com/wazuh/wazuh-dashboards-reporting

[^23]: https://groups.google.com/g/wazuh/c/jPQSLNegD-s

[^24]: https://slack.com/help/articles/360035354694-Move-data-to-Slack-using-a-CSV-or-text-file

[^25]: https://opensearch.org/docs/2.9/reporting/rep-cli-cron/

[^26]: https://groups.google.com/g/wazuh/c/_RiWrWqw024

[^27]: https://github.com/jk-olaoluwa/wazuh-slack-integration

[^28]: https://opensearch.org/docs/2.5/dashboards/reporting-cli/rep-cli-cron/

[^29]: https://forum.opensearch.org/t/is-csv-stored-on-the-server-if-the-reporting-is-scheduled/16658

[^30]: https://www.reddit.com/r/Wazuh/comments/1lkv56z/integrate_slack_with_wazuh/

[^31]: https://docs.opensearch.org/docs/latest/reporting/rep-cli-cron/

[^32]: https://documentation.wazuh.com/current/integrations-guide/opensearch/index.html

[^33]: https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html

[^34]: https://eliatra.com/docs/2.11/reporting/rep-cli-cron/

[^35]: https://logit.io/docs/log-management/opensearch/reporting/

[^36]: https://documentation.wazuh.com/current/cloud-security/amazon/services/supported-services/custom-buckets.html

[^37]: https://forum.opensearch.org/t/reporting-schedule-as-a-daily-recurring-is-not-creating-report/6863

[^38]: https://github.com/wazuh/wazuh-dashboard/issues/194

[^39]: https://www.youtube.com/watch?v=ZoDVH5AT2Cs

[^40]: https://github.com/opensearch-project/reporting

[^41]: https://wazuh.com/blog/detection-with-opensearch-integration/

[^42]: https://groups.google.com/g/wazuh/c/ZMTH_DAdsrk

[^43]: https://github.com/wazuh/wazuh-kibana-app/issues/390

[^44]: https://qiita.com/zongxiaojie/items/3f2b8ebb45d47b3f55f8

[^45]: https://groups.google.com/g/wazuh/c/hFwkzzhKkv0

[^46]: https://groups.google.com/g/wazuh/c/UDL0uD0l00Q

[^47]: https://gist.github.com/danielunderwood/fd362a1ab382e674576b8f15f39e8435

[^48]: https://documentation.wazuh.com/current/getting-started/components/wazuh-indexer.html

[^49]: https://www.reddit.com/r/Wazuh/comments/1b6fb2z/get_count_in_csv_report/

[^50]: https://gist.github.com/mowings/59790ae930accef486bfb9a417e9d446

[^51]: https://documentation.wazuh.com/current/user-manual/indexer-api/index.html

[^52]: https://askubuntu.com/questions/1347455/cronjob-not-working-for-daily-messaging-for-slack

[^53]: https://www.reddit.com/r/Wazuh/comments/1ijpux2/wazuh_query_the_wazuh_indexer/

[^54]: https://github.com/madebymode/chronos

[^55]: https://groups.google.com/g/wazuh/c/kBxxIv3G420

[^56]: https://github.com/wazuh/wazuh-dashboard-plugins/issues/390

[^57]: https://github.com/ttskch/slack-cron

[^58]: https://documentation.wazuh.com/current/user-manual/wazuh-indexer/index.html

[^59]: https://stackoverflow.com/questions/76907047/how-to-run-shell-script-as-a-crontab-in-docker-container

[^60]: https://stackoverflow.com/questions/35742775/is-it-possible-to-post-files-to-slack-using-the-incoming-webhook

[^61]: https://nickjanetakis.com/blog/docker-tip-40-running-cron-jobs-on-the-host-vs-in-a-container

[^62]: https://github.com/ovidiugiorgi/csv2opensearch

[^63]: https://api.slack.com/methods/files.upload

[^64]: https://dev.to/hexshift/how-to-run-cron-jobs-with-docker-containers-the-right-way-26p4

[^65]: https://www.reddit.com/r/Netsuite/comments/1dye7uc/automating_daily_csv_export_of_saved_search/

[^66]: https://tools.slack.dev/python-slack-sdk/tutorial/uploading-files/

[^67]: https://stackoverflow.com/questions/72517407/using-docker-and-volume-mounted-crontab-file-not-working

[^68]: https://forum.opensearch.org/t/generate-csv-creates-csv-with-incorrect-rows/7051

[^69]: https://api.slack.com/messaging/files

[^70]: https://dev.to/devgraph/running-cron-jobs-in-container-environments-ofb

[^71]: https://github.com/polymons/opensearch-export

[^72]: https://stackoverflow.com/questions/71033427/slack-api-upload-string-as-file

[^73]: https://stackoverflow.com/questions/37458287/how-to-run-a-cron-job-inside-a-docker-container

[^74]: https://communities.sas.com/t5/SAS-Communities-Library/Four-Tips-for-Exporting-logs-from-OpenSearch-Dashboards-Generate/ta-p/848403

[^75]: https://mangolassi.it/topic/23008/send-csv-file-to-slack-channel-by-bash-script-through-webhook

[^76]: https://dev.to/dm8ry/scheduling-cron-jobs-in-docker-a-how-to-guide-415k

[^77]: https://github.com/opensearch-project/reporting/issues/378

[^78]: https://mangolassi.it/tags/csv

[^79]: https://tecadmin.net/running-a-cronjob-inside-docker/

[^80]: https://documentation.wazuh.com/current/user-manual/api/securing-api.html

[^81]: https://forum.opensearch.org/t/rest-api-auth-through-openid/11162

[^82]: https://documentation.wazuh.com/current/user-manual/api/getting-started.html

[^83]: https://docs.opensearch.org/docs/latest/security/access-control/authentication-tokens/

[^84]: https://documentation.wazuh.com/current/cloud-service/apis/authentication.html

[^85]: https://cloud.yandex.com/en/docs/managed-opensearch/api-ref/authentication

[^86]: https://documentation.wazuh.com/current/cloud-service/your-environment/manage-auth.html

[^87]: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/JSON-Web-tokens.html

[^88]: https://docs.goauthentik.io/integrations/services/wazuh/

[^89]: https://forum.opensearch.org/t/opensearch-jwt-authentication/10822

[^90]: https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html

[^91]: https://forum.opensearch.org/t/jwt-token-aws-opensearch/22628

[^92]: https://groups.google.com/g/wazuh/c/6IqkFzpjvNM

[^93]: https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/settings.html

[^94]: https://docs.digitalocean.com/products/databases/opensearch/how-to/reconfigure/

[^95]: https://github.com/opensearch-project/reporting/blob/main/docs/dashboards-reports/ux/OpenSearch-Dashboards-Reporting-UX-documentation.md

[^96]: https://opensearch.org/blog/feature-highlight-reporting/

[^97]: https://libraries.io/pypi/wazuh-findings-exporter

[^98]: https://github.com/quirinziessler/wazuh_findings_exporter

[^99]: https://documentation.wazuh.com/current/compliance/nist/visualization-and-dashboard.html

[^100]: https://opensearch.org/docs/2.5/dashboards/reporting

[^101]: https://eugenio-chaves.github.io/blog/2022/wazuh-api-packages-en-us/

[^102]: https://opster.com/guides/opensearch/opensearch-how-tos/reporting-in-opensearch/

[^103]: https://wazuh.com/blog/wazuh-scripting-made-easy/

[^104]: https://docs.opensearch.org/docs/latest/reporting/report-dashboard-index/

[^105]: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html

[^106]: https://www.bookstack.cn/read/opensearch-2.18-en/79e83622647c4c3e.md

[^107]: https://forum.opensearch.org/t/programmatically-download-scheduled-reports/6323

[^108]: https://github.com/TridentStack/wazuh-docker-secure

[^109]: https://docs.opensearch.org/docs/latest/reporting/rep-cli-index/

[^110]: https://github.com/FortnoxAB/opensearch-csv-exporter

[^111]: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/dashboards.html

[^112]: https://wazuh.com/blog/auto-scalable-wazuh-cluster-with-docker-compose/

[^113]: https://opensearch.org/docs/latest/getting-started/communicate/

[^114]: https://github.com/opensearch-project/reporting/blob/main/docs/dashboards-reports/dev/OpenSearch-Dashboards-Reporting-Design-Proposal.md

[^115]: https://docs.opensearch.org/docs/latest/getting-started/communicate/

[^116]: https://stackoverflow.com/questions/18892560/is-there-any-way-in-elasticsearch-to-get-results-as-csv-file-in-curl-api

[^117]: https://documentation.wazuh.com/current/deployment-options/docker/container-usage.html

[^118]: https://forum.opensearch.org/t/how-to-use-curl-to-export-dashboard-objects/20580

[^119]: https://www.reddit.com/r/docker/comments/1d3ei4c/difficulties_scheduling_cronjob_in_docker/

[^120]: https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/5a3411ce3cc74dd912cabda17bee3a0f/899bb8e6-b157-4b86-9a88-88e1bc6f9419/6f3d7cd1.py

[^121]: https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/5a3411ce3cc74dd912cabda17bee3a0f/899bb8e6-b157-4b86-9a88-88e1bc6f9419/b3356305.md

[^122]: https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/5a3411ce3cc74dd912cabda17bee3a0f/899bb8e6-b157-4b86-9a88-88e1bc6f9419/2bf4676d.md

[^123]: https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/5a3411ce3cc74dd912cabda17bee3a0f/508a96e0-8186-4011-939b-a9f1b5b8c68f/4d7c51b1.txt

[^124]: https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/5a3411ce3cc74dd912cabda17bee3a0f/508a96e0-8186-4011-939b-a9f1b5b8c68f/6f9d41d0.sh

[^125]: https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/5a3411ce3cc74dd912cabda17bee3a0f/508a96e0-8186-4011-939b-a9f1b5b8c68f/4661d59a.yml

[^126]: https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/5a3411ce3cc74dd912cabda17bee3a0f/508a96e0-8186-4011-939b-a9f1b5b8c68f/4b76935a.md

[^127]: https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/5a3411ce3cc74dd912cabda17bee3a0f/508a96e0-8186-4011-939b-a9f1b5b8c68f/dd2c0eb6

[^128]: https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/5a3411ce3cc74dd912cabda17bee3a0f/508a96e0-8186-4011-939b-a9f1b5b8c68f/749e06f6.template

[^129]: https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/5a3411ce3cc74dd912cabda17bee3a0f/3aea78f3-e07f-47c1-9766-55cc8ed5a4de/37ffab79.py

