#!/usr/bin/env python3
"""
Wazuh Automated CSV Report Generator and Slack Sender
This script automates the generation of CSV reports from Wazuh and sends them to Slack
"""
import requests
import json
import csv
import os
import datetime
from base64 import b64encode
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhReportAutomator:
    def __init__(self, config):
        self.wazuh_api_url = config['wazuh_api_url']
        self.wazuh_username = config['wazuh_username']
        self.wazuh_password = config['wazuh_password']
        self.opensearch_url = config['opensearch_url']
        self.opensearch_username = config['opensearch_username']
        self.opensearch_password = config['opensearch_password']
        self.slack_token = config['slack_token']
        self.slack_channel = config['slack_channel']
        self.saved_search_id = config['saved_search_id']
        self.report_title = config['report_title']

    def get_wazuh_token(self):
        """Authenticate with Wazuh API and get JWT token"""
        auth_url = f"{self.wazuh_api_url}/security/user/authenticate"

        try:
            response = requests.post(
                auth_url,
                auth=(self.wazuh_username, self.wazuh_password),
                verify=False,
                params={'raw': 'true'}
            )
            response.raise_for_status()
            return response.text.strip()
        except requests.exceptions.RequestException as e:
            print(f"Error authenticating with Wazuh API: {e}")
            return None

    def generate_csv_report(self):
        """Generate CSV report using OpenSearch/Wazuh indexer"""
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic {b64encode(f"{self.opensearch_username}:{self.opensearch_password}".encode()).decode()}'
        }

        # Get current date for yesterday's data
        yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
        from_date = yesterday.strftime('%Y-%m-%dT00:00:00')
        to_date = yesterday.strftime('%Y-%m-%dT23:59:59')

        # OpenSearch query to get alert data
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": from_date,
                                    "lte": to_date
                                }
                            }
                        }
                    ]
                }
            },
            "size": 10000,
            "_source": [
                "data.srcip",
                "GeoLocation.country_name", 
                "data.id",
                "data.protocol",
                "data.url",
                "data.browser",
                "full_log",
                "agent.ip",
                "agent.name",
                "rule.id",
                "rule.level",
                "rule.mitre.id",
                "rule.description",
                "rule.mitre.technique"
            ]
        }

        try:
            response = requests.post(
                f"{self.opensearch_url}/wazuh-alerts-*/_search",
                headers=headers,
                json=query,
                verify=False
            )
            response.raise_for_status()

            data = response.json()
            hits = data.get('hits', {}).get('hits', [])

            # Generate CSV file
            filename = f"{self.report_title}_{yesterday.strftime('%Y-%m-%d')}.csv"

            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                if hits:
                    # Get field names from first hit
                    first_hit = hits[0]['_source']
                    fieldnames = self._flatten_keys(first_hit)

                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()

                    for hit in hits:
                        flattened_row = self._flatten_dict(hit['_source'])
                        writer.writerow(flattened_row)
                else:
                    # Create empty CSV with headers
                    fieldnames = [
                        'data.srcip', 'GeoLocation.country_name', 'data.id',
                        'data.protocol', 'data.url', 'data.browser', 'full_log',
                        'agent.ip', 'agent.name', 'rule.id', 'rule.level',
                        'rule.mitre.id', 'rule.description', 'rule.mitre.technique'
                    ]
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()

            print(f"CSV report generated: {filename} with {len(hits)} records")
            return filename

        except requests.exceptions.RequestException as e:
            print(f"Error generating CSV report: {e}")
            return None

    def _flatten_dict(self, d, parent_key='', sep='.'):
        """Flatten nested dictionary for CSV output"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Convert list to string representation
                items.append((new_key, ', '.join(map(str, v)) if v else ''))
            else:
                items.append((new_key, v))
        return dict(items)

    def _flatten_keys(self, d, parent_key='', sep='.'):
        """Get flattened keys from nested dictionary"""
        keys = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                keys.extend(self._flatten_keys(v, new_key, sep=sep))
            else:
                keys.append(new_key)
        return keys

    def send_to_slack(self, filename):
        """Send CSV file to Slack channel"""
        if not os.path.exists(filename):
            print(f"File {filename} not found")
            return False

        # Upload file to Slack
        url = "https://slack.com/api/files.upload"

        with open(filename, 'rb') as file:
            files = {'file': file}
            data = {
                'token': self.slack_token,
                'channels': self.slack_channel,
                'filename': filename,
                'title': f"Daily Wazuh Alert Report - {datetime.datetime.now().strftime('%Y-%m-%d')}",
                'initial_comment': f"📊 Daily security alert report generated from Wazuh\n📅 Report Date: {datetime.datetime.now().strftime('%Y-%m-%d')}\n📁 File: {filename}"
            }

            try:
                response = requests.post(url, files=files, data=data)
                response.raise_for_status()

                result = response.json()
                if result.get('ok'):
                    print(f"File {filename} successfully sent to Slack channel {self.slack_channel}")
                    return True
                else:
                    print(f"Error sending file to Slack: {result.get('error', 'Unknown error')}")
                    return False

            except requests.exceptions.RequestException as e:
                print(f"Error sending file to Slack: {e}")
                return False

    def cleanup_file(self, filename):
        """Remove the CSV file after sending"""
        try:
            if os.path.exists(filename):
                os.remove(filename)
                print(f"Cleaned up file: {filename}")
        except OSError as e:
            print(f"Error cleaning up file {filename}: {e}")

    def run_daily_report(self):
        """Main method to run the daily report generation and sending"""
        print(f"Starting daily Wazuh report generation at {datetime.datetime.now()}")

        # Generate CSV report
        filename = self.generate_csv_report()
        if not filename:
            print("Failed to generate CSV report")
            return False

        # Send to Slack
        if self.send_to_slack(filename):
            print("Report successfully sent to Slack")
            self.cleanup_file(filename)
            return True
        else:
            print("Failed to send report to Slack")
            return False

# Configuration template
config_template = {
    'wazuh_api_url': 'https://localhost:55000',
    'wazuh_username': 'wazuh',
    'wazuh_password': 'your_wazuh_password',
    'opensearch_url': 'https://localhost:9200',
    'opensearch_username': 'admin',
    'opensearch_password': 'your_opensearch_password',
    'slack_token': 'xoxb-your-slack-bot-token',
    'slack_channel': '#security-alerts',
    'saved_search_id': 'your_saved_search_id',
    'report_title': 'wazuh_daily_alerts'
}

if __name__ == "__main__":
    # Load configuration from environment variables or config file
    config = {
        'wazuh_api_url': os.getenv('WAZUH_API_URL', 'https://localhost:55000'),
        'wazuh_username': os.getenv('WAZUH_USERNAME', 'wazuh'),
        'wazuh_password': os.getenv('WAZUH_PASSWORD'),
        'opensearch_url': os.getenv('OPENSEARCH_URL', 'https://localhost:9200'),
        'opensearch_username': os.getenv('OPENSEARCH_USERNAME', 'admin'),
        'opensearch_password': os.getenv('OPENSEARCH_PASSWORD'),
        'slack_token': os.getenv('SLACK_BOT_TOKEN'),
        'slack_channel': os.getenv('SLACK_CHANNEL', '#security-alerts'),
        'saved_search_id': os.getenv('SAVED_SEARCH_ID', ''),
        'report_title': os.getenv('REPORT_TITLE', 'wazuh_daily_alerts')
    }

    # Validate required configuration
    required_fields = ['wazuh_password', 'opensearch_password', 'slack_token']
    missing_fields = [field for field in required_fields if not config.get(field)]

    if missing_fields:
        print(f"Missing required configuration: {', '.join(missing_fields)}")
        exit(1)

    # Run the automation
    automator = WazuhReportAutomator(config)
    automator.run_daily_report()
