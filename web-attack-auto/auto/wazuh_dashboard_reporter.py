#!/usr/bin/env python3

import requests
import json
import os
import time
import datetime
import logging
from base64 import b64encode
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

class WazuhDashboardReporter:
    def __init__(self, config):
        self.dashboard_url = config['dashboard_url']
        self.username = config['username']
        self.password = config['password']
        self.slack_token = config['slack_token']
        self.slack_channel = config['slack_channel']
        self.saved_search_id = config['saved_search_id']
        self.session = requests.Session()
        self.session.verify = False
        
        # Basic Auth Header
        auth_str = f"{self.username}:{self.password}"
        auth_bytes = b64encode(auth_str.encode()).decode()
        self.headers = {
            "Authorization": f"Basic {auth_bytes}",
            "kbn-xsrf": "true",
            "securitytenant": "global",
            "Content-Type": "application/json"
        }

    def authenticate_dashboard(self):
        """Ping the dashboard to confirm credentials work"""
        try:
            resp = self.session.get(f"{self.dashboard_url}/api/status", headers=self.headers)
            if resp.status_code == 200:
                logging.info("Authenticated with Wazuh Dashboard")
                return True
            else:
                logging.error(f"Auth failed: {resp.status_code}")
                return False
        except Exception as e:
            logging.error(f"Error during auth: {e}")
            return False

    def create_report_definition(self):
        """Create a report definition from saved search"""
        url = f"{self.dashboard_url}/api/reporting/report-definition"
        payload = {
            "report_params": {
                "report_name": f"Daily Report {datetime.datetime.now().strftime('%Y-%m-%d')}",
                "report_source": "saved_search",
                "description": "Automated daily security report",
                "core_params": {
                    "base_url": f"{self.dashboard_url}",
                    "saved_search_id": self.saved_search_id,
                    "time_from": "now-24h",
                    "time_to": "now"
                }
            },
            "delivery": {
                "delivery_type": "download",
                "delivery_params": {}
            },
            "trigger": {
                "trigger_type": "on_demand"
            }
        }
        
        try:
            resp = self.session.post(url, headers=self.headers, json=payload)
            resp.raise_for_status()
            report_def_id = resp.json().get("report_definition", {}).get("id")
            logging.info(f"Created report definition: ID {report_def_id}")
            return report_def_id
        except Exception as e:
            logging.error(f"Failed to create report definition: {e}")
            # Try alternative API endpoint
            return self.create_report_definition_alt()

    def create_report_definition_alt(self):
        """Alternative method to create report from saved search"""
        url = f"{self.dashboard_url}/api/saved_objects/_export"
        payload = {
            "type": "search",
            "objects": [{"id": self.saved_search_id, "type": "search"}]
        }
        
        try:
            resp = self.session.post(url, headers=self.headers, json=payload)
            if resp.status_code == 200:
                logging.info(f"Using saved search ID directly: {self.saved_search_id}")
                return self.saved_search_id
            else:
                logging.error(f"Failed to validate saved search: {resp.status_code}")
                return None
        except Exception as e:
            logging.error(f"Error validating saved search: {e}")
            return None

    def generate_report(self, report_def_id):
        """Generate report from saved search or report definition"""
        # Try modern reporting API first
        url = f"{self.dashboard_url}/api/reporting/generate/csv"
        payload = {
            "searchSource": {
                "query": {"match_all": {}},
                "index": self.saved_search_id if report_def_id == self.saved_search_id else None
            },
            "timerange": {
                "from": "now-24h",
                "to": "now"
            }
        }
        
        try:
            resp = self.session.post(url, headers=self.headers, json=payload)
            if resp.status_code in [200, 201]:
                report_data = resp.json()
                report_id = report_data.get("job", {}).get("id") or report_data.get("id")
                logging.info(f"Report generation started: ID {report_id}")
                return report_id
        except Exception as e:
            logging.warning(f"Modern API failed, trying legacy: {e}")
        
        # Fallback to legacy API
        return self.generate_report_legacy(report_def_id)

    def generate_report_legacy(self, report_def_id):
        """Legacy method to generate CSV report"""
        url = f"{self.dashboard_url}/api/reporting/generate"
        payload = {
            "reportDefinitionId": report_def_id,
            "format": "csv"
        }
        
        try:
            resp = self.session.post(url, headers=self.headers, json=payload)
            resp.raise_for_status()
            report_id = resp.json().get("reportInstance", {}).get("id")
            logging.info(f"Legacy report generation started: ID {report_id}")
            return report_id
        except Exception as e:
            logging.error(f"Legacy report generation failed: {e}")
            return None

    def wait_for_report_completion(self, report_id, timeout=300):
        """Wait for report to complete generation"""
        url = f"{self.dashboard_url}/api/reporting/report/{report_id}"
        start = time.time()
        
        while time.time() - start < timeout:
            resp = self.session.get(url, headers=self.headers)
            if resp.status_code == 200:
                status = resp.json().get("data", {}).get("status")
                logging.info(f"Status: {status}")
                if status == "completed":
                    return True
                elif status in ["failed", "error"]:
                    return False
                time.sleep(5)
            else:
                logging.error(f"Status check failed: {resp.status_code}")
                time.sleep(5)
        
        logging.error("Timeout reached.")
        return False

    def download_report(self, report_id):
        """Download the generated report"""
        url = f"{self.dashboard_url}/api/reporting/report/{report_id}/download"
        resp = self.session.get(url, headers=self.headers)
        if resp.status_code == 200:
            filename = f"wazuh_report_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
            with open(filename, "wb") as f:
                f.write(resp.content)
            logging.info(f"Downloaded report to: {filename}")
            return filename
        else:
            logging.error(f"Failed to download: {resp.status_code}")
            return None

    def send_to_slack(self, filename):
        """Send CSV file to Slack channel"""
        if not os.path.exists(filename):
            logging.error(f"File {filename} not found")
            return False

        url = "https://slack.com/api/files.upload"

        with open(filename, 'rb') as file:
            files = {'file': file}
            data = {
                'token': self.slack_token,
                'channels': self.slack_channel,
                'filename': filename,
                'title': f"Daily Wazuh Alert Report - {datetime.datetime.now().strftime('%Y-%m-%d')}",
                'initial_comment': f"📊 Daily security alert report from Wazuh Dashboard\n📅 Report Date: {datetime.datetime.now().strftime('%Y-%m-%d')}\n📁 File: {filename}"
            }

            try:
                response = requests.post(url, files=files, data=data)
                response.raise_for_status()

                result = response.json()
                if result.get('ok'):
                    logging.info(f"Successfully sent {filename} to Slack channel {self.slack_channel}")
                    return True
                else:
                    logging.error(f"Slack API error: {result.get('error', 'Unknown error')}")
                    return False

            except requests.exceptions.RequestException as e:
                logging.error(f"Error sending file to Slack: {e}")
                return False

    def cleanup_file(self, filename):
        """Remove the CSV file after sending"""
        try:
            if os.path.exists(filename):
                os.remove(filename)
                logging.info(f"Cleaned up file: {filename}")
        except OSError as e:
            logging.error(f"Error cleaning up file {filename}: {e}")

    def run_automated_report(self):
        """Main method to run the automated reporting process"""
        logging.info(f"Starting Wazuh Dashboard automated reporting at {datetime.datetime.now()}")

        if not self.authenticate_dashboard():
            logging.error("Authentication failed, aborting")
            return False

        report_def_id = self.create_report_definition()
        if not report_def_id:
            logging.error("Failed to create report definition")
            return False

        report_instance_id = self.generate_report(report_def_id)
        if not report_instance_id:
            logging.error("Failed to generate report")
            return False

        if not self.wait_for_report_completion(report_instance_id):
            logging.error("Report generation failed or timed out")
            return False

        filename = self.download_report(report_instance_id)
        if not filename:
            logging.error("Failed to download report")
            return False

        if self.send_to_slack(filename):
            logging.info("Report successfully sent to Slack")
            self.cleanup_file(filename)
            return True
        else:
            logging.error("Failed to send report to Slack")
            return False

# Configuration
if __name__ == "__main__":
    config = {
        'dashboard_url': os.getenv('WAZUH_DASHBOARD_URL', 'https://localhost:443'),
        'username': os.getenv('WAZUH_DASHBOARD_USER', 'admin'),
        'password': os.getenv('WAZUH_DASHBOARD_PASSWORD'),
        'slack_token': os.getenv('SLACK_BOT_TOKEN'),
        'slack_channel': os.getenv('SLACK_CHANNEL', '#security-alerts'),
        'saved_search_id': os.getenv('SAVED_SEARCH_ID', '')
    }

    required_fields = ['password', 'slack_token', 'saved_search_id']
    missing_fields = [field for field in required_fields if not config.get(field)]

    if missing_fields:
        logging.error(f"Missing required configuration: {', '.join(missing_fields)}")
        logging.error("Required environment variables:")
        logging.error("- WAZUH_DASHBOARD_PASSWORD")
        logging.error("- SLACK_BOT_TOKEN")
        logging.error("- SAVED_SEARCH_ID")
        exit(1)

    reporter = WazuhDashboardReporter(config)
    success = reporter.run_automated_report()

    if success:
        logging.info("Automated reporting completed successfully")
        exit(0)
    else:
        logging.error("Automated reporting failed")
        exit(1)
