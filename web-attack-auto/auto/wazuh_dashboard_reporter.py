#!/usr/bin/env python3
"""
Wazuh Dashboard 4.12+ Reporting Automation Script
- Authenticates via basic auth
- Fetches a named report template
- Triggers report generation
- Polls for completion
- Downloads PDF
- Sends to Slack
"""

import requests
import os
import time
import datetime
from base64 import b64encode
import urllib3
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("/var/log/wazuh_automation.log"),
        logging.StreamHandler()
    ]
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhDashboardReporter:
    def __init__(self, config):
        self.dashboard_url = config['dashboard_url']
        self.username = config['username']
        self.password = config['password']
        self.slack_token = config['slack_token']
        self.slack_channel = config['slack_channel']
        self.template_name = config.get('template_name', 'Daily Log Summary')
        self.session = requests.Session()
        self.session.verify = False

        auth = b64encode(f"{self.username}:{self.password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {auth}",
            "kbn-xsrf": "true",
            "securitytenant": "global",
            "Content-Type": "application/json"
        }

    def authenticate_dashboard(self):
        try:
            resp = self.session.get(f"{self.dashboard_url}/api/status", headers=self.headers)
            if resp.status_code == 200:
                logging.info("Authenticated with Wazuh Dashboard")
                return True
            else:
                logging.error(f"Authentication failed: {resp.status_code}")
                return False
        except Exception as e:
            logging.exception("Error during authentication")
            return False

    def get_template_id(self):
        url = f"{self.dashboard_url}/api/reporting/templates"
        resp = self.session.get(url, headers=self.headers)
        resp.raise_for_status()
        for t in resp.json().get("data", []):
            if t.get("name") == self.template_name:
                logging.info(f"Found template '{self.template_name}' with ID {t['id']}")
                return t["id"]
        raise ValueError(f"Template '{self.template_name}' not found")

    def generate_report(self, template_id):
        url = f"{self.dashboard_url}/api/reporting/report"
        payload = {
            "templateId": template_id,
            "timeRange": {
                "from": "now-24h",
                "to": "now"
            }
        }
        resp = self.session.post(url, headers=self.headers, json=payload)
        resp.raise_for_status()
        report_id = resp.json().get("data", {}).get("id")
        logging.info(f"Report generation started: ID {report_id}")
        return report_id

    def wait_for_report_completion(self, report_id, timeout=300):
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
                logging.warning(f"Status check failed: {resp.status_code}")
                time.sleep(5)

        logging.error("Timeout reached while waiting for report completion")
        return False

    def download_report(self, report_id):
        url = f"{self.dashboard_url}/api/reporting/report/{report_id}/download"
        resp = self.session.get(url, headers=self.headers)
        if resp.status_code == 200:
            filename = f"wazuh_report_{datetime.datetime.now().strftime('%Y%m%d')}.pdf"
            with open(filename, "wb") as f:
                f.write(resp.content)
            logging.info(f"Downloaded report: {filename}")
            return filename
        else:
            logging.error(f"Download failed: {resp.status_code}")
            return None

    def send_to_slack(self, filename):
        if not os.path.exists(filename):
            logging.error(f"File not found: {filename}")
            return False

        url = "https://slack.com/api/files.upload"
        with open(filename, 'rb') as file:
            files = {'file': file}
            data = {
                'token': self.slack_token,
                'channels': self.slack_channel,
                'filename': filename,
                'title': f"Wazuh Report {datetime.datetime.now().strftime('%Y-%m-%d')}",
                'initial_comment': "Daily Wazuh Report attached."
            }

            try:
                response = requests.post(url, files=files, data=data)
                if response.ok and response.json().get("ok"):
                    logging.info("Report uploaded to Slack")
                    return True
                else:
                    logging.error("Slack upload failed")
                    return False
            except Exception as e:
                logging.exception("Slack error")
                return False

    def cleanup_file(self, filename):
        try:
            os.remove(filename)
            logging.info(f"Cleaned up {filename}")
        except Exception as e:
            logging.exception(f"Cleanup error for {filename}")

    def run_automated_report(self):
        logging.info(f"Starting Wazuh Dashboard automated reporting at {datetime.datetime.now()}")
        
        if not self.authenticate_dashboard():
            logging.error("Authentication failed, aborting")
            return False
        
        try:
            template_id = self.get_template_id()
            report_id = self.generate_report(template_id)
            
            if not self.wait_for_report_completion(report_id):
                logging.error("Report generation failed or timed out")
                return False
            
            filename = self.download_report(report_id)
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
                
        except Exception as e:
            logging.exception("Unexpected error in run_automated_report")
            return False

if __name__ == "__main__":
    config = {
        'dashboard_url': os.getenv('WAZUH_DASHBOARD_URL', 'https://localhost:5601'),
        'username': os.getenv('WAZUH_DASHBOARD_USER', 'admin'),
        'password': os.getenv('WAZUH_DASHBOARD_PASSWORD'),
        'slack_token': os.getenv('SLACK_BOT_TOKEN'),
        'slack_channel': os.getenv('SLACK_CHANNEL', '#security-alerts'),
        'template_name': os.getenv('TEMPLATE_NAME', 'Daily Log Summary')
    }

    required = ['password', 'slack_token', 'template_name']
    missing = [k for k in required if not config.get(k)]
    if missing:
        logging.error(f"Missing config vars: {', '.join(missing)}")
        exit(1)

    reporter = WazuhDashboardReporter(config)
    if reporter.run_automated_report():
        logging.info("Report automation successful")
    else:
        logging.error("Report automation failed")
        exit(1)
