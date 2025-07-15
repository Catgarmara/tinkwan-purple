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

    def authenticate_dashboard(self):
        """Authenticate with Wazuh Dashboard"""
        login_url = f"{self.dashboard_url}/app/login"

        try:
            response = self.session.get(f"{self.dashboard_url}/login")

            auth_header = b64encode(f"{self.username}:{self.password}".encode()).decode()
            self.session.headers.update({
                'Authorization': f'Basic {auth_header}',
                'Content-Type': 'application/json',
                'osd-xsrf': 'true'
            })

            health_response = self.session.get(f"{self.dashboard_url}/api/status")
            if health_response.status_code == 200:
                logging.info("Successfully authenticated with Wazuh Dashboard")
                return True
            else:
                logging.error(f"Authentication failed: {health_response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            logging.error(f"Error authenticating with dashboard: {e}")
            return False

    def create_report_definition(self):
        """Create a report definition for the saved search"""
        yesterday = datetime.datetime.now() - datetime.timedelta(days=1)

        report_def = {
            "report_params": {
                "report_name": f"Daily_Wazuh_Report_{yesterday.strftime('%Y%m%d')}",
                "report_source": "Saved search",
                "description": f"Automated daily report for {yesterday.strftime('%Y-%m-%d')}",
                "core_params": {
                    "base_url": f"/app/discover#/view/{self.saved_search_id}",
                    "saved_search_id": self.saved_search_id,
                    "report_format": "csv",
                    "time_duration": "PT24H",
                    "origin": "Dashboard"
                }
            },
            "delivery": {
                "delivery_type": "Download",
                "delivery_params": {},
                "config_ids": [],
                "title": f"Daily Wazuh Report - {yesterday.strftime('%Y-%m-%d')}",
                "text_description": "Daily web attack reports from dashboard",
                "html_description": "<p>Automated daily download of Wazuh alerts</p>"
            },
            "trigger": {
                "trigger_type": "On demand"
            }
        }

        try:
            logging.debug("Report definition payload:\n", json.dumps(report_def, indent=2))
            response = self.session.post(
                f"{self.dashboard_url}/api/reporting/reportDefinition",
                json=report_def,
                headers={'osd-xsrf': 'true'}
            )

            if response.status_code in [200, 201]:
                result = response.json()
                report_definition_id = result.get('reportDefinitionId')
                logging.info(f"Created report definition: {report_definition_id}")
                return report_definition_id
            else:
                logging.error(f"Failed to create report definition: {response.status_code} - {response.text}")
                return None

        except requests.exceptions.RequestException as e:
            logging.error(f"Error creating report definition: {e}")
            return None

    def generate_report(self, report_definition_id):
        """Generate report from definition"""
        try:
            response = self.session.post(
                f"{self.dashboard_url}/api/reporting/generateReport/{report_definition_id}",
                headers={'osd-xsrf': 'true'}
            )

            if response.status_code in [200, 201]:
                result = response.json()
                report_instance_id = result.get('reportInstanceId')
                logging.info(f"Started report generation: {report_instance_id}")
                return report_instance_id
            else:
                logging.error(f"Failed to generate report: {response.status_code} - {response.text}")
                return None

        except requests.exceptions.RequestException as e:
            logging.error(f"Error generating report: {e}")
            return None

    def wait_for_report_completion(self, report_instance_id, max_wait=300):
        """Wait for report to complete generation"""
        start_time = time.time()

        while time.time() - start_time < max_wait:
            try:
                response = self.session.get(
                    f"{self.dashboard_url}/api/reporting/reportInstance/{report_instance_id}"
                )

                if response.status_code == 200:
                    result = response.json()
                    status = result.get('state')

                    logging.debug(f"Report status: {status}")

                    if status == 'Success':
                        logging.info("Report generation completed successfully")
                        return True
                    elif status in ['Failed', 'Error']:
                        logging.error(f"Report generation failed with status: {status}")
                        return False

                    time.sleep(10)
                else:
                    logging.error(f"Error checking report status: {response.status_code}")
                    time.sleep(10)

            except requests.exceptions.RequestException as e:
                logging.error(f"Error checking report status: {e}")
                time.sleep(10)

        logging.error("Report generation timed out")
        return False

    def download_report(self, report_instance_id):
        """Download the generated report"""
        try:
            response = self.session.get(
                f"{self.dashboard_url}/api/reporting/reportInstance/{report_instance_id}"
            )

            if response.status_code == 200:
                result = response.json()

                if 'url' in result:
                    download_url = result['url']
                    download_response = self.session.get(f"{self.dashboard_url}{download_url}")
                elif 'file_data' in result:
                    download_response = self.session.get(
                        f"{self.dashboard_url}/api/reporting/reportInstance/download/{report_instance_id}"
                    )
                else:
                    logging.error("No download URL or file data found in response")
                    return None

                if download_response.status_code == 200:
                    filename = f"wazuh_report_{datetime.datetime.now().strftime('%Y%m%d')}.csv"

                    with open(filename, 'wb') as f:
                        f.write(download_response.content)

                    logging.info(f"Downloaded report: {filename}")
                    return filename
                else:
                    logging.error(f"Failed to download report: {download_response.status_code}")
                    return None
            else:
                logging.error(f"Failed to get report info: {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            logging.error(f"Error downloading report: {e}")
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
