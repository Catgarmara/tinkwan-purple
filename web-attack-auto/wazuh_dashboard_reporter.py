#!/usr/bin/env python3
"""
Wazuh Dashboard Reporting API Automation
This script uses the OpenSearch Dashboard Reporting API to generate and download CSV reports
"""
import requests
import json
import os
import time
import datetime
from base64 import b64encode
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        login_url = f"{self.dashboard_url}/auth/login"

        # Get login page to get CSRF token
        try:
            response = self.session.get(f"{self.dashboard_url}/login")

            # Try basic auth for OpenSearch Dashboard
            auth_header = b64encode(f"{self.username}:{self.password}".encode()).decode()
            self.session.headers.update({
                'Authorization': f'Basic {auth_header}',
                'Content-Type': 'application/json',
                'osd-xsrf': 'true'
            })

            # Test authentication
            health_response = self.session.get(f"{self.dashboard_url}/api/status")
            if health_response.status_code == 200:
                print("Successfully authenticated with Wazuh Dashboard")
                return True
            else:
                print(f"Authentication failed: {health_response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"Error authenticating with dashboard: {e}")
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
                    "base_url": f"{self.dashboard_url}/app/discover#/view/{self.saved_search_id}",
                    "report_format": "csv",
                    "time_duration": "PT24H",
                    "origin": "Dashboard"
                }
            },
            "delivery": {
                "delivery_type": "Download",
                "delivery_params": {}
            },
            "trigger": {
                "trigger_type": "On demand"
            }
        }

        try:
            response = self.session.post(
                f"{self.dashboard_url}/api/reporting/reportDefinition",
                json=report_def,
                headers={'osd-xsrf': 'true'}
            )

            if response.status_code in [200, 201]:
                result = response.json()
                report_definition_id = result.get('reportDefinitionId')
                print(f"Created report definition: {report_definition_id}")
                return report_definition_id
            else:
                print(f"Failed to create report definition: {response.status_code} - {response.text}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"Error creating report definition: {e}")
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
                print(f"Started report generation: {report_instance_id}")
                return report_instance_id
            else:
                print(f"Failed to generate report: {response.status_code} - {response.text}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"Error generating report: {e}")
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

                    print(f"Report status: {status}")

                    if status == 'Success':
                        print("Report generation completed successfully")
                        return True
                    elif status in ['Failed', 'Error']:
                        print(f"Report generation failed with status: {status}")
                        return False

                    # Wait before checking again
                    time.sleep(10)
                else:
                    print(f"Error checking report status: {response.status_code}")
                    time.sleep(10)

            except requests.exceptions.RequestException as e:
                print(f"Error checking report status: {e}")
                time.sleep(10)

        print("Report generation timed out")
        return False

    def download_report(self, report_instance_id):
        """Download the generated report"""
        try:
            response = self.session.get(
                f"{self.dashboard_url}/api/reporting/reportInstance/{report_instance_id}"
            )

            if response.status_code == 200:
                result = response.json()

                # Get download URL or file content
                if 'url' in result:
                    download_url = result['url']
                    download_response = self.session.get(f"{self.dashboard_url}{download_url}")
                elif 'file_data' in result:
                    download_response = self.session.get(
                        f"{self.dashboard_url}/api/reporting/reportInstance/download/{report_instance_id}"
                    )
                else:
                    print("No download URL or file data found in response")
                    return None

                if download_response.status_code == 200:
                    filename = f"wazuh_report_{datetime.datetime.now().strftime('%Y%m%d')}.csv"

                    with open(filename, 'wb') as f:
                        f.write(download_response.content)

                    print(f"Downloaded report: {filename}")
                    return filename
                else:
                    print(f"Failed to download report: {download_response.status_code}")
                    return None
            else:
                print(f"Failed to get report info: {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"Error downloading report: {e}")
            return None

    def send_to_slack(self, filename):
        """Send CSV file to Slack channel"""
        if not os.path.exists(filename):
            print(f"File {filename} not found")
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
                    print(f"Successfully sent {filename} to Slack channel {self.slack_channel}")
                    return True
                else:
                    print(f"Slack API error: {result.get('error', 'Unknown error')}")
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

    def run_automated_report(self):
        """Main method to run the automated reporting process"""
        print(f"Starting Wazuh Dashboard automated reporting at {datetime.datetime.now()}")

        # Authenticate
        if not self.authenticate_dashboard():
            print("Authentication failed, aborting")
            return False

        # Create report definition
        report_def_id = self.create_report_definition()
        if not report_def_id:
            print("Failed to create report definition")
            return False

        # Generate report
        report_instance_id = self.generate_report(report_def_id)
        if not report_instance_id:
            print("Failed to generate report")
            return False

        # Wait for completion
        if not self.wait_for_report_completion(report_instance_id):
            print("Report generation failed or timed out")
            return False

        # Download report
        filename = self.download_report(report_instance_id)
        if not filename:
            print("Failed to download report")
            return False

        # Send to Slack
        if self.send_to_slack(filename):
            print("Report successfully sent to Slack")
            self.cleanup_file(filename)
            return True
        else:
            print("Failed to send report to Slack")
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

    # Validate required configuration
    required_fields = ['password', 'slack_token', 'saved_search_id']
    missing_fields = [field for field in required_fields if not config.get(field)]

    if missing_fields:
        print(f"Missing required configuration: {', '.join(missing_fields)}")
        print("Required environment variables:")
        print("- WAZUH_DASHBOARD_PASSWORD")
        print("- SLACK_BOT_TOKEN") 
        print("- SAVED_SEARCH_ID")
        exit(1)

    # Run the automation
    reporter = WazuhDashboardReporter(config)
    success = reporter.run_automated_report()

    if success:
        print("Automated reporting completed successfully")
        exit(0)
    else:
        print("Automated reporting failed")
        exit(1)
