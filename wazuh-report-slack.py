import requests
import datetime
import csv
import os
import requests, datetime, csv, os, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Wazuh API Configuration
WAZUH_API = "https://20.2.200.176:55000"
USERNAME = "wazuh"
PASSWORD = "wazuh"
VERIFY_TLS = False

# use Basic auth header
login_url = f"{WAZUH_API}/security/user/authenticate?raw=true"
resp = requests.post(login_url, auth=(USERNAME, PASSWORD), verify=VERIFY_TLS)
if resp.status_code != 200:
    print(resp.status_code, resp.text)
    exit(1)
token = resp.text.strip()


# Slack Configuration
SLACK_TOKEN = "xoxb-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
SLACK_CHANNEL = "#daily-wazuh-attack-report"

# Time Window (UTC-aware)
now = datetime.datetime.now(datetime.timezone.utc)
yesterday = now - datetime.timedelta(days=1)
begin = yesterday.isoformat()
end = now.isoformat()

# Authenticate to Wazuh API
auth_payload = {"username": USERNAME, "password": PASSWORD}
auth_response = requests.post(
    f"{WAZUH_API}/security/user/authenticate",
    json=auth_payload,
    verify=VERIFY_TLS
)

if auth_response.status_code != 200:
    print("AUTHENTICATION FAILED")
    print("STATUS:", auth_response.status_code)
    print("BODY:", auth_response.text)
    exit(1)

auth_data = auth_response.json()
if "data" not in auth_data or "token" not in auth_data["data"]:
    print("INVALID AUTH PAYLOAD")
    print("BODY:", auth_data)
    exit(1)

token = auth_data["data"]["token"]
headers = {"Authorization": f"Bearer {token}"}

# Query Wazuh Alerts
params = {
    "q": "rule.groups:web",
    "limit": 10000,
    "sort": "desc",
    "begin": begin,
    "end": end
}

alerts_response = requests.get(
    f"{WAZUH_API}/alerts",
    headers=headers,
    params=params,
    verify=VERIFY_TLS
)

if alerts_response.status_code != 200:
    print("ALERT QUERY FAILED")
    print("STATUS:", alerts_response.status_code)
    print("BODY:", alerts_response.text)
    exit(1)

alerts_json = alerts_response.json()
if "data" not in alerts_json or "affected_items" not in alerts_json["data"]:
    print("INVALID ALERT PAYLOAD")
    print("BODY:", alerts_json)
    exit(1)

alerts = alerts_json["data"]["affected_items"]
print(f"Retrieved {len(alerts)} alerts")

# Write to CSV
date_str = yesterday.strftime("%Y-%m-%d")
filename = f"Web_Attack_Daily_Report_{date_str}.csv"

with open(filename, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
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
    ])
    for alert in alerts:
        writer.writerow([
            alert.get("data", {}).get("srcip", ""),
            alert.get("GeoLocation", {}).get("country_name", ""),
            alert.get("data", {}).get("id", ""),
            alert.get("data", {}).get("protocol", ""),
            alert.get("data", {}).get("url", ""),
            alert.get("data", {}).get("browser", ""),
            alert.get("full_log", ""),
            alert.get("agent", {}).get("ip", ""),
            alert.get("agent", {}).get("name", ""),
            alert.get("rule", {}).get("id", ""),
            alert.get("rule", {}).get("level", ""),
            alert.get("rule", {}).get("mitre", {}).get("id", ""),
            alert.get("rule", {}).get("description", ""),
            alert.get("rule", {}).get("mitre", {}).get("technique", "")
        ])

# Upload to Slack
with open(filename, "rb") as file_data:
    slack_response = requests.post(
        url="https://slack.com/api/files.upload",
        headers={"Authorization": f"Bearer {SLACK_TOKEN}"},
        files={"file": file_data},
        data={
            "channels": SLACK_CHANNEL,
            "filename": os.path.basename(filename),
            "title": f"Wazuh Web Attack Report {date_str}"
        }
    )

if not slack_response.ok or not slack_response.json().get("ok"):
    print("SLACK UPLOAD FAILED")
    print("STATUS:", slack_response.status_code)
    print("BODY:", slack_response.text)
    exit(1)

print(f"Report uploaded and saved as {filename}")
input("Press Enter to exit...")
