# explain decoder to a kid
## use https://regex101.com/ for initial log analyst 

Example Block from official doc

```XML
<var name="header">myprog</var>
<var name="offset">after_parent</var>
<var name="type">syscall</var>

<decoder name="syscall">
  <prematch>^$header</prematch>
</decoder>

<decoder name="syscall-child">
  <parent>syscall</parent>
  <prematch offset="$offset">^: $type </prematch>
  <regex offset="after_prematch">(\S+)</regex>
  <order>syscall</order>
</decoder>
```
Decoders are like translators: They take messy log entries (e.g., 192.168.1.10 - - [14/Jul/2024:10:00:00 +0000] "GET /test HTTP/1.1" 200 1234...) and break them into labeled fields like IP address, timestamp, or browser type.
Without decoders, Wazuh can't understand your logs or detect threats.

# My take
Three key part:<prematch><regex><order>
```XML
<decoder name="mydeco">
  <prematch>- INFO-</prematch> <!-- prefilter to capture relevant log -->
  <regex>(\S+) (\S+):(\S+)</regex> <!-- regex to extract feild -->
  <order>path, srcip, usragent</order> <!-- fields name -->
</decoder>
```
# Scenario1
inbound raw log
ALERT - Login failed from 192.168.1.5 using Firefox
Goal: extract IP and  Browser

```xml
<decoder name="longin_alert">
  <prematch>ALERT - Login failed</prematch>
  <regex>from (\d+\.\d+\.\d+\.\d+) using (\w+)</regex>
  <order>srcip, browser</order>
</decoder>
```
prematch capture log with 'ALERT - Login failed'
regex (\d+\.\d+\.\d+\.\d+) = ipv4
      (\w+) = browser type

# Testing the decoder
1. var/ossec/etc/decoders/custom_decoders.xml
2. run log tester
   /var/ossec/bin/wazuh-logtest

# common pitfalls and  fixes
<regex> too strict
  fix: use .*? to  skip variable text

```xml
<regex>from (.*?) using (.*?)</regex>
```
debug
no  match fix: check for spaces and special charaters in logs
syntax error: use validator online https://www.xmlvalidation.com/

# leveling up
## Dynamic decoder
  multi-line logs or JSON data https://documentation.wazuh.com/current/user-manual/ruleset/decoders/index.html
  pre-decoding
```xml
<decoder name="predecode">
  <timestamp>%Y-%m-%dT%h:%M:%S</timestamp>
  <hostname>example-server</hostname>
</decoder>
```

## Parent-child decoders

log: Starting process HTTP
<decoder name="parent">
  <prematch>Starting process</prematch>
</decoder>
<decoder name"child">
  <parent>parent</parent>
  <regex>PID: (\d+)</regex>
  <order>pid</order>
</decoder>

# Log Example:
[2024-07-15 10:00:00] ALERT: User 'admin' logged in from 192.168.1.10

<decoder name="Alert log">
  <prematch>ALERT: User </prematch>
  <regex>User '(\w+)' logged in from (\d+\.\d+\.\d+\.d+)</regex>
  <order>username, srcip</order>
</decoder>

# all elements
<decoder name="my_decoder">
  <program_name>sshd</program_name>                     <!-- Only logs from sshd -->
  <prematch>ALERT</prematch>                            <!-- Only logs containing ALERT -->
  <regex>User (\w+) from (\d+\.\d+\.\d+\.\d+)</regex>   <!-- Extract username and IP -->
  <order>username, srcip</order>                        <!-- Name the captured fields -->
  <type>json</type>                                     <!-- (If parsing JSON logs) -->
  <offset>after_prematch</offset>                       <!-- Start matching after prematch -->
</decoder>

<!-- Example of parent/child (chaining) -->
<decoder name="child_decoder">
  <parent>my_decoder</parent>
  <regex>failed with code (\d+)</regex>
  <order>error_code</order>
</decoder>

REAL DEBUGGING SCENARIO: July 2025

Problem: Custom decoder matched correctly in wazuh-logtest, but alerts didn’t show in Kibana Discover
Cause: The decoder was capturing timestamp in a format that was not ISO8601
Result: Alert was generated and indexed, but not visible in Discover (time-range broken)
Fix: Remove timestamp capture from decoder regex. Let Wazuh auto-assign timestamp.
✅ After that, alerts showed up properly in Kibana

<!-- Bad (timestamp captured in wrong format) -->
<regex>^(\S+) - - \[(\S+)...
<order>srcip, timestamp,...</order>

<!-- Good (no timestamp capture) -->
<regex>^(\S+) - - \[\S+... <!-- timestamp is there but not captured -->
<order>srcip, ...</order>

Lesson: Only capture timestamps if you're sure your regex matches a standard format like 2025-07-01T14:00:00Z. Otherwise, skip capturing — Wazuh will use log ingestion time.

---

# Wazuh Custom NGINX Access Log Decoder Notes

## Goal
To build a custom decoder chain for NGINX access logs that includes:
- Full user-agent string
- Request URI
- Status code
- Response size
- Optional timestamp (ISO 8601 if captured)
- Prevent fallback to default `web-accesslog`

## Environment
- Wazuh Manager: Dockerized (4.7+)
- Filebeat: Internal to Wazuh container
- Logs ingested via `filebeat.modules: wazuh.alerts`

## Key Problem
Default decoder `0375-web-accesslog_decoders.xml` fails to extract sufficient fields like browser or full URL path. It also truncates complex logs. Custom decoder is needed.

## Steps Taken

### 1. Disabled Default Decoder
```xml
<ruleset>
  <decoder_exclude>ruleset/decoders/0375-web-accesslog_decoders.xml</decoder_exclude>
</ruleset>
```

### 2. Created Custom Decoder File
Placed in:
```
/var/ossec/etc/decoders/0375-web-accesslog_decoders.xml
```

### 3. Decoder Chain
```xml
<decoder name="web-accesslog-test">
  <type>web-log</type>
  <program_name>nginx|apache</program_name>
</decoder>

<decoder name="web-accesslog-test">
  <type>web-log</type>
  <prematch>^\S+ \S+ \S+ \[.*\] \"\w+ \S+ HTTP/\S+\" </prematch>
</decoder>

<decoder name="web-accesslog-domain-test">
  <type>web-log</type>
  <parent>web-accesslog-test</parent>
  <regex>^(\S+) \S+ \S+ \[.*\] "(\w+) (\S+) HTTP/(\S+)" (\d+) (\S+) "(.*?)" "(.*?)".*</regex>
  <order>srcip, protocol, url, http_version, id, rsize, rcode, browser</order>
</decoder>
```

### 4. Regex Debug Notes
- Wazuh **does not require escaping square brackets** in `regex` or `prematch`.
- Use `\[` only in contexts where regex expects literal matching via POSIX.
- **Do not try to capture timestamps** unless formatted in ISO 8601 (`YYYY-MM-DDTHH:MM:SSZ`) or explicitly normalized.

### 5. Common Pitfalls
- Capturing timestamps in `DD/Mon/YYYY:HH:MM:SS +ZZZZ` format breaks Discover index.
- Kibana Discover tab **requires a valid `@timestamp`**.
- Wazuh can insert it automatically if not captured — safest default.
- Regex syntax error in any `<regex>` will silently fall back to parent decoder.

### 6. Test Method
Used `wazuh-logtest`:
```bash
/var/ossec/bin/wazuh-logtest
```

Sample log:
```
81.179.122.118 - - [03/Jul/2025:10:32:00 +0000] "GET /please-work HTTP/1.1" 404 10 "-" "Mozilla/5.0..."
```

Confirmed fields:
- srcip
- protocol
- url
- http_version
- id (status code)
- rsize
- rcode (referrer placeholder)
- browser

### 7. Result
Decoder chain is working. Logs are parsed. Alerts trigger rule `31101`. Alerts visible in Kibana Discover after removing timestamp capture.

---

To improve further, implement:
- Sigma rules mapping
- Rule pack for URI + browser-based threat detection
- Extended GeoIP field tagging






