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










