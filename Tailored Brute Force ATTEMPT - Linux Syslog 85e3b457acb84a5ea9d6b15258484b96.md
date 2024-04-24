# Brute Force ATTEMPT - Linux Syslog

**Incident Description**

- This incident involves log on failed attempts.

KQL

```
// Brute Force Success Linux
let IpAddress_REGEX_PATTERN = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";
Syslog
| where Facility == "auth" and SyslogMessage startswith "Failed password for"
| where TimeGenerated > ago(1h)
| project TimeGenerated, AttackerIP = extract(IpAddress_REGEX_PATTERN, 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
| summarize FailureCount = count() by AttackerIP, DestinationHostName, DestinationIP
| where FailureCount >= 10
```

**Tactics and Techniques: Credential Access**

- [Brute Force, Technique T1110 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1110/)

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Check the IP address from the alert to see if it’s malicious or not.

**Containment and Recovery**

- Block the IPs from the Firewall Inbound Rules.
