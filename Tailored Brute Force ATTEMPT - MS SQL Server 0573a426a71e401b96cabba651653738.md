# Tailored: Brute Force ATTEMPT - MS SQL Server

**Incident Description**

- This incident involves log on failed attempts.

KQL

```
// Brute Force Attempt MS SQL Server
let IpAddress_REGEX_PATTERN = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";
Event
| where EventLog == "Application"
| where EventID == 18456
| where TimeGenerated > ago(1hr)
| project TimeGenerated, AttackerIP = extract(IpAddress_REGEX_PATTERN, 0, RenderedDescription), DestinationHostName = Computer, RenderedDescription
| summarize FailureCount = count() by AttackerIP, DestinationHostName
| where FailureCount >= 3
```

**Tactics and Techniques: Credential Access**

- [Brute Force, Technique T1110 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1110/)

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Check the IP address from the alert to see if it’s malicious or not.

**Containment and Recovery**

- Block the IPs from the Firewall Inbound Rules.