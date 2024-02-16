# Tailored: Brute Force SUCCESS - Linux Syslog

**Incident Description**

- This incident involves observation of potential brute force attempts against a Linux VM.

**KQL**

```
// Brute Force Success Linux
let FailedLogons = Syslog
| where Facility == "auth" and SyslogMessage startswith "Failed password for"
| where TimeGenerated > ago(1h)
| project TimeGenerated, SourceIP = extract(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
| summarize FailureCount = count() by AttackerIP = SourceIP, DestinationHostName
| where FailureCount >= 5;
let SuccessfulLogons = Syslog
| where Facility == "auth" and SyslogMessage startswith "Accepted password for"
| where TimeGenerated > ago(1h)
| project TimeGenerated, SourceIP = extract(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
| summarize SuccessfulCount = count() by SuccessTime = TimeGenerated, AttackerIP = SourceIP, DestinationHostName
| where SuccessfulCount >= 1
| project DestinationHostName, SuccessfulCount, AttackerIP, SuccessTime;
let BruteForceSuccesses = SuccessfulLogons 
| join kind = inner FailedLogons on AttackerIP, DestinationHostName;
BruteForceSuccesses
```

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Immediately isolate the machine and change the password of the affected user.
- Identify the origin of the attacks and determine if they are attacking or involved with anything else.
- Determine how and when the attack occurred.
    - Are the NSGs not being locked down? If so, check other NSGs.
- Assess the potential impact of the incident.
    - What type of account was it? Permissions?
    

**Containment and Recovery**

- Lock down the NSG assigned to that VM/Subnet, either entirely, or to allow only necessary traffic.
- Reset the affected user’s password.
- Enable MFA