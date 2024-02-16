# Tailored: Brute Force ATTEMPT - Windows

**Incident Description**

- This incident involves log on failed attempts.

KQL

```
// Failed logon 
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(60m)
| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, DestinationHostName = Computer
| where FailureCount >= 10
```

**Tactics and Techniques: Credential Access**

- [Brute Force, Technique T1110 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1110/)

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Check the IP address from the alert to see if it’s malicious or not.

**Containment and Recovery**

- Block the IPs from the Firewall Inbound Rules.

**Document Findings and Close out Incident**

- Example:

![Untitled](Tailored%20Brute%20Force%20ATTEMPT%20-%20Windows%20891671d4242649cc8b502b125cb3dd92/Untitled.png)

- Reason for closing in the example: I am closing this as a true positive because this alert was triggered due to unauthorized users with malicious IP addresses trying to logon by brute force.