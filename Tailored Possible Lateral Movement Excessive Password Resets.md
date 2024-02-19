# Tailored: Possible Lateral Movement (Excessive Password Resets)

**Incident Description**

- This incident involves observation of potential lateral movement based on excessive password resets.

**KQL**

```
AuditLogs
| where OperationName startswith "Change" or OperationName startswith "Reset"
| order by TimeGenerated
| summarize count() by tostring(InitiatedBy)
| project Count = count_, InitiatorId = parse_json(InitiatedBy).user.id, InitiatorUpn = parse_json(InitiatedBy).user.userPrincipalName, InitiatorIpAddress = parse_json(InitiatedBy).user.ipAddress 
| where Count >= 10
```

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Immediately identify and Revoke Sessions/Access for any affected users.
- Identify the attacker and determine if they are attacking or involved with anything else.
- Observe the target accounts which had their passwords reset.
    - Have any of them immediately logged in or done anything else?
- Assess the potential impact of the incident.
    - What type of accounts are involved?
    - What Roles did it have?
    - How long has it been since the breach went unattended?
    

**Containment and Recovery**

- Reset the affected users’ password and Roles if applicable.
- Enable MFA
