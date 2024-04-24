# Possible Privilege Escalation (Global Admin Role Assignment)

**Incident Description**

- This incident involves the unexpected assignment of the Global Administrator role to a user account in Azure AD.

**KQL**

```
AuditLogs
| where OperationName == "Add member to role" and Result == "success"
| where TargetResources[0].modifiedProperties[1].newValue == '"Global Administrator"' or TargetResources[0].modifiedProperties[1].newValue == '"Company Administrator"' and TargetResources[0].type == "User"
| where TimeGenerated > ago(60m)
| project
    TimeGenerated,
    OperationName,
    AssignedRole = TargetResources[0].modifiedProperties[1].newValue,
    Status = Result,
    TargetResources,
    InitiatorID = InitiatedBy["user"]["id"],
    TargetID = TargetResources[0]["id"]
```


**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Identify the user account that was assigned the Global Administrator role.
- Determine how and when the role assignment occurred.
- Assess the potential impact of the incident.

**Containment and Recovery**

- Revoke the Global Administrator role from the affected user account immediately if unintended, otherwise skip to the documentation phase.
- Check for any other unauthorized role assignments made by the attacker and revoke them if necessary.
- Identify the root cause of the incident and take corrective actions to prevent similar incidents from occurring in the future.
- Restore any data or system configurations that may have been affected by the incident. This may involve resetting the Global Administrator password for the affected account and updating the secret in Key Vault
