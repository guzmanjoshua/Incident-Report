# Tailored: Possible Privilege Escalation (Azure Key Vault Critical Credential Retrieval or Update)

**Incident Description**

- This incident involves the unexpected reading of a critical credential from the organization's Key Vault.

**KQL**

```
// Updating a specific existing password Success
let CRITICAL_PASSWORD_NAME = "Tenant-Global-Admin-Password";
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" 
| where OperationName == "SecretGet" or OperationName == "SecretSet"
| where id_s contains CRITICAL_PASSWORD_NAME
```

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Identify the credential that was read and the user or application that read it.
- Determine how and when the credential was read.
- Assess the potential impact of the incident.

**Containment and Recovery**

- Revoke access to the credential from the affected user or application immediately if unintended, otherwise skip to the documentation phase.
- Check for any other unauthorized access to the credential and revoke it if necessary.
- Monitor the affected systems for any suspicious activity related to the incident.
- Identify the root cause of the incident and take corrective actions to prevent similar incidents from occurring in the future.
- Change the credential if it was compromised.
