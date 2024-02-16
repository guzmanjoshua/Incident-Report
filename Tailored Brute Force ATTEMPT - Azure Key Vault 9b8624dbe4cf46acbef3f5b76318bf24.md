# Tailored: Brute Force ATTEMPT - Azure Key Vault

**Incident Description**

- This incident involves log on failed attempts.

KQL

```
// Failed access attempts
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" 
| where ResultSignature == "Forbidden"
```

**Tactics and Techniques: Credential Access**

- [Brute Force, Technique T1110 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1110/)

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Check the IP address from the alert to see if it’s malicious or not.

**Containment and Recovery**

- Block the IPs from the Firewall Inbound Rules.