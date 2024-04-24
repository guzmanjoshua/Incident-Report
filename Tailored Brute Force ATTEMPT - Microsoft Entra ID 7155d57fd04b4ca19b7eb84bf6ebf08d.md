# Brute Force ATTEMPT - Microsoft Entra ID

**Incident Description**

- This incident involves log on failed attempts.

KQL

```
SigninLogs
| where ResultDescription == "Invalid username or password or Invalid on-premise username or password."
| project TimeGenerated, ResultDescription, UserPrincipalName, UserId, AppDisplayName, IPAddress, IPAddressFromResourceProvider, City = LocationDetails.city, State = LocationDetails.state, Country = LocationDetails.country, Latitude = LocationDetails.geoCoordinates.latitude, Longitude = LocationDetails.geoCoordinates.longitude
```

**Tactics and Techniques: Credential Access**

- [Brute Force, Technique T1110 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1110/)

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Check the IP address from the alert to see if it’s malicious or not.

**Containment and Recovery**

- Block the IPs from the Firewall Inbound Rules.
