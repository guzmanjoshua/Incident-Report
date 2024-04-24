# Brute Force SUCCESS - Microsoft Entra ID

**Incident Description**

- This incident involves observation of potential brute force success against Azure Active Directory.

**KQL**

```
// Failed AAD logon
let FailedLogons = SigninLogs
| where Status.failureReason == "Invalid username or password or Invalid on-premise username or password."
| where TimeGenerated > ago(1h)
| project TimeGenerated, Status = Status.failureReason, UserPrincipalName, UserId, UserDisplayName, AppDisplayName, AttackerIP = IPAddress, IPAddressFromResourceProvider, City = LocationDetails.city, State = LocationDetails.state, Country = LocationDetails.country, Latitude = LocationDetails.geoCoordinates.latitude, Longitude = LocationDetails.geoCoordinates.longitude
| summarize FailureCount = count() by AttackerIP, UserPrincipalName;
let SuccessfulLogons = SigninLogs
| where Status.errorCode == 0 
| where TimeGenerated > ago(1h)
| project TimeGenerated, Status = Status.errorCode, UserPrincipalName, UserId, UserDisplayName, AppDisplayName, AttackerIP = IPAddress, IPAddressFromResourceProvider, City = LocationDetails.city, State = LocationDetails.state, Country = LocationDetails.country, Latitude = LocationDetails.geoCoordinates.latitude, Longitude = LocationDetails.geoCoordinates.longitude
| summarize SuccessCount = count() by AuthenticationSuccessTime = TimeGenerated, AttackerIP, UserPrincipalName, UserId, UserDisplayName;
let BruteForceSuccesses = SuccessfulLogons
| join kind = inner FailedLogons on AttackerIP, UserPrincipalName;
BruteForceSuccesses
| project AttackerIP, TargetAccount = UserPrincipalName, UserId, FailureCount, SuccessCount, AuthenticationSuccessTime
```

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Immediately identify and Revoke Sessions/Access for affected user.
- Identify the origin of the attacker and determine if they are attacking or involved with anything else.
- Assess the potential impact of the incident.
    - What type of account was it?
    - What Roles did it have?
    - How long has it been since the breach went unattended?

**Containment and Recovery**

- Reset the affected user’s password and Roles if applicable.
- Enable MFA
- Consider preventing any logins from outside the US with [Conditional Access](https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies).
