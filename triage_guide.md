Incident Triage Playbook: Anomaly-Based Password Spray

# Alert Context
This alert triggers when a single IP address attempts a high volume of failed logins against multiple unique Entra ID accounts, and the failure rate exceeds the historical 14-day baseline for that IP by a factor of 3x or more. This indicates an attacker attempting to bypass standard brute-force detection by spreading authentication attempts across a wide set of users.

# Step 1: Investigation & Validation
1. Analyze the Source IP:
   - Check the `IPAddress` field in the alert. 
   - Cross-reference the IP with threat intelligence feeds (e.g., VirusTotal, AlienVault OTX) to see if it is a known malicious node or residential proxy.
   - Determine if the IP belongs to a known corporate VPN exit node or legitimate corporate infrastructure.

2. Check for Compromise (Crucial Step):
   - Query `SigninLogs` to determine if the attacker successfully guessed a password during or immediately after the spray campaign.
   - Run the following KQL query to look for successful logins (`ResultType == 0`) from the malicious IP:
     ```kql
     SigninLogs
     | where IPAddress == "<Suspicious_IP_Here>"
     | where ResultType == 0
     | project TimeGenerated, UserPrincipalName, AppDisplayName, UserAgent
     ```

3. Evaluate Targeted Accounts:
   - Review the `TargetedUsers` array from the alert. Are the targeted accounts active employees, service accounts, or disabled/former employee accounts?

# Step 2: Containment & Remediation
If the activity is confirmed as malicious:

1. Block the Source:
   - Add the offending `IPAddress` to the corporate firewall blocklist or Conditional Access named locations blocklist.
2. Secure Compromised Accounts (If any successes were found):
   - Immediately force a password reset for the affected `UserPrincipalName`.
   - Revoke active Entra ID refresh tokens to kill any hijacked sessions.
   - Instruct the user to verify their MFA registration methods for any unauthorized secondary devices.

# Step 3: False Positive Handling
This alert may trigger falsely under the following conditions:
- Misconfigured Applications: A legacy application with an expired service account password might continuously attempt to authenticate, inflating failure counts. 
- Corporate Gateway NAT: If thousands of legitimate users share a single external IP address (e.g., browsing from a shared office network), a localized network issue might temporarily spike login failures. 
- Action: If verified as a false positive, tune the `threshold_multiplier` in the detection rule or add an explicit exclusion for the known corporate IP.