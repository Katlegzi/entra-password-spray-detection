 Advanced Threat Detection: Entra ID Password Spraying

# Project Overview
This repository contains a custom Detection Engineering project focused on identifying low-and-slow password spray attacks against Microsoft Entra ID (formerly Azure AD). The detection logic utilizes Kusto Query Language (KQL) to establish a 14-day historical baseline of authentication failures and flags anomalous spikes that evade standard static threshold alerts. 

This project demonstrates practical skills aligned with Microsoft Security Operations Analyst (SC-200) objectives, specifically in custom threat detection, log analysis, and incident response playbook creation.

## 🛠️ Technologies & Telemetry
* Language: Kusto Query Language (KQL)
* Environment: Microsoft Sentinel / Azure Data Explorer (ADX)
* Log Sources: `SigninLogs`, `AADNonInteractiveUserSignInLogs`
* Framework: MITRE ATT&CK 
  * Tactic: Credential Access (TA0006)
  * Technique: Brute Force - Password Spraying (T1110.003)

# Threat Scenario
Modern threat actors often avoid triggering standard account lockout policies by distributing login attempts across hundreds of corporate accounts using a single compromised password. This "low-and-slow" method bypasses static threshold alerts (e.g., >10 failed logins in 5 minutes). 

This detection rule counters this evasion tactic by shifting from static limits to **time-series anomaly detection**. By dynamically calculating the normal background noise of failed sign-ins per IP address, the rule identifies malicious deviations in real-time.

# Repository Structure
* `/detection_rule.kql`: The production-ready Kusto Query Language script containing the baseline calculation and anomaly detection logic.
* `/triage_guide.md`: A step-by-step incident response playbook detailing how a SOC Analyst should validate the alert, check for successful compromises, and execute containment procedures.

# Key Features
1. Dynamic Baselining: Calculates a rolling 14-day average of failed authentications per IP address to establish an environment-specific baseline.
2. Anomaly Scoring: Generates an `AnomalyScore` metric to distinguish coordinated attacks from standard user typing errors or misconfigured legacy apps.
3. High-Fidelity Alerting: Aggregates critical contextual data (targeted user sets, applications, locations, and user agents) into the final alert output to accelerate SOC triage.

# Triage & Containment (Summary)
Upon alert generation, defenders should immediately investigate the flagged `IPAddress` for successful authentications (`ResultType == 0`). If compromise is confirmed, the playbook dictates revoking active Entra ID refresh tokens, enforcing mandatory password resets for affected users, and blocking the malicious infrastructure via Conditional Access policies.