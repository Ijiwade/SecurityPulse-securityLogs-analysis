# SecurityPulse-security-analysis
This project analyzes authentication logs to detect suspicious behavior such as brute-force attempts, impossible travel, and repeated failed logins before successful access.

Tools
* SQL(SQLite)
* POWER BI
* GitHub

Dataset
* users
* devices
* ip_reputation
* auth_events

Business Questions
* latest login per user
* first device per user
* failed login ranking
* bruteforce detection
* impossible travel detection
* login failure escalation

OUTPUT/Dashboard
The final securityPulse_users_report powers the POWER BI Dashboard.

SECURITYPULSE -- KEY FINDINGS & ACTIONS
INSIGHTS
* **Risk is concentrated, not widespread**
  Only ¬5% of users exhibit elevated risk, indicating targeted security issues rather than systemic failure.
* **High-confidence threats identified**
  Impossible travel and overlapping anomaly highlight a small group of users with likely compromised accounts.
* **Authentication friction is evident**
  Escalation events(multiple failed logins before success) are widespread, suggesting usability issues rather than direct attacks

RISKS
* **Critical accounts at immediate risk**
  A small subset of users (risk_score >= 2) show multiple concurrent anomalies, making them high-probability compromise cases
* **Operational exposure in key departments**
  High-risk users are concentrated in IT, Support, and Finance -- roles with elevated system access.
* **Signal noise may obscure real threats**
  Over-triggered escalation alerts can reduce the effectiveness of detection systems.

ACTIONS
* **Prioritise investigation of high-risk users**
  Immediately review and secure accounts with multiple risk signals (force reset, enforce MFA, audit activity).
* **Implement adaptive authentication**
  Trigger MFA or step-up verification based on anomaly signals (fail spikes, impossible travel).
* **Refine detection thresholds**
  Adjust escalation rules to reduce false positives and improve signal quality

**HOW TO REPRODUCE**
1. Load the SecurityPulse dataset into SQLite(SQLiteviz recommended)
2. Run the SQL queries in the sql_queries folder
3. Export the final assembled user report as CSV
4. Load the CSV into POWER BI
5. Open the dashboard file in the Dashboard folder.
