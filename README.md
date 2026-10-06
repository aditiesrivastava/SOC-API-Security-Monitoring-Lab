\# SOC API Security Monitoring Lab



\## Overview



A beginner-friendly cybersecurity project that simulates a Security Operations Center (SOC) monitoring an API for suspicious activity.



The project uses a local Flask API to generate security events and a Python detection script to analyze logs for suspicious authentication and access patterns.



\## Architecture



Postman

↓

Flask API

↓

security.log

↓

Python Detection Engine

↓

Security Alerts



\## Features



\- Local Flask API

\- Security event logging

\- HTTP 401 authentication-failure monitoring

\- Brute-force detection

\- HTTP 403 restricted-resource monitoring

\- Source IP tracking

\- Threshold-based security alerts



\## Detection Rules



| Event | Detection |

| 5+ HTTP 401 responses within 60 seconds | Possible brute-force attack |

| 3+ HTTP 403 responses within 60 seconds | Possible restricted-resource probing |



\## Technologies Used



\- Python

\- Flask

\- Postman

\- HTTP/REST APIs

\- Python log parsing

\- Basic SOC detection concepts



\## How It Works



1\. Flask runs a local API.

2\. Requests generate security events.

3\. Events are written to `security.log`.

4\. `detection.py` reads the log.

5\. Detection rules identify suspicious patterns.

6\. Security alerts are generated.



\## Disclaimer



This project was developed for educational purposes in a controlled local environment.

