# Firebase-Scan
Firebase misconfiguration detection tool

Created by: Y0b4get

## Installation

Requirements:
```
pip install requests argparse
```

Usage:

```
git clone https://github.com/Y0b4g3t/Firebase-Scan.git
cd Firebase-Scan
python3 firebase_scan.py [OPTIONS]
```

## Finds common misconfigurations:
1) Enabled user registration

2) Storage bucket listing

3) Misconfigured Firebase Database with enabled READ permissions. Enabled WRITE permissions are available to check, 
   but can't happen passivley so it's not included.

4) Remote config fetching

## References
[https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-enum](https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-enum)
[https://atos.net/en/lp/securitydive/misconfigured-firebase-a-real-time-cyber-threat](https://atos.net/en/lp/securitydive/misconfigured-firebase-a-real-time-cyber-threat)


