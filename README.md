# Firebase-Scan
Firebase misconfiguration detection tool

Created by: Y0b4get

## Installation

Requirements:
```
pip install requests argparse pyrebase4
```

Usage:

```
git clone https://github.com/Y0b4g3t/Firebase-Scan.git
cd Firebase-Scan
python3 main.py [OPTIONS]
```

Quick Start: (Just fetch the firebase config from a URL response)
```commandline
python3 main.py --url URL
```

## Finds common misconfigurations:
1) Enabled user registration

2) Storage bucket READ/WRITE

3) Misconfigured Firebase Database with enabled READ permissions. Enabled WRITE permissions are available to check manually.

4) Remote config fetching

## References
[https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-enum](https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-enum)

[https://atos.net/en/lp/securitydive/misconfigured-firebase-a-real-time-cyber-threat](https://atos.net/en/lp/securitydive/misconfigured-firebase-a-real-time-cyber-threat)


