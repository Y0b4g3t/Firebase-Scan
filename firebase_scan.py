import argparse
import requests

# Disable requests warnings
requests.packages.urllib3.disable_warnings()


description = """
Title: Firebase Misconfiguration scanning tool.
Description: This tool is used for testing various firebase common misconfigurations, like
Storage Bucket listing, User registration, Remote config, and exposed database.

Author: y0b4get
"""

def storage_bucket(firebase_storage_bucket, api_key):
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        url = f"https://firebasestorage.googleapis.com/v0/b/{firebase_storage_bucket}/o?maxResults=50"
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 200:
            print("[MEDIUM] The storage bucket listing is exposed!")
            return True
    except Exception:
        pass
    print("The storage bucket listing is not vulnerable.")
    return False


def user_registration(api_key):
    # This script looks for user registration misconfiguration. This is a high-severity finding,
    # as remote attacker can create a firebase user and potentially access sensitive information,
    # manipulate entries, or even compromise the database.

    user_registartion_url = f'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}'
    data = {
        "email": "asd@asdfggh.com",
        "password": "",
        "returnSecureToken": "true"
    }
    response = requests.post(user_registartion_url, json=data, verify=False)

    if response.status_code == 200:
        # Less chance that status code will be 200
        print("[HIGH] User registration is enabled!")
        return True
    
    elif response.status_code == 400 and 'MISSING_PASSWORD' in response.text:
        # User registration enabled. If disabled, the message will be 'NO_FORMAT' or 'ADMIN_OPERATION_ONLY', etc.
        print("[HIGH] User registration is enabled!")
        return True
    
    # elif 'ADMIN_ONLY_OPERATION' not in response.text and 'CONFIGURATION_NOT_FOUND' not in response.text:
    #     return False
    print("User registration is disabled.")
    return False


def database_misconfig(firebase_db_url, api_key=None):
    # Check for database misconfig.
    # Reference: https://atos.net/en/lp/securitydive/misconfigured-firebase-a-real-time-cyber-threat
    if 'http' not in firebase_db_url:
        firebase_db_url = f'https://{firebase_db_url}'
    try:
        firebase_expose_url = f'{firebase_db_url}/.json'
        response = requests.get(firebase_expose_url, verify=False)
        if response.status_code == 200:
            print(f"[CRITICAL] Firebase Database is exposed!!: {firebase_expose_url}")
            return True
        # If api key is given, check if it can be accessed with api key.
        elif api_key:
            response = requests.get(f'{firebase_expose_url}?auth={api_key}', verify=False)
            if response.status_code == 200:
                print(f"Firebase Database is exposed!!: \n{firebase_expose_url}?auth={api_key}")
                return True
        
        # Not vulnerable message.
        print("Firebase Storage Bucket seems to not be vulnerable.")
        return False
    except Exception:
        return False
    

def look_for_configs(app_id: str, api_key: str, env='PROD'):
    # This script is for fetching remote config, sometimes has sensitive info.
    # Reference: https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-enum
    try:
        project_id = app_id.split(':')[1]
    except KeyError as err:
        raise 'APP ID is not in the right format. Example: 1:612345678909:web:c212345678909876'
    
    # Set up the request
    end_url = f'https://firebaseremoteconfig.googleapis.com/v1/projects/{project_id}/namespaces/firebase:fetch?key={api_key}'
    data = {
        "appId": app_id,
        "appInstanceId": env
    }
    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(end_url, json=data, headers=headers, verify=False)
        if "NO_TEMPLATE" in response.text:
            print("Couldn't fetch remote config.")
            return False  # No info
        else:
            # Print information
            print(f"[INFO] Might found interesting information from remote config:\n {response.text}")
    except Exception as err:
        print(f"Error when looking for remote config: {err}")


def main():
    parser = argparse.ArgumentParser(prefix_chars='-', add_help=True, prog='./firebase_scan.py', usage='./firebase_scan.py [OPTIONS]',
                                     formatter_class=argparse.RawDescriptionHelpFormatter, description=description)
    parser.add_argument('-a', '--api-key', type=str, action='store', help='Firebase API Key.')
    parser.add_argument('-d', '--database', type=str, action='store', help='Firebase Databse URL (Example: https://appid.firebaseio.com)')
    parser.add_argument('-b', '--bucket', type=str, action='store', help='Firebase Storage Bucket.')
    parser.add_argument('-id', '--app-id', type=str, action='store', help='Firebase APP ID.')
    parser.add_argument('-e', '--env', type=str, action='store', help='Environment to look for when fetching remote config. Example: PROD/DEV/TEST.')

    args = parser.parse_args()
    api_key = args.api_key
    db_url = args.database
    bucket_url = args.bucket
    app_id = args.app_id

    # Start scan print
    print("Started firebase scan...")

    # Check for bucket listing misconfig
    storage_bucket(bucket_url, api_key)

    # Check for user registration misconfig
    user_registration(api_key)

    # Check for databse READ access.
    database_misconfig(db_url, api_key)

    # Check for interesting configs - taken from https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-enum
    look_for_configs(app_id, api_key)


if __name__ == "__main__":
    main()