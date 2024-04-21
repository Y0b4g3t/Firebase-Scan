import argparse
import json
from firebase_scan import storage_bucket, database_misconfig, user_registration, look_for_configs, FirebaseObj
from firebase_config_fetcher import firebase_regex_search
import requests

DESCRIPTION = """
Title: Firebase Misconfiguration scanning tool.
Description: This tool is used for testing various firebase common misconfigurations, like
Storage Bucket listing, User registration, Remote config, and exposed database.

Author: y0b4get
"""


def set_config(api_key, db_url, bucket_url, app_id, project_name):
    config = {
        'apiKey': api_key,
        'databaseURL': db_url,
        'storageBucket': bucket_url,
        'appId': app_id,
        'authDomain': project_name
    }
    return config


def main():
    parser = argparse.ArgumentParser(prefix_chars='-', add_help=True, prog='./main.py', usage='./main.py [OPTIONS]',
                                     formatter_class=argparse.RawDescriptionHelpFormatter, description=DESCRIPTION)
    parser.add_argument('-a', '--api-key', type=str, action='store', help='Firebase API Key.')
    parser.add_argument('-d', '--database', type=str, action='store', help='Firebase Databse URL (Example: https://appid.firebaseio.com)', default=None)
    parser.add_argument('-b', '--bucket', type=str, action='store', help='Firebase Storage Bucket. (Example: project-name.appspot.com)', default=None)
    parser.add_argument('-id', '--app-id', type=str, action='store', help='Firebase APP ID.')
    parser.add_argument('-e', '--env', type=str, action='store', help='Environment to look for when fetching remote config. Example: PROD/DEV/TEST.',
                        default="PROD")
    parser.add_argument('-email', '--email', type=str, action='store', help='Email for user registration', default="asd@asdfggh.com")
    parser.add_argument('-p', '--password', type=str, action='store', help='Password for user registration',
                        default="asdasd")
    parser.add_argument('--projectname', type=str, action='store', help='Project name')
    
    # Load a firebase json config file instead of using all the switches
    parser.add_argument('-f', '--file', type=str, action='store', help='JSON file of the Firebase config.')
    parser.add_argument('-u', '--url', type=str, action='store', help='URL of where the Firebase config is presented.')

    # Bucket exploitation
    parser.add_argument('-bw', '--bucket_write', type=str, action='store',
                        help='Attempt write action against the storage bucket. File will be saved to poc/<FILE_NAME>.',
                        default=False)
    parser.add_argument('-bl', '--bucket_list', action='store_true',
                        help='Print the bucket listing.', default=False)

    args = parser.parse_args()
    
    if args.file:
        firebase_config = json.load(open(args.file, 'r'))
        api_key = firebase_config.get('apiKey')
        db_url = firebase_config.get('databaseURL')
        bucket_url = firebase_config.get('storageBucket')
        app_id = firebase_config.get('appId')
    elif args.url:
        # Get URL response and fetch the firebase config.
        response = requests.get(args.url, verify=False)
        firebase_config = firebase_regex_search(response.text)
        api_key = firebase_config.get('apiKey')
        db_url = firebase_config.get('databaseURL')
        bucket_url = firebase_config.get('storageBucket')
        app_id = firebase_config.get('appId')
    else:
        api_key = args.api_key
        db_url = args.database
        bucket_url = args.bucket
        app_id = args.app_id
        project_name = args.projectname
        firebase_config = set_config(api_key, db_url, bucket_url, app_id, project_name)

    firebase_obj = FirebaseObj(firebase_config)

    # Set values (These have defaults)
    env = args.env
    email = args.email
    password = args.password

    # Start scan print
    print("Started firebase scan...")

    # Check for bucket listing misconfig
    if bucket_url:
        storage_bucket(firebase_obj, bucket_write=args.bucket_write, bucket_list=args.bucket_list)

    # Check for databse READ access.
    if db_url:
        database_misconfig(db_url, api_key)

    # Check for interesting configs - taken from https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-enum
    look_for_configs(app_id, api_key, env)

    # Check for user registration misconfig
    if user_registration(api_key):
        firebase_obj.set_user_true(email, password)
        # Start authenticated enumeration on bucket and DB.
        firebase_obj.authenticated_database_enum()


if __name__ == "__main__":
    main()
