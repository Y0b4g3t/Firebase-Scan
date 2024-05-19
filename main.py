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


def scan_url(url):
    # Get URL response and fetch the firebase config.
    response = requests.get(url, verify=False)
    firebase_config = firebase_regex_search(response.text)

    # Run the scan
    run_scan(firebase_config)


def main():
    parser = argparse.ArgumentParser(prefix_chars='-', add_help=True, prog='./main.py', usage='./main.py [OPTIONS]',
                                     formatter_class=argparse.RawDescriptionHelpFormatter, description=DESCRIPTION)
    parser.add_argument('-a', '--api-key', type=str, action='store', help='Firebase API Key.')
    parser.add_argument('-d', '--database', type=str, action='store', help='Firebase Databse URL (Example: https://appid.firebaseio.com)', default=None)
    parser.add_argument('-b', '--bucket', type=str, action='store', help='Firebase Storage Bucket. (Example: project-name.appspot.com)', default=None)
    parser.add_argument('-id', '--app-id', type=str, action='store', help='Firebase APP ID.')
    parser.add_argument('-e', '--env', type=str, action='store', help='Environment to look for when fetching remote config. Example: PROD/DEV/TEST.',
                        default="PROD")
    parser.add_argument('-email', '--email', type=str, action='store', help='Email for user registration', default="asdd@asdfggh.com")
    parser.add_argument('-p', '--password', type=str, action='store', help='Password for user registration',
                        default="asdsasd")
    parser.add_argument('--projectname', type=str, action='store', help='Project name')
    
    # Load a firebase json config file/from URL instead of using all the switches
    parser.add_argument('-f', '--file', type=str, action='store', help='JSON file of the Firebase config.')
    parser.add_argument('-u', '--url', type=str, action='store', help='URL of where the Firebase config is presented.')
    parser.add_argument('--proxy', type=str, action='store', help='For proxy.', default=None)

    # Scan options
    scan_options_group = parser.add_argument_group('Storage Bucket Enumeration')
    scan_options_group.add_argument('-sa', '--all', action='store_true', help='All scan (detection) options.')
    scan_options_group.add_argument('-sb', '--scan-bucket', action='store_true', help='Detection of bucket misconfig.')
    scan_options_group.add_argument('-sd', '--scan-database', action='store_true', help='Detection of database misconfig.')
    scan_options_group.add_argument('-sr', '--scan-registration', action='store_true', help='Detection of user registration.')
    scan_options_group.add_argument('-sc', '--scan-remote-config', action='store_true', help='Detection of remote config fetching.')

    # Bucket exploitation
    storage_enum_group = parser.add_argument_group('Storage Bucket Enumeration')
    storage_enum_group.add_argument('-bw', '--bucket_write', type=str, action='store',
                            help='Attempt write action against the storage bucket. File will be saved exactly to the '
                                 'path you choose.', default=False)
    storage_enum_group.add_argument('-bl', '--bucket_list', action='store_true',
                            help='Print the bucket listing.', default=False)
    storage_enum_group.add_argument('-bd', '--bucket_download', action='store', type=str,
                            help='Download a file in this directory.', default=False)

    args = parser.parse_args()
    # Set values (These have defaults)
    email = args.email
    password = args.password
    
    if args.file:
        firebase_config = json.load(open(args.file, 'r'))
    elif args.url:
        proxies = {
            'http': args.proxy,
            'https': args.proxy
        }
        # Get URL response and fetch the firebase config.
        response = requests.get(args.url, verify=False, proxies=proxies)
        firebase_config = firebase_regex_search(response.text)
    else:
        api_key = args.api_key
        db_url = args.database
        bucket_url = args.bucket
        app_id = args.app_id
        project_name = args.projectname
        firebase_config = set_config(api_key, db_url, bucket_url, app_id, project_name)

    run_scan(firebase_config, email=email, password=password, args=args, proxy=args.proxy)


def run_scan(firebase_config, email=None, password=None, args=None, proxy=None):
    api_key = firebase_config.get('apiKey')
    db_url = firebase_config.get('databaseURL')
    bucket_url = firebase_config.get('storageBucket')
    app_id = firebase_config.get('appId')
    req_session = requests.Session()
    req_session.proxies = {
        "http": proxy,
        "https": proxy
    }
    firebase_obj = FirebaseObj(firebase_config, req_session)


    # Start scan print
    print("Started firebase scan...")

    if args:
        bucket_write = args.bucket_write
        bucket_list = args.bucket_list
        bucket_download = args.bucket_download
    else:
        bucket_write = 'poc.txt'
        bucket_list = False
        bucket_download = False

    # Check for bucket listing misconfig
    if bucket_url:
        storage_bucket(firebase_obj, bucket_write=bucket_write, bucket_list=bucket_list,
                       bucket_download=bucket_download)

    # Check for databse READ access.
    if db_url:
        database_misconfig(db_url, api_key)

    # Check for interesting configs - taken from
    # https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-enum
    look_for_configs(app_id, api_key, session=req_session)

    # Check for user registration misconfig
    if user_registration(api_key, email, password, session=req_session):
        # Sign in with the user credentials to get idToken.
        firebase_obj.set_user_true(email, password)

        # Authenticated firebase enum for bucket write/read and DB write/read.
        firebase_obj.authenticated_enum(bucket_write=bucket_write)

    # Close pyrebase SDK - basically just delete user account if registered
    firebase_obj.close()


if __name__ == "__main__":
    main()


