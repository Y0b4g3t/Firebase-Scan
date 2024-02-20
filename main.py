import argparse
import json
from firebase_scan import storage_bucket, database_misconfig, user_registration, look_for_configs, description


def main():
    parser = argparse.ArgumentParser(prefix_chars='-', add_help=True, prog='./main.py', usage='./main.py [OPTIONS]',
                                     formatter_class=argparse.RawDescriptionHelpFormatter, description=description)
    parser.add_argument('-a', '--api-key', type=str, action='store', help='Firebase API Key.')
    parser.add_argument('-d', '--database', type=str, action='store', help='Firebase Databse URL (Example: https://appid.firebaseio.com)', default=None)
    parser.add_argument('-b', '--bucket', type=str, action='store', help='Firebase Storage Bucket.', default=None)
    parser.add_argument('-id', '--app-id', type=str, action='store', help='Firebase APP ID.')
    parser.add_argument('-e', '--env', type=str, action='store', help='Environment to look for when fetching remote config. Example: PROD/DEV/TEST.',
                        default="PROD")
    
    # Load a firebase json config file instead of using all the switches
    parser.add_argument('-f', '--file', type=str, action='store', help='JSON file of the Firebase config.')


    args = parser.parse_args()
    
    if args.file:
        json_file = json.load(open(args.file, 'r'))
        api_key = json_file.get('apiKey')
        db_url = json_file.get('databaseURL')
        bucket_url = json_file.get('storageBucket')
        app_id = json_file.get('appId')
    else:
        api_key = args.api_key
        db_url = args.database
        bucket_url = args.bucket
        app_id = args.app_id
    
    env = args.env

    # Start scan print
    print("Started firebase scan...")

    # Check for bucket listing misconfig
    if bucket_url:
        storage_bucket(bucket_url, api_key)

    # Check for user registration misconfig
    user_registration(api_key)

    # Check for databse READ access.
    if db_url:
        database_misconfig(db_url, api_key)

    # Check for interesting configs - taken from https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-enum
    look_for_configs(app_id, api_key, env)


if __name__ == "__main__":
    main()