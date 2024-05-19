import requests
from urllib.parse import urlencode
from full_bucket_filenames_extract import extract
import json

# Disable requests warnings
requests.packages.urllib3.disable_warnings()


class FirebaseObj:
    def __init__(self, config: dict, session: requests.Session):
        self.config = config
        if self.config.get('databaseURL') is None:
            self.config['databaseURL'] = ''
        self.user = None
        self.session = session
        self.session.verify = False
        self.bucket_url = f'https://firebasestorage.googleapis.com/v0/b/{self.config.get("storageBucket")}/o'
        self.api_key = self.config.get('apiKey')

    def set_user_true(self, email, password):
        # Authenticate with pyrebase built in method, but it has an endpoint that sometimes returns "Wrong password",
        # Even though the credentials are right.
        url = f'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={self.config["apiKey"]}'
        data = {"email": email, "password": password, "returnSecureToken": "true"}
        response = self.session.post(url, json=data, verify=False)
        self.user = response.json()

    def authenticated_enum(self, bucket_write=None):
        # Check if storage bucket is vulnerable with idToken
        try:
            if storage_bucket(self, id_token=self.user['idToken'], bucket_write=bucket_write) is False:
                print("Couldn't enumerate storage bucket with user credentials.")
        except Exception:
            # print("Couldn't enumerate storage bucket with user credentials.")
            pass

        # Check for exposed database with user credentials
        try:
            self.authenticated_database_enum()
        except Exception:
            pass

    def authenticated_database_enum(self):
        try:
            database_listing_url = f'{self.config.get("databaseURL")}/.json?auth={self.user["idToken"]}'
            database_listing = self.session.get(database_listing_url)
            if database_listing.status_code == 200:
                print('[CRITICAL] Database is exposed with user credentials!')
        except Exception:
            print("Couldn't enumerate database with user credentials.")

    def delete_user_account(self, id_token):
        request_ref = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/deleteAccount?key={self.api_key}"
        headers = {"content-type": "application/json; charset=UTF-8"}
        data = json.dumps({"idToken": id_token})
        request_object = self.session.post(request_ref, headers=headers, data=data)
        return request_object.json()

    def close(self):
        # Delete user if there is
        if self.user:
            self.delete_user_account(self.user['idToken'])


def storage_bucket(firebase_obj: FirebaseObj, id_token=None, bucket_write=None,
                   bucket_list=False, bucket_download=False):
    # Check for storage bucket listing
    try:
        if id_token:
            headers = {"Authorization": f"Bearer {id_token}"}
        else:
            headers = {"Authorization": f"Bearer {firebase_obj.config['apiKey']}"}
        firebase_storage_bucket = firebase_obj.config['storageBucket']
        url = f"{firebase_obj.bucket_url}?maxResults=100"
        # If ID TOKEN provided, will try to list files with user token.
        if id_token:
            # Try to list bucket
            message = "[HIGH] The storage bucket listing is exposed with USER CREDENTIALS! - to download/list files, use the proper flag. - %s"

        else:
            message = "[HIGH] The storage bucket listing is exposed! - to download/list files, use the proper flag. - %s"

        response = firebase_obj.session.get(url, headers=headers, verify=False)
        if response.status_code == 200:
            print(message % url)
            if bucket_list:
                print(response.text)

            if bucket_write:
                # Check write permissions. bucket_write will contain the name of the file to upload.
                bucket_write_res = bucket_write_permission(firebase_obj, bucket_write, id_token=id_token)

                # if bucket_write_res:
                #     extracted_bucket_files = extract(firebase_storage_bucket, firebase_obj.config['apiKey'],
                #                                      session=firebase_obj.session)

            if bucket_download:
                bucket_download_file(firebase_obj, bucket_download)

            if id_token:
                return authenticated_enum
            else:
                return True
    except Exception as err:
        print(err)
        pass
    # print("The storage bucket listing is not vulnerable.")
    return False


def user_registration(api_key, email, password, session: requests.Session):
    # This script looks for user registration misconfiguration. This is a high-severity finding,
    # as remote attacker can create a firebase user and potentially access sensitive information,
    # manipulate entries, or even compromise the database.

    user_registartion_url = f'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}'
    data = {
        "email": email,
        "password": password,
        "returnSecureToken": "true"
    }
    response = session.post(user_registartion_url, json=data, verify=False)
    
    if response.status_code == 200 and 'idToken' in response.text:
        # User registration enabled. If disabled, the message will be 'NO_FORMAT' or 'ADMIN_OPERATION_ONLY', etc.
        print(f"[HIGH] User registration is enabled! - REGISTERED USER: {email}{password}")
        return True
    
    elif response.status_code == 400 and 'EMAIL_EXISTS' in response.text:
        # User registration enabled. If disabled, the message will be 'NO_FORMAT' or 'ADMIN_OPERATION_ONLY', etc.
        print(f"[HIGH] User registration is enabled! - REGISTERED USER: {email}{password}")
        return True
    
    # elif 'ADMIN_ONLY_OPERATION' not in response.text and 'CONFIGURATION_NOT_FOUND' not in response.text:
    #     return False
    # print("User registration is disabled.")
    return False


def database_misconfig(firebase_db_url, session:requests.Session, api_key=None):
    # Check for database misconfig.
    # Reference: https://atos.net/en/lp/securitydive/misconfigured-firebase-a-real-time-cyber-threat
    if 'http' not in firebase_db_url:
        firebase_db_url = f'https://{firebase_db_url}'
    try:
        firebase_expose_url = f'{firebase_db_url}/.json'
        response = session.get(firebase_expose_url, verify=False)
        if response.status_code == 200:
            print(f"[CRITICAL] Firebase Database is exposed!!: {firebase_expose_url}")
            return True
        # If api key is given, check if it can be accessed with api key.
        elif api_key:
            response = session.get(f'{firebase_expose_url}?auth={api_key}', verify=False)
            if response.status_code == 200:
                print(f"Firebase Database is exposed!!: \n{firebase_expose_url}?auth={api_key}")
                return True
        
        # Not vulnerable message.
        # print("Firebase Database seems to not be vulnerable.")
        return False
    except Exception:
        return False
    

def look_for_configs(app_id: str, api_key: str, session: requests.Session, env='PROD'):
    # This script is for fetching remote config, sometimes has sensitive info.
    # Reference: https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-enum
    try:
        project_id = app_id.split(':')[1]
    except IndexError as err:
        raise ValueError('APP ID is not in the right format. Example: 1:612345678909:web:c212345678909876') from err
    
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
        response = session.post(end_url, json=data, headers=headers, verify=False)
        if "NO_TEMPLATE" in response.text:
            return False  # No info
        else:
            # Print information
            print(f"[INFO] Might found interesting information from remote config:\n {response.text}")
    except Exception as err:
        print(f"Error when looking for remote config: {err}")


def bucket_write_permission(firebase_client, write_file_name, id_token=None):
    try:
        headers = {'Authorization': f'Bearer {firebase_client.api_key}'}
        if id_token:
            write_url = f'{firebase_client.bucket_url}?name={write_file_name}'
            headers = {'Authorization': f'Bearer {id_token}'}
        else:
            write_url = f'{firebase_client.bucket_url}?name={write_file_name}'
        try:
            file_obj = open(write_file_name, 'rb')
        except Exception:
            file_obj = write_file_name
        response = firebase_client.session.post(write_url, data=file_obj, verify=False, headers=headers)
        if response.status_code == 204 or response.status_code == 200:
            print(f'[CRITICAL] File uploaded to the bucket: {write_file_name}, bucket: {firebase_client.config.get("storageBucket")}, idToken: {id_token}')
            # Delete the file
            firebase_client.session.delete(write_url, verify=False, headers=headers)
            return response
    except Exception:
        return False


def bucket_download_file(firebase_client: FirebaseObj, file_name):
    try:
        encoded_filename = urlencode(file_name)
        file_url = f'{firebase_client.bucket_url}/{encoded_filename}?alt=media'
        response = firebase_client.session.get(file_url, verify=False)
        if response.status_code == 200:
            print(f'File content: {response.content}')
    except Exception as err:
        print(f"Couldn't download the file: {err}")


def analyze_bucket_content(file_names):
    for name in file_names:
        if name.endswith('.html') or name.endswith('.js') or name.endswith('.php'):
            print("Vector 4")
            pass
