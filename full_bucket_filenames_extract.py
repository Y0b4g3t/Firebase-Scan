import requests
import argparse

# Disable requests warnings
requests.packages.urllib3.disable_warnings()


proxies = {
    'http': '127.0.0.1:8080',
    'https': '127.0.0.1:8080'
}


def get_names_from_response(response_json):
    for item in response_json.get('items'):
        file_names.append(item['name'])


def extract(bucket_url, api_key):
    global file_names
    file_names = []
    url = f'https://firebasestorage.googleapis.com/v0/b/{bucket_url}/o?maxResults=1000'
    headers = {
        "Authorization": f"Bearer {api_key}"
    }
    response = requests.get(url, headers=headers, verify=False, proxies=proxies)
    get_names_from_response(response.json())

    while 'nextPageToken' in response.json():
        next_page_token = response.json().get('nextPageToken')
        new_url = url + '&pageToken=' + next_page_token
        response = requests.get(new_url, proxies=proxies, headers=headers, verify=False)
        get_names_from_response(response.json())

    return file_names


# extract('ynet-goal.appspot.com', 'AIzaSyDIVjgcdj6Vg-zo5p01l1P_EmWM8oJTR6U')
# with open('bucket_results_ynet-goal.appspot.com.txt', 'a') as f:
#     for name in file_names:
#         f.write(name + '\n')

