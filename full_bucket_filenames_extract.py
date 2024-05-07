import requests

# Disable requests warnings
requests.packages.urllib3.disable_warnings()


def get_names_from_response(response_json):
    for item in response_json.get('items'):
        file_names.append(item['name'])


def analyze_names():
    for name in file_names:
        name = str(name)
        if name.endswith(('.js', '.html', '.php', '.json')):
            return name
    return False


def extract(bucket_url, api_key, session: requests.Session):
    global file_names
    file_names = []
    url = f'https://firebasestorage.googleapis.com/v0/b/{bucket_url}/o?maxResults=1000'
    headers = {
        "Authorization": f"Bearer {api_key}"
    }
    response = session.get(url, headers=headers, verify=False)
    get_names_from_response(response.json())

    while 'nextPageToken' in response.json():
        next_page_token = response.json().get('nextPageToken')
        new_url = url + '&pageToken=' + next_page_token
        response = session.get(new_url, headers=headers, verify=False)
        get_names_from_response(response.json())

    # Analyze file names to assess the risk
    analyzed_response = analyze_names()
    if analyzed_response:
        print(f"[CRITICAL] Write permissions with sensitive files in the bucket! Example: {analyzed_response}")
    return file_names


