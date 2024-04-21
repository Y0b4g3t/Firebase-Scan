import re


# Fetch the firebase config from a web content.
def firebase_regex_search(response_text):
    # Patterns of different common firebase config keys
    patterns = {
        "apiKey": r'"?apiKey"?\s*:\s*"([^"]+)"?',
        "authDomain": r'"?authDomain"?\s*:\s*"([^"]+)"?',
        "projectId": r'"?projectId"?\s*:\s*"([^"]+)"?',
        "storageBucket": r'"?storageBucket"?\s*:\s*"([^"]+)"?',
        "databaseURL": r'"?databaseURL"?\s*:\s*"([^"]+)"?',
        "messagingSenderId": r'"?messagingSenderId"?\s*:\s*"([^"]+)"?',
        "appId": r'"?appId"?\s*:\s*"([^"]+)"?',
        "measurementId": r'"?measurementId"?\s*:\s*"([^"]+)"?'
    }

    # Combine patterns into a single regex pattern
    combined_pattern = "|".join(f"({pattern})" for pattern in patterns.values())

    matches = re.findall(combined_pattern, response_text)

    results = {}
    # Pattern to find values between quote marks
    quote_pattern = r'"(.*?)"'

    for match in matches:
        for inmatch in match:
            # Take only the matches with the key:value
            if ':' in inmatch and 'http' not in inmatch:
                # Seperate the key and the value
                key, *value_parts = inmatch.split(':')

                # If it is appId, need to handle the split correctly.
                if 'appId' in inmatch:
                    value = ':'.join(value_parts)
                else:
                    value = inmatch.split(':')[1]

                # If between quote marks, extract the values
                try:
                    if '"' in key:
                        key = re.search(quote_pattern, key).group(1)
                    if '"' in value:
                        value = re.search(quote_pattern, value).group(1)
                except Exception as err:
                    print(err)

                results[key] = value

            elif ':' in inmatch and 'database' in inmatch:
                # Usually firebase database URLs have 'http/s' scheme
                key, *value_parts = inmatch.split(':')
                values_stripped = [value.strip() for value in value_parts]
                value = ':'.join(values_stripped)  # Retrieve the URL
                # Extract value from quote marks
                if '"' in value:
                    value = re.search(quote_pattern, value).group(1)

                if 'http' not in value:
                    if '//' in value:
                        value = f'https:{value}'
                    else:
                        value = f'https://{value}'
                results['databaseURL'] = value

    return results
