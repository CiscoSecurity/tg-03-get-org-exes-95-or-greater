import requests

# Threat Grid API Key
tg_api_key = 'asdf1234asdf1234asdf1234'

# Threat Grid URL used for collecting samples
tg_url = 'https://panacea.threatgrid.com/api/v2/search/submissions'

# Instantiate session object
session = requests.Session()

# Parameters for Threat Grid API query
parameters = {'api_key': tg_api_key,
              'advanced':'true',
              'offset':0,
              'org_only':True,
              'after':'30 days ago',
              'q':'analysis.metadata.submitted_file.type:exe && analysis.threat_score:>=95'
              }

while True:
    # Query Threat Grid for samples
    response = session.get(tg_url, params=parameters)

    # Decode the JSON response
    response_json = response.json()
    items_per_page = response_json['data']['items_per_page']
    current_item_count = response_json['data']['current_item_count']

    # Set new offset
    parameters['offset'] += items_per_page

    # Name the 'items' list in the JSON response
    items = response_json['data']['items']

    # Iterate over the 'items' list
    for sample in items:
        sha256 = sample['item']['sha256']
        sample_id = sample['item']['sample']
        file_type = sample['item']['analysis']['metadata']['analyzed_file']['type']

        # Print Sample ID, SHA256, file type
        print(sample_id, sha256, file_type)

    # Stop pagination
    if current_item_count != items_per_page:
        break
