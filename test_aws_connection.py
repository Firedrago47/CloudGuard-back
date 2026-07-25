import boto3
import json

from datetime import datetime, timedelta, timezone

client = boto3.client('cloudtrail', region_name='us-east-1')

response = client.lookup_events(
    LookupAttributes=[
        {
            'AttributeKey': 'EventName',
            'AttributeValue': 'ConsoleLogin'
        }
    ],
    StartTime=datetime.now(timezone.utc) - timedelta(hours=2),
    EndTime=datetime.now(timezone.utc),
    MaxResults=50
)

li = []

for event in response['Events']:
    detail = json.loads(event['CloudTrailEvent'])
    
    adapted_event = {
        "eventName": event['EventName'],
        "eventTime": event['EventTime'].isoformat(),
        "userIdentity": {"userName": event.get('Username')},
        "sourceIPAddress": detail.get('sourceIPAddress'),
        "responseElements": {"ConsoleLogin": detail.get('responseElements', {}).get('ConsoleLogin')}
    }
    li.append(adapted_event)

li.reverse()  # oldest first

for item in li:
    print(item)