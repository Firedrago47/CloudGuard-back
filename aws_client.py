from datetime import datetime, timezone, timedelta
import json
import boto3
from botocore.exceptions import BotoCoreError, ClientError


def aws_log():
    client = boto3.client('cloudtrail', region_name='eu-north-1')  # Change to your desired region

    try:
        response = client.lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'ConsoleLogin'
                }
            ],
            StartTime=datetime.now(timezone.utc) - timedelta(hours=24),
            EndTime=datetime.now(timezone.utc),
            MaxResults=50
        )
    except (BotoCoreError, ClientError) as error:
        print(f"AWS CloudTrail lookup failed: {error}")
        return []

    li = []
    for event in response['Events']:
        detail = json.loads(event['CloudTrailEvent'])
        identity = detail.get('userIdentity', {})

        # Extract username: try CloudTrailEvent detail first, fall back to top-level
        username = identity.get('userName') or event.get('Username')

        # If still no username but it's a Root session, label it "root"
        if not username and identity.get('type') == 'Root':
            username = 'root'

        adapted_event = {
            "eventName": event['EventName'],
            "eventTime": event['EventTime'].isoformat(),
            "userIdentity": {"userName": username, "type": identity.get('type')},
            "sourceIPAddress": detail.get('sourceIPAddress'),
            "responseElements": {"ConsoleLogin": detail.get('responseElements', {}).get('ConsoleLogin')}
        }
        li.append(adapted_event)

    li.reverse()  # oldest first
    for item in li:
        print(item)
    return li