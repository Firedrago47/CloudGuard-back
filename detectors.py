from utils import parse_time


def detect_brute_force(log_data, threshold=3, window_seconds=600):
    failure_tracker = {}  # dictionary: username -> number of consecutive failures
    flagged = []  # list to store flagged usernames

    for event in log_data:
        if event.get('eventName') != 'ConsoleLogin':
            continue  # skip non-login events

        username = event.get('userIdentity', {}).get('userName')
        status = event.get('responseElements', {}).get('ConsoleLogin')
        event_time = parse_time(event.get('eventTime'))
        source_ip = event.get('sourceIPAddress')

        if status == 'Failure':
            if username not in failure_tracker or failure_tracker[username]['first_failure_time'] is None:
                failure_tracker[username] = {'count': 1, 'first_failure_time': event_time, 'flagged': False}
            else:
                failure_tracker[username]['count'] += 1

            streak = failure_tracker[username]
            time_diff = (event_time - streak['first_failure_time']).total_seconds()

            if streak['count'] >= threshold and time_diff <= window_seconds and not streak['flagged']:
                flagged.append({
                    "username": username,
                    "alert_type": "Brute Force Login Attempt",
                    "source_ip": source_ip,
                    "time_detected": event.get('eventTime'),
                    "failure_count": streak['count'],
                    "recommended_action": "Lock account, verify with user, review source IP reputation"
                })
                streak['flagged'] = True

        elif status == 'Success':
            if username in failure_tracker:
                failure_tracker[username] = {"count": 0, "first_failure_time": None, "flagged": False}  # reset on success

    return flagged