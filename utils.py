from datetime import datetime

def parse_time(time_str):
    """Convert a CloudTrail timestamp string into a datetime object."""
    return datetime.fromisoformat(time_str.replace("Z", "+00:00"))