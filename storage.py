from tinydb import TinyDB, Query
from datetime import datetime, timezone
import json
import os

DB_PATH = 'alerts_db.json'

# If the DB file is corrupted, delete it so TinyDB can recreate it fresh
def _ensure_db():
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH, 'r') as f:
                data = f.read().strip()
                if data:
                    json.loads(data)
        except (json.JSONDecodeError, ValueError):
            print(f"Corrupted DB file '{DB_PATH}' detected. Recreating...")
            os.remove(DB_PATH)

_ensure_db()
db = TinyDB(DB_PATH)
Alert = Query()

def save_alert(alert):
    """Save an alert, or update last_seen if the same issue already exists."""
    existing = db.search(
        (Alert.username == alert['username']) & 
        (Alert.alert_type == alert['alert_type'])
    )

    now = datetime.now(timezone.utc).isoformat()

    if existing:
        # Same ongoing issue — just update last_seen
        db.update({'last_seen': now}, 
                  (Alert.username == alert['username']) & 
                  (Alert.alert_type == alert['alert_type']))
    else:
        # New issue — insert with both timestamps
        alert_with_tracking = dict(alert)
        alert_with_tracking['first_detected'] = now
        alert_with_tracking['last_seen'] = now
        db.insert(alert_with_tracking)

def get_all_stored_alerts():
    return db.all()