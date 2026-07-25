import boto3
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aws_client import aws_log
from detectors import detect_brute_force
from iam_checks import run_iam_checks, get_iam_users, check_mfa_status

app = FastAPI()

# Allow your Next.js frontend (running on a different port) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # your Next.js dev server
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/analyze")
def analyze():
    log = aws_log()
    flagged_users = detect_brute_force(log, threshold=3, window_seconds=600)
    iam_alerts = run_iam_checks()

    all_alerts = flagged_users + iam_alerts
    return all_alerts

@app.get("/users")
def list_users():
    """Return all IAM users with MFA status and creation date."""
    users = get_iam_users()
    result = []
    for user in users:
        username = user['UserName']
        mfa_devices = check_mfa_status(username)
        result.append({
            "username": username,
            "created_date": user['CreateDate'].isoformat() if hasattr(user['CreateDate'], 'isoformat') else str(user['CreateDate']),
            "mfa_enabled": len(mfa_devices) > 0,
            "arn": user.get('Arn', ''),
        })
    return result