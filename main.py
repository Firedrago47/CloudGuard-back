import boto3
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler
from contextlib import asynccontextmanager

from aws_client import aws_log
from detectors import detect_brute_force
from iam_checks import run_iam_checks, get_iam_users, check_mfa_status
from storage import save_alert, get_all_stored_alerts

def run_analysis():
    log = aws_log()
    flagged_users = detect_brute_force(log, threshold=3, window_seconds=600)
    iam_alerts = run_iam_checks()

    all_alerts = flagged_users + iam_alerts

    for alert in all_alerts:
        save_alert(alert)

    return all_alerts

scheduler = BackgroundScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.add_job(run_analysis, 'interval', minutes=1)
    scheduler.start()
    yield
    scheduler.shutdown()    

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/analyze")
def analyze():
    return run_analysis()

@app.get("/history")
def get_history():
    return get_all_stored_alerts()

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