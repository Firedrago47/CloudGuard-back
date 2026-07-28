# CloudGuard Backend

Python service that watches your AWS account for suspicious activity — brute-force login attempts, missing MFA, and overly permissive IAM policies.

## What it does

Three detection rules run every minute (and on demand via API):

**Brute-force login detection** – watches CloudTrail `ConsoleLogin` events over a 10-minute rolling window. If someone hits 3+ failures, they get flagged. A successful login resets the counter.

**Missing MFA** – scans every IAM user and checks if they have MFA devices attached. Flags anyone who doesn't.

**Overly permissive policies** – looks at each user's attached IAM policies. If a policy grants full `Action: *` and `Resource: *` access, that's a Critical alert.

## Endpoints

| Method | Path | What it does |
|--------|------|-------------|
| `POST` | `/analyze` | Runs a full scan right now, saves results, returns them |
| `GET` | `/history` | Returns everything previously stored |
| `GET` | `/users` | Lists all IAM users with MFA status and creation date |

## Running it

```bash
pip install fastapi uvicorn boto3 tinydb apscheduler
uvicorn main:app --reload --port 8000
```

You'll need AWS credentials with these permissions:
- `cloudtrail:LookupEvents`
- `iam:ListUsers`, `iam:ListMFADevices`
- `iam:ListAttachedUserPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`

The server starts at `http://localhost:8000` and will automatically scan every minute.

## How the data flows

1. Pulls the last 24 hours of CloudTrail login events
2. Runs brute-force detection on the event stream
3. Calls IAM APIs to check MFA and policy configs
4. Saves everything to a local TinyDB file (`alerts_db.json`)
5. Returns the combined results

The frontend (https://github.com/Firedrago47/CloudGuard-front) hits `/analyze` on demand and `/history` to load persisted alerts.

## Files

```
main.py          – FastAPI app, routes, scheduler
aws_client.py    – talks to CloudTrail
detectors.py     – brute-force logic
iam_checks.py    – MFA + policy checks
storage.py       – TinyDB persistence