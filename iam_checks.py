import boto3,json

def get_iam_users():
    client = boto3.client('iam')
    response = client.list_users()
    return response['Users']

def check_mfa_status(username):
    client = boto3.client('iam')
    response = client.list_mfa_devices(UserName=username)
    return response['MFADevices']

def get_user_policy_documents(username):
    client = boto3.client('iam')
    
    attached_policies = client.list_attached_user_policies(UserName=username)
    policy_documents = []

    for policy in attached_policies['AttachedPolicies']:
        policy_arn = policy['PolicyArn']
        
        policy_info = client.get_policy(PolicyArn=policy_arn)
        version_id = policy_info['Policy']['DefaultVersionId']
        
        version_info = client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        document = version_info['PolicyVersion']['Document']
        
        policy_documents.append({"policy_name": policy['PolicyName'], "document": document})

    return policy_documents


def is_policy_overly_permissive(policy_document):
    statements = policy_document.get('Statement', [])
    
    if isinstance(statements, dict):
        statements = [statements]
    
    for statement in statements:
        if statement.get('Effect') == 'Allow':
            action = statement.get('Action')
            resource = statement.get('Resource')
            
            actions = [action] if isinstance(action, str) else action
            resources = [resource] if isinstance(resource, str) else resource
            
            if '*' in actions and '*' in resources:
                return True
    
    return False


def run_iam_checks():
    flagged = []
    users = get_iam_users()

    for user in users:
        username = user['UserName']

        #Missing MFA
        mfa_devices = check_mfa_status(username)
        if len(mfa_devices) == 0:
            flagged.append({
                "username": username,
                "alert_type": "Missing MFA",
                "severity": "High",
                "source_ip": None,
                "time_detected": user['CreateDate'].isoformat(),
                "failure_count": None,
                "recommended_action": "Enable MFA for this IAM user to protect against credential compromise"
            })

        #Overly permissive policies
        policies = get_user_policy_documents(username)
        for policy in policies:
            if is_policy_overly_permissive(policy['document']):
                flagged.append({
                    "username": username,
                    "alert_type": "Overly Permissive IAM Policy",
                    "severity": "Critical",
                    "source_ip": None,
                    "time_detected": user['CreateDate'].isoformat(),
                    "failure_count": None,
                    "recommended_action": f"Review and restrict policy '{policy['policy_name']}' — grants full Action and Resource wildcard access"
                })

    return flagged


