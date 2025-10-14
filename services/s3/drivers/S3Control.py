import urllib.parse
from datetime import date

import boto3
import botocore

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator

class S3Control(Evaluator):
    def __init__(self, s3Control):
        super().__init__()
        self.s3Control = s3Control

        self._resourceName = 'S3AccountLevel'
        
        self.init()
    
    def _checkAccountPublicAccessBlock(self):
        self.results['S3AccountPublicAccessBlock'] = [-1, 'Off']

        try:
            stsInfo = Config.get('stsInfo')
            if not stsInfo:
                print("Unable to retrieve account information")
                self.results['S3AccountPublicAccessBlock'] = [-1, 'Insufficient info']
                return
        except botocore.exceptions.ClientError as e:
            print('Unable to capture STS account info:', e.response['Error']['Code'])
            self.results['S3AccountPublicAccessBlock'] = [-1, 'Insufficient info']
            return

        try:
            resp = self.s3Control.get_public_access_block(
                AccountId=stsInfo['Account']
            )
            pab_config = resp.get("PublicAccessBlockConfiguration", {})
        except botocore.exceptions.ClientError as e:
            # This means no block is configured at all
            print("Public access configuration not set:", e.response['Error']['Code'])
            self.results['S3AccountPublicAccessBlock'] = [-1, 'Not configured']
            return

        # Check all 4 recommended settings
        required_flags = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets"
        ]

        non_compliant = [flag for flag in required_flags if not pab_config.get(flag, False)]
        if non_compliant:
            self.results['S3AccountPublicAccessBlock'] = [-1, f"Disabled flags: {non_compliant}"]
        else:
            self.results['S3AccountPublicAccessBlock'] = [1, "All account-level public access blocks enabled"]