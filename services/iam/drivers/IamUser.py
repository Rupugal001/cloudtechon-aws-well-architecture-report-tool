import boto3, botocore
import datetime
from dateutil.tz import tzlocal
from datetime import datetime, timezone

from .IamCommon import IamCommon
 
class IamUser(IamCommon):
    ENUM_NO_INFO = ['not_supported', 'no_information']
    
    def __init__(self, user, iamClient):
        super().__init__()
        self.user = user
        self.iamClient = iamClient

        self._resourceName = user['user']
        
        self.init()
        
    def is_access_key_recently_rotated(last_rotated_date: int, threshold_days: int = 30) -> bool:
        """
        Validate if an access key was rotated within the last `threshold_days`.
        """
        if last_rotated_date in (None, 0):
            return False
        return last_rotated_date < threshold_days
    
    def _checkHasMFA(self):
        xkey = "rootMfaActive" if self.user['user'] == "<root_account>" else "mfaActive"
        if self.user['user'] == "<root_account>":
            # Root must always have MFA
            if self.user['mfa_active'] == 'false':
                self.results[xkey] = [-1, 'Inactive']
            else:
                self.results[xkey] = [1, 'Active']

        else:
            # IAM user
            if self.user['password_enabled'] == 'true' and self.user['mfa_active'] == 'false':
                self.results[xkey] = [-1, 'Inactive']
            else:
                self.results[xkey] = [1, 'Active or Not Required']
                
    def _checkRootHardwareMfaForBreakGlass(self):
        user = self.user['user']
        if user == '<root_account>':
            # Root user check must use account summary, not list_mfa_devices
            summary = self.iamClient.get_account_summary()["SummaryMap"]
            if summary.get("AccountMFAEnabled", 0) == 1:
                self.results['RootHardwareMfaForBreakGlass'] = [1, 'MFA enabled for root']
            else:
                self.results['RootHardwareMfaForBreakGlass'] = [-1, 'No MFA enabled for root']
        else:
            # For IAM users, use the list_mfa_devices API
            response = self.iamClient.list_mfa_devices(UserName=user)
            mfa_devices = response.get('MFADevices', [])
            if not mfa_devices:
                self.results['RootHardwareMfaForBreakGlass'] = [-1, 'No MFA device found']
            else:
                self.results['RootHardwareMfaForBreakGlass'] = [1, 'MFA device found']

    def _checkConsoleLastAccess(self):
        key = ''
        
        ##<TODO>
        ##Created new Iam users, wait for this info to populate
        if self.user['password_last_used'] in self.ENUM_NO_INFO:
            return
        
        if self.user['password_enabled'] == 'false':
            return
        
        if self.user == '<root_account>':
            return

        daySinceLastAccess = self.getAgeInDay(self.user['password_last_used'])

        key = "consoleLastAccess"
        status = 1

        if daySinceLastAccess > 365:
            key = "consoleLastAccess365"
            status = -1
        elif daySinceLastAccess > 90:
            key = "consoleLastAccess90"
            status = -1
        elif daySinceLastAccess > 45:
            key = "consoleLastAccess45"
            status = -1

        # Always store result
        self.results[key] = [status, daySinceLastAccess]
    
    def _checkUserInGroup(self):
        user = self.user['user']
        if user == '<root_account>':
            return
        
        try:
            resp = self.iamClient.list_groups_for_user(UserName = user)
            groups = resp.get('Groups')
            if not groups:
                self.results['userNotUsingGroup'] = [-1, '-']
        except botocore.exceptions.ClientError as e:
            print(e.response['Error']['Code'], e.response['Error']['Message'])
                
    def _checkUserPolicy(self):
        user = self.user['user']
        if user == '<root_account>':
            return
            
        ## Managed Policy   
        try:
            resp = self.iamClient.list_attached_user_policies(UserName = user)
            policies = resp.get('AttachedPolicies')
            self.evaluateManagePolicy(policies) ## code in iam_common.class.php
            
            ## Inline Policy
            resp = self.iamClient.list_user_policies(UserName = user)
            inlinePolicies = resp.get('PolicyNames')
            self.evaluateInlinePolicy(inlinePolicies, user, 'user')
        except botocore.exceptions.ClientError as e:
            print(e.response['Error']['Code'], e.response['Error']['Message'])
        
    def _checkAccessKeyRotate(self):
        # print(f"Checking Access Key")
        user = self.user
        if user['password_last_changed'] in self.ENUM_NO_INFO:
            return
        
        if user['password_enabled'] == 'true':
            daySinceLastChange = self.getAgeInDay(self.user['password_last_changed'])
    
            status = 1
            key = "passwordLastChange"

            if daySinceLastChange > 365:
                key = "passwordLastChange365"
                status = -1
            elif daySinceLastChange > 90:
                key = "passwordLastChange90"
                status = -1

            # Store result
            self.results[key] = [status, daySinceLastChange]
        
        
        daysAccesskey = 0
        if user['user'] == '<root_account>':
            # print(f"Root Access Key checking")
            if user['access_key_1_active'] == 'true':
                print(f"Root if ")
                daysAccesskeyLastRotated = self.getAgeInDay(user['access_key_1_last_rotated'])
                if daysAccesskeyLastRotated <= 30:
                    self.results['accessKeyRecentlyRotated'] = [1, f"Rotated {daysAccesskeyLastRotated} days ago"]
                else:
                    self.results['accessKeyRecentlyRotated'] = [-1, f"Rotated {daysAccesskeyLastRotated} days ago"]
            elif user['access_key_1_active'] == 'false' and user['access_key_2_active'] == 'false':
                self.results['rootHasNoAccessKeys'] = [1, 'No active access keys']
            else:
                self.results['rootHasAccessKey'] = [-1, 'Root user has access key']

        else:
            if user['access_key_1_active'] == 'true':
                daysAccesskeyLastRotated = self.getAgeInDay(user['access_key_1_last_rotated'])
                if daysAccesskeyLastRotated <= 30:
                    self.results['accessKeyRecentlyRotated'] = [1, f"Rotated {daysAccesskeyLastRotated} days ago"]
                else:
                    self.results['accessKeyRecentlyRotated'] = [-1, f"Rotated {daysAccesskeyLastRotated} days ago"]
            elif user['access_key_2_active'] == 'false':
                daysAccesskey = self.getAgeInDay(user['access_key_1_last_used_date'])
                daysAccesskeyLastRotated = self.getAgeInDay(user['access_key_1_last_rotated'])
            else:
                # print("User If")
                daysAccesskey = max(
                    self.getAgeInDay(user['access_key_1_last_used_date']),
                    self.getAgeInDay(user['access_key_2_last_used_date'])
                )
                daysAccesskeyLastRotated = max(
                    self.getAgeInDay(user['access_key_1_last_rotated']),
                    self.getAgeInDay(user['access_key_2_last_rotated'])
                )
            
            if daysAccesskeyLastRotated >= 90:
                self.results['hasAccessKeyNoRotate90days'] = [-1, str(daysAccesskey)]
            elif daysAccesskeyLastRotated >= 30:
                self.results['hasAccessKeyNoRotate30days'] = [-1, str(daysAccesskey)]
            else:
                return

                
            daySinceLastLogin = 0
            field = 'password_last_used'
            if user['password_last_used'] in self.ENUM_NO_INFO:
                field = 'user_creation_time'
                
            daySinceLastLogin = self.getAgeInDay(user[field])
                    
            if daysAccesskey >= 90 and daySinceLastLogin >= 90:
                self.results['userNoActivity90days'] = [-1, '']
            else:
                self.results['userActive'] = [1, '']
                
    def _checkIamUserGroupMembership(self):
        user = self.user['user']
        if user == '<root_account>':
            return
        try:
            resp = self.iamClient.list_groups_for_user(UserName = user)
            groups = resp.get('Groups')
            if groups and len(groups) > 0:
                groupNames = [g['GroupName'] for g in groups]
                self.results['iamUserGroupMembership'] = [1, ', '.join(groupNames)]
            else:
                self.results['iamUserGroupMembership'] = [-1, 'No group membership']
        except botocore.exceptions.ClientError as e:
            print(e.response['Error']['Code'], e.response['Error']['Message'])
    