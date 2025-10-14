import botocore
from botocore.config import Config as bConfig

import json
from datetime import datetime, timedelta
from dateutil.tz import tzlocal

from utils.Config import Config
from utils.Tools import _warn, _pr
from .IamCommon import IamCommon
 
class IamAccount(IamCommon):
    PASSWORD_POLICY_MIN_SCORE = 4
    ROOT_LOGIN_MAX_COUNT = 3
    
    def __init__(self, none, awsClients, users, roles, ssBoto):
        super().__init__()
        
        self.ssBoto = ssBoto
        self.iamClient = awsClients['iamClient']
        self.accClient = awsClients['accClient']
        self.sppClient = awsClients['sppClient']
        self.gdClient = awsClients['gdClient']
        self.budgetClient = awsClients['budgetClient']
        self.orgClient = awsClients['orgClient']
        
        
        self.curClient = awsClients['curClient']
        self.ctClient = awsClients['ctClient']
        self.shClient = awsClients['shClient']
        self.configClient = awsClients['configClient']
        self.ecsclient = awsClients['ecsClient']
        self.smClient = awsClients['smClient']
        self.emrClient = awsClients['emrClient']
        self.dmsClient = awsClients['dmsClient']
        self.ssmClient = awsClients['ssmClient']
        self.sageMakerClient = awsClients['sageMakerClient']
        self.esClient = awsClients['esClient']
        self.ebsClient = awsClients['ebsClient']
        self.ecrClient = awsClients['ecrClient']
        self.backupClient = awsClients['backupClient']
        self.acmClient = awsClients['acmClient']
        self.accessanalyzerClient = awsClients['accessanalyzerClient']
        self.auditmanagerClient = awsClients['auditmanagerClient']

        self.noOfUsers = len(users)
        self.roles = roles
        
        self._resourceName = 'General'

        # self.__configPrefix = 'iam::settings::'

        # Assuming AWS Organization is disabled at first
        self.organizationIsEnabled = False

        # Check if AWS Organization is enabled
        try:
            resp = self.orgClient.describe_organization()
            self.organizationIsEnabled = True
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == "AccessDeniedException":
                # Couldn’t verify due to permissions
                self.organizationIsEnabled = None

        self.init()
        
    def passwordPolicyScoring(self, policies):
        score = 0
        for policy, value in policies.items():
            ## no score for this:
            if policy in ['AllowUsersToChangePassword', 'ExpirePasswords']:
                continue
            
            if policy == 'MinimumPasswordLength':
                if value >= 12:
                    score += 1
                else:
                    self.results['passwordPolicyLength'] = [-1, value]
                continue

            if policy == 'MaxPasswordAge' and value <= 90:
                score += 1
                continue

            if policy == 'PasswordReusePrevention' and value >= 6:
                score += 1
                self.results['passwordPolicyReuse'] = [-1, value]
                continue
            
            if not value is None and value > 0:
                score += 1
                
        return score
    
    def _checkPasswordPolicy(self):
        try:
            resp = self.iamClient.get_account_password_policy()
            policies = resp.get('PasswordPolicy')
            
            if policies:
                self.results['passwordPolicy'] = [1, 'Having password policy']
            if not policies:
                self.results['HavingPolicy'] = [-1, 'No password policy']
            else:
                self.results['HavingPolicy'] = [1, 'Having password policy']
                
            score = self.passwordPolicyScoring(policies)
            
            currVal = [f"{policy}={num}" for policy, num in policies.items()]
            output = '<br>'.join(currVal)
            if score <= self.PASSWORD_POLICY_MIN_SCORE:
                # Weak password policy
                self.results['passwordPolicyWeak'] = [-1, output]
            else:
                # Strong password policy
                self.results['passwordPolicyStrong'] = [1, output, 1]
                
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            print(ecode)
            if ecode == 'NoSuchEntity':
                self.results['passwordPolicy'] = [-1, ecode]
    
    def _checkRootLoginActivity(self):
        c = 0
        LookupAttributes=[
            {
                'AttributeKey': 'Username',
                'AttributeValue': 'root'
            },
            {
                'AttributeKey': 'Eventname',
                'AttributeValue': 'ConsoleLogin'
            }
        ]
        StartTime=datetime.today() - timedelta(days=30)
        EndTime=datetime.today() + timedelta(days=1)
        
        resp = self.ctClient.lookup_events(
            LookupAttributes=LookupAttributes,
            StartTime=StartTime,
            EndTime=EndTime,
            MaxResults=50,
        )
        
        ee = resp.get('Events')
        if len(ee) == 0 or not ee:
            self.results['rootConsoleLogin30days'] = [1, "No root logins in last 30 days"]
            return
        
        self.results['rootConsoleLogin30days'] = [-1, '']
        
        for e in ee:
            o = e.get('CloudTrailEvent')
            o = json.loads(o)
            
            if 'errorMessage' in o:
                c += 1
                
            if c >= self.ROOT_LOGIN_MAX_COUNT:
                self.results['rootConsoleLoginFail3x'] = [-1, '']
                return
        
        while resp.get('NextToken') != None:
            resp = self.ctClient.lookup_events(
                LookupAttributes=LookupAttributes,
                StartTime=StartTime,
                EndTime=EndTime,
                MaxResults=50,
                NextToken = resp.get('NextToken')
            )
            
            ee = resp.get('Events')
            for e in ee:
                o = e.get('CloudTrailEvent')
                o = json.loads(o)
                
                if 'errorMessage' in o:
                    c += 1
                    
                if c >= self.ROOT_LOGIN_MAX_COUNT:
                    self.results['rootConsoleLoginFail3x'] = [-1, '']
                return
    
    def _checkHasRole_AWSReservedSSO(self):
        hasReservedRole = False
        for role in self.roles:
            if role['RoleName'].startswith('AWSReservedSSO_'):
                hasReservedRole = True
                break 
            
        if hasReservedRole == False:
            self.results['hasSSORoles'] = [-1, '']
    
    def _checkHasExternalProvider(self):
        hasOpID = False
        hasSaml = False
        resp = self.iamClient.list_open_id_connect_providers()
        if 'OpenIDConnectProviderList' in resp:
            if len(resp['OpenIDConnectProviderList']) > 0:
                hasOpID = True
        
        resp = self.iamClient.list_saml_providers()
        if 'SAMLProviderList' in resp:
            if len(resp['SAMLProviderList']) > 0:
                hasSaml = True
        
        if hasOpID == False and hasSaml == False:
            self.results['hasExternalIdentityProvider'] = [-1, '']
    
    def _checkHasGuardDuty(self):
        ssBoto = self.ssBoto
        regions = Config.get("REGIONS_SELECTED")
        
        results = {}
        badResults = []
        cnt = 0
        for region in regions:
            if region == 'GLOBAL':
                continue
            
            conf = bConfig(region_name = region)
            gdClient = ssBoto.client('guardduty', config=conf)
        
            resp = gdClient.list_detectors()
            if 'DetectorIds' in resp:
                ids = resp.get('DetectorIds')
                if len(ids) > 0:
                    self.results['enableGuardDuty'] = [1, f"Enabled in {region}"]
                    return
            
        self.results["enableGuardDuty"] = [-1, ""]
        
    def _checkHasCostBudget(self):
        stsInfo = Config.get('stsInfo')
        
        budgetClient = self.budgetClient
        
        try:
            resp = budgetClient.describe_budgets(AccountId=stsInfo['Account'])
        
            if 'Budgets' in resp:
                return 
        
            self.results['enableCostBudget'] = [-1, ""]
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
    
    def _checkSupportPlan(self):
        sppClient = self.sppClient
        try:
            resp = sppClient.describe_severity_levels()
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'SubscriptionRequiredException':
                self.results['supportPlanLowTier'] = [-1, '']
    
    def _checkHasUsers(self):
        # has at least 1 for all account (root)
        if self.noOfUsers < 2:
            self.results['noUsersFound'] = [-1, 'No IAM User found']
                
    def _checkHasAlternateContact(self):
        CONTACT_TYP = ['BILLING', 'SECURITY', 'OPERATIONS']
        cnt = 0
        for typ in CONTACT_TYP:
            res = self.getAlternateContactByType(typ)
            if res == None:
                res = 0
            cnt += res
        
        if cnt == 0:
            self.results['hasAlternateContact'] = [-1, 'No alternate contacts']
    
    def getAlternateContactByType(self, typ):
        try:
            resp = self.accClient.get_alternate_contact(
                AlternateContactType = typ
            )
            return 1
            
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'ResourceNotFoundException':
                return 0

    def _checkHasOrganization(self):
        if (self.organizationIsEnabled == False):
                self.results['hasOrganization'] = [-1, '']
        else:
            self.results['hasOrganization'] = [1, '']

    def _checkCURReport(self):
        try:
            results = self.curClient.describe_report_definitions()
            if len(results.get('ReportDefinitions')) == 0:
                self.results['enableCURReport'] = [-1, '']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if e.response['Error']['Code'] == 'AccessDeniedException':
               _warn('Unable to describe the CUR report. It is likely that this account is part of AWS Organizations')
            else:
                print(e)
        
        return

    def _checkConfigEnabled(self):
        ssBoto = self.ssBoto
        regions = Config.get("REGIONS_SELECTED")
        
        results = {}
        badResults = []
        cnt = 0
        for region in regions:
            if region == 'GLOBAL':
                continue
            
            conf = bConfig(region_name = region)
            cfg = ssBoto.client('config', config=conf)
            
            resp = cfg.describe_configuration_recorders()
            recorders = resp.get('ConfigurationRecorders')
            r = 1
            if len(recorders) == 0:
                r = 0
                badResults.append(region)
            
            cnt = cnt + r
            results[region] = r
        total_regions = len([r for r in regions if r != 'GLOBAL'])
        
        if cnt == 0:
            self.results['EnableConfigService'] = [-1, None]
        elif cnt < len(regions):
            self.results['PartialEnableConfigService'] = [-1, ', '.join(badResults)]
        else:
            self.results['EnableConfigService'] = [1, f"Enabled in {cnt}/{total_regions} regions"]
            # return

    def _checkSCPEnabled(self):
        # Run this check only when AWS Organization is activated in the account
        if self.organizationIsEnabled == True:
            try:
                # Get organization root ID
                roots = self.orgClient.list_roots()
                root_id = roots['Roots'][0]['Id']
                
                policies = self.orgClient.list_policies_for_target(
                    TargetId=root_id,
                    Filter='SERVICE_CONTROL_POLICY'
                )
                
                # If no SCPs are attached, add to results
                if len(policies.get('Policies', [])) == 0:
                    self.results['SCPEnabled'] = [-1, '']
                else:
                    # Pass case: SCPs exist
                    self.results['SCPEnabled'] = [1, f"{len(policies['Policies'])} SCP(s) attached"]
                                    
            except botocore.exceptions.ClientError as e:
                ecode = e.response['Error']['Code']
                self.results['SCPEnabled'] = [-1, f"Error while checking SCPs: {ecode}"]
        else:
            self.results['SCPEnabled'] = [0, 'AWS Organizations not enabled']

    def _checkSCPGuardrailsPresent(self):
        if self.organizationIsEnabled:
            try:
                guardrails = []

                # 1. Get current account ID
                sts = self.ssBoto.client("sts")
                account_id = sts.get_caller_identity()["Account"]

                # 2. Check SCPs directly attached to the account
                acct_policies = self.orgClient.list_policies_for_target(
                    TargetId=account_id,
                    Filter="SERVICE_CONTROL_POLICY"
                ).get("Policies", [])
                guardrails.extend([p for p in acct_policies if p["Name"] != "FullAWSAccess"])

                # 3. Walk up the OU hierarchy
                parent = self.orgClient.list_parents(ChildId=account_id)["Parents"][0]
                while parent["Type"] == "ORGANIZATIONAL_UNIT":
                    ou_id = parent["Id"]
                    ou_policies = self.orgClient.list_policies_for_target(
                        TargetId=ou_id,
                        Filter="SERVICE_CONTROL_POLICY"
                    ).get("Policies", [])
                    guardrails.extend([p for p in ou_policies if p["Name"] != "FullAWSAccess"])

                    parent = self.orgClient.list_parents(ChildId=ou_id)["Parents"][0]

                # 4. Finally, check root SCPs
                root_id = parent["Id"]  # when Type == ROOT
                root_policies = self.orgClient.list_policies_for_target(
                    TargetId=root_id,
                    Filter="SERVICE_CONTROL_POLICY"
                ).get("Policies", [])
                guardrails.extend([p for p in root_policies if p["Name"] != "FullAWSAccess"])

                # 5. Store result
                if len(guardrails) == 0:
                    self.results["scpGuardrailsPresent"] = [-1, "No SCP guardrails present (only FullAWSAccess)"]
                else:
                    self.results["scpGuardrailsPresent"] = [1, f"{len(guardrails)} SCP guardrail(s) present"]

            except botocore.exceptions.ClientError as e:
                ecode = e.response["Error"]["Code"]
                self.results["scpGuardrailsPresent"] = [-1, f"Error while checking SCP guardrails: {ecode}"]

        else:
            self.results["scpGuardrailsPresent"] = [0, "AWS Organizations not enabled"]
            
    def _checkFederationEnforced(self):
        try:
            users = self.iamClient.list_users().get("Users", [])
            if not users:
                self.results["federationEnforced"] = [1, "No IAM users → federation enforced"]
                return

            # Check for console access and access keys
            non_federated_users = []
            for user in users:
                user_name = user["UserName"]

                # Check for console password
                try:
                    self.iamClient.get_login_profile(UserName=user_name)
                    non_federated_users.append(user_name)
                except self.iamClient.exceptions.NoSuchEntityException:
                    pass

                # Check for active access keys
                keys = self.iamClient.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
                active_keys = [k for k in keys if k["Status"] == "Active"]
                if active_keys:
                    non_federated_users.append(user_name)

            if not non_federated_users:
                self.results["federationEnforced"] = [1, "IAM users exist but no console passwords or active keys → federation enforced"]
            else:
                self.results["federationEnforced"] = [-1, f"Federation not enforced, IAM users with console or keys: {list(set(non_federated_users))}"]

        except botocore.exceptions.ClientError as e:
            ecode = e.response["Error"]["Code"]
            self.results["federationEnforced"] = [-1, f"Error while checking federation enforcement: {ecode}"]


    def _checkNoLocalIamUsers(self):
        try:
            users = self.iamClient.list_users().get("Users", [])
            if not users:
                self.results["noLocalIamUsers"] = [1, "No IAM users found in account"]
            else:
                usernames = [u["UserName"] for u in users]
                self.results["noLocalIamUsers"] = [-1, f"Found {len(users)} IAM users: {usernames}"]
            with_boundary = [u for u in users if 'PermissionsBoundary' in u]
            if with_boundary:
                usernames = [u["UserName"] for u in with_boundary]
                self.results["iamUsersWithPermissionsBoundary"] = [1, f"Found {len(with_boundary)} IAM users with permissions boundary: {usernames}"]
            else:
                self.results["iamUsersWithPermissionsBoundary"] = [-1, "No IAM users with permissions boundary found"]
        except botocore.exceptions.ClientError as e:
            ecode = e.response["Error"]["Code"]
            self.results["noLocalIamUsers"] = [-1, f"Error while checking IAM users: {ecode}"]

    def _checkEnableSecurityHub(self):
        try:
            resp = self.shClient.get_enabled_standards()
            if resp.get("StandardsSubscriptions"):
                self.results['EnableSecurityHub'] = [1, '']
            else:
                self.results['EnableSecurityHub'] = [-1, '']
            standards = resp.get("StandardsSubscriptions", [])
            cis_enabled = any('cis-aws-foundations-benchmark' in s['StandardsArn'] for s in standards)
            if not cis_enabled:
                self.results['CISBenchmarkEnabled'] = [-1, 'CIS AWS Foundations Benchmark not enabled']
            else:
                self.results['CISBenchmarkEnabled'] = [1, 'CIS AWS Foundations Benchmark enabled']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'ResourceNotFoundException':
                self.results['EnableSecurityHub'] = [-1, '']
            elif ecode == 'AccessDeniedException':
                _warn('Unable to describe the Security Hub. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkConformancePackDeployed(self):
        try:
            resp = self.configClient.describe_conformance_packs()
            if resp.get("ConformancePackDetails"):
                self.results['ConformancePackDeployed'] = [1, '']
            else:
                self.results['ConformancePackDeployed'] = [-1, '']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'NoSuchEntityException':
                self.results['ConformancePackDeployed'] = [-1, '']
            elif ecode == 'AccessDeniedException':
                _warn('Unable to describe the Config Conformance Packs. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkConfigRulesRecentlyUpdated(self):
        try:
            resp = self.configClient.describe_config_rules()
            rules = resp.get("ConfigRules", [])
            if not rules:
                self.results['ConfigRulesRecentlyUpdated'] = [-1, 'No Config rules found']
                return

            now = datetime.now(tz=tzlocal())
            outdated_90 = []
            outdated_365 = []

            for r in rules:
                last_update = r.get("LastUpdateTime", datetime.min.replace(tzinfo=tzlocal()))
                if last_update < now - timedelta(days=365):
                    outdated_365.append(r["ConfigRuleName"])
                elif last_update < now - timedelta(days=90):
                    outdated_90.append(r["ConfigRuleName"])

            if not outdated_90 and not outdated_365:
                self.results['ConfigRulesRecentlyUpdated'] = [1, 'All Config rules updated within the last 90 days']
            elif outdated_365:
                self.results['ConfigRulesRecentlyUpdated'] = [-1, f"Stale Config rules >365d: {outdated_365}"]
            elif outdated_90:
                self.results['ConfigRulesRecentlyUpdated'] = [0, f"Config rules not updated in >90d: {outdated_90}"]

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'NoSuchEntityException':
                self.results['ConfigRulesRecentlyUpdated'] = [-1, 'No Config rules found']
            elif ecode == 'AccessDeniedException':
                _warn('Unable to describe the Config Rules. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)

    def _checkECSTaskDefinitions(self):
        try:
            resp = self.ecsclient.list_task_definitions(maxResults=100)
            if resp.get("taskDefinitionArns"):
                self.results['ECSTaskDefinitionsPresent'] = [1, '']
            else:
                self.results['ECSTaskDefinitionsPresent'] = [-1, 'No ECS Task Definitions found']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list ECS Task Definitions. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkECSFargateLatestPlatformVersion(self):
        try:
            paginator = self.ecsclient.get_paginator('list_clusters')
            page_iterator = paginator.paginate()
            non_compliant_clusters = []

            for page in page_iterator:
                for cluster_arn in page.get('clusterArns', []):
                    services = self.ecsclient.list_services(cluster=cluster_arn).get('serviceArns', [])
                    for service_arn in services:
                        service = self.ecsclient.describe_services(cluster=cluster_arn, services=[service_arn]).get('services', [])[0]
                        if service.get('launchType') == 'FARGATE':
                            task_def_arn = service.get('taskDefinition')
                            task_def = self.ecsclient.describe_task_definition(taskDefinition=task_def_arn).get('taskDefinition', {})
                            if task_def.get('requiresCompatibilities') and 'FARGATE' in task_def['requiresCompatibilities']:
                                platform_version = service.get('platformVersion', 'LATEST')
                                if platform_version != 'LATEST':
                                    non_compliant_clusters.append(cluster_arn)
                                    break  # No need to check other services in this cluster

            if not non_compliant_clusters:
                self.results['ECSFargateLatestPlatformVersion'] = [1, 'All Fargate services use LATEST platform version']
            else:
                self.results['ECSFargateLatestPlatformVersion'] = [-1, f'Clusters with Fargate services not using LATEST: {non_compliant_clusters}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list ECS Clusters or Services. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkECSContainerInsights(self):
        try:
            clusters = self.ecsclient.list_clusters()["clusterArns"]
            non_compliant_clusters = []
            
            for cluster_arn in clusters:
                resp = self.ecsclient.describe_clusters(clusters=[cluster_arn])
                cluster = resp.get("clusters", [])[0]
                settings = cluster.get("settings", [])
                
                if not any(s.get("name") == "containerInsights" and s.get("value") == "enabled" for s in settings):
                    non_compliant_clusters.append(cluster_arn)

            if not non_compliant_clusters:
                self.results['ECSContainerInsights'] = [1, 'Container Insights enabled on all ECS clusters']
            else:
                self.results['ECSContainerInsights'] = [-1, f'Clusters without Container Insights: {non_compliant_clusters}']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list or describe ECS Clusters. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkECSTaskNonRootUser(self):
        try:
            paginator = self.ecsclient.get_paginator('list_task_definitions')
            page_iterator = paginator.paginate()
            non_compliant_tasks = []

            for page in page_iterator:
                for task_arn in page.get('taskDefinitionArns', []):
                    task = self.ecsclient.describe_task_definition(taskDefinition=task_arn).get('taskDefinition', {})
                    containers = task.get('containerDefinitions', [])
                    for container in containers:
                        user = container.get('user')
                        if not user or user == '0' or user.lower() == 'root':
                            non_compliant_tasks.append(task_arn)
                            break  # No need to check other containers in this task

            if not non_compliant_tasks:
                self.results['ECSTaskNonRootUser'] = [1, 'All ECS tasks run as non-root users']
            else:
                self.results['ECSTaskNonRootUser'] = [-1, f'ECS tasks running as root: {non_compliant_tasks}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list ECS Task Definitions. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)

    def _checkECSContainersNonPrivileged(self):
        try:
            paginator = self.ecsclient.get_paginator('list_task_definitions')
            page_iterator = paginator.paginate()
            non_compliant_tasks = []

            for page in page_iterator:
                for task_arn in page.get('taskDefinitionArns', []):
                    task = self.ecsclient.describe_task_definition(taskDefinition=task_arn).get('taskDefinition', {})
                    containers = task.get('containerDefinitions', [])
                    for container in containers:
                        if container.get('privileged', False):
                            non_compliant_tasks.append(task_arn)
                            break  # No need to check other containers in this task

            if not non_compliant_tasks:
                self.results['ECSTaskContainersNonPrivileged'] = [1, 'All ECS containers run as non-privileged']
            else:
                self.results['ECSTaskContainersNonPrivileged'] = [-1, f'ECS containers running as privileged: {non_compliant_tasks}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list ECS Task Definitions. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkECSContainersReadOnly(self):
        try:
            paginator = self.ecsclient.get_paginator('list_task_definitions')
            page_iterator = paginator.paginate()
            non_compliant_tasks = []

            for page in page_iterator:
                for task_arn in page.get('taskDefinitionArns', []):
                    task = self.ecsclient.describe_task_definition(taskDefinition=task_arn).get('taskDefinition', {})
                    containers = task.get('containerDefinitions', [])
                    for container in containers:
                        if container.get('readOnly', False):
                            non_compliant_tasks.append(task_arn)
                            break  # No need to check other containers in this task

            if not non_compliant_tasks:
                self.results['ECSTaskContainersReadOnly'] = [1, 'All ECS containers run as read-only']
            else:
                self.results['ECSTaskContainersReadOnly'] = [-1, f'ECS containers running as writable: {non_compliant_tasks}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list ECS Task Definitions. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)

    def _checkSecretsRotation(self):
        try:
            paginator = self.smClient.get_paginator('list_secrets')
            page_iterator = paginator.paginate()
            non_rotated_secrets = []

            for page in page_iterator:
                for secret in page.get('SecretList', []):
                    desc = self.smClient.describe_secret(SecretId=secret['ARN'])
                    if not desc.get('RotationEnabled', False):
                        non_rotated_secrets.append(secret['Name'])

            if not non_rotated_secrets:
                self.results['secretsRotationEnabled'] = [1, 'All secrets have rotation enabled']
            else:
                self.results['secretsRotationEnabled'] = [-1, f'Secrets without rotation: {non_rotated_secrets}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Secrets Manager secrets. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)


    def _checkSecretPeriodicRotation(self):
        try:
            paginator = self.smClient.get_paginator('list_secrets')
            page_iterator = paginator.paginate()
            non_rotated_secrets = []

            for page in page_iterator:
                for secret in page.get('SecretList', []):
                    desc = self.smClient.describe_secret(SecretId=secret['ARN'])
                    if not desc.get('RotationEnabled', False):
                        non_rotated_secrets.append(secret['Name'])
                    else:
                        last_rotated = desc.get('LastRotatedDate')
                        if last_rotated:
                            days_since_rotation = (datetime.now(tz=tzlocal()) - last_rotated).days
                            if days_since_rotation > 90:
                                non_rotated_secrets.append(f"{secret['Name']} (last rotated {days_since_rotation} days ago)")
                        else:
                            non_rotated_secrets.append(f"{secret['Name']} (never rotated)")

            if not non_rotated_secrets:
                self.results['secretsPeriodicallyRotated'] = [1, 'All secrets rotated within the last 90 days']
            else:
                self.results['secretsPeriodicallyRotated'] = [-1, f'Secrets not rotated in last 90 days: {non_rotated_secrets}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Secrets Manager secrets. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)


    def _checkSecretUnused(self):
        try:
            paginator = self.smClient.get_paginator('list_secrets')
            page_iterator = paginator.paginate()
            unused_secrets = []

            for page in page_iterator:
                for secret in page.get('SecretList', []):
                    desc = self.smClient.describe_secret(SecretId=secret['ARN'])
                    last_accessed = desc.get('LastAccessedDate')
                    if not last_accessed or (datetime.now(tz=tzlocal()) - last_accessed).days > 90:
                        unused_secrets.append(secret['Name'])

            if not unused_secrets:
                self.results['secretsRecentlyAccessed'] = [1, 'All secrets accessed within the last 90 days']
            else:
                self.results['secretsRecentlyAccessed'] = [-1, f'Secrets not accessed in last 90 days: {unused_secrets}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Secrets Manager secrets. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)


    def _checkSecretUsingCMK(self):
        try:
            paginator = self.smClient.get_paginator('list_secrets')
            page_iterator = paginator.paginate()
            secrets_without_cmk = []

            for page in page_iterator:
                for secret in page.get('SecretList', []):
                    desc = self.smClient.describe_secret(SecretId=secret['ARN'])
                    kms_key = desc.get('KmsKeyId')

                    # If no KMS key or using the default AWS managed key, mark as non-compliant
                    if not kms_key or kms_key.endswith('aws/secretsmanager'):
                        secrets_without_cmk.append(secret['Name'])

            if not secrets_without_cmk:
                self.results['secretsUsingCMK'] = [1, 'All secrets use customer-managed KMS keys']
            else:
                self.results['secretsUsingCMK'] = [-1, f'Secrets not using customer-managed KMS keys: {secrets_without_cmk}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Secrets Manager secrets. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkEMRKerberosEnabled(self):
        try:
            clusters = self.emrClient.list_clusters()
            kerberos_enabled_clusters = []

            for cluster in clusters['Clusters']:
                if cluster['Status']['State'] == 'RUNNING':
                    kerberos_enabled = self.emrClient.describe_cluster(ClusterId=cluster['Id']).get('Cluster', {}).get('KerberosAttributes', {}).get('Enabled', False)
                    if kerberos_enabled:
                        kerberos_enabled_clusters.append(cluster['Name'])

            if not kerberos_enabled_clusters:
                self.results['emrKerberosEnabled'] = [1, 'No EMR clusters with Kerberos enabled']
            else:
                self.results['emrKerberosEnabled'] = [-1, f'EMR clusters with Kerberos enabled: {kerberos_enabled_clusters}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list EMR clusters. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
    
    def _checkEmrMasterNoPublicIp(self):
        bad_clusters = []
        clusters = self.emrClient.list_clusters(ClusterStates=['WAITING','RUNNING'])['Clusters']
        for c in clusters:
            instances = self.emrClient.list_instances(ClusterId=c['Id'], InstanceGroupTypes=['MASTER'])
            for inst in instances['Instances']:
                if inst.get('PublicIpAddress'):
                    bad_clusters.append(c['Name'])

        if bad_clusters:
            self.results['EmrMasterNoPublicIp'] = [-1, f"Clusters with public master: {bad_clusters}"]
        else:
            self.results['EmrMasterNoPublicIp'] = [1, "No EMR masters have public IPs"]
        
    def _checkPoliciesBlockedKMS(self):
        try:
            paginator = self.iamClient.get_paginator('list_policies')
            page_iterator = paginator.paginate(Scope='Local')
            non_compliant_policies = []

            for page in page_iterator:
                for policy in page.get('Policies', []):
                    policy_version = self.iamClient.get_policy(PolicyArn=policy['Arn']).get('Policy', {}).get('DefaultVersionId')
                    policy_document = self.iamClient.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy_version).get('PolicyVersion', {}).get('Document', {})
                    
                    statements = policy_document.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]

                    for stmt in statements:
                        actions = stmt.get('Action', [])
                        if not isinstance(actions, list):
                            actions = [actions]
                        
                        if any(a.startswith('kms:') for a in actions) and stmt.get('Effect') == 'Allow':
                            non_compliant_policies.append(policy['PolicyName'])
                            break  # No need to check other statements in this policy

            if not non_compliant_policies:
                self.results['policiesBlockedKMS'] = [1, 'No IAM policies allow unrestricted KMS actions']
            else:
                self.results['policiesBlockedKMS'] = [-1, f'IAM policies allowing unrestricted KMS actions: {non_compliant_policies}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list IAM policies. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)

    def _checkDMSReplicationNotPublic(self):
        try:
            replication_instances = self.dmsClient.describe_replication_instances()
            non_compliant_instances = []

            for instance in replication_instances['ReplicationInstances']:
                if instance['PubliclyAccessible'] == False:
                    non_compliant_instances.append(instance['ReplicationInstanceIdentifier'])

            if not non_compliant_instances:
                self.results['dmsReplicationNotPublic'] = [1, 'All DMS replication instances are not publicly accessible']
            else:
                self.results['dmsReplicationNotPublic'] = [-1, f'DMS replication instances that are publicly accessible: {non_compliant_instances}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list DMS replication instances. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)

    def _checkSSMDocumentsNotPublic(self):
        try:
            documents = self.ssmClient.list_documents()
            non_compliant_documents = []

            for document in documents.get('DocumentIdentifiers', []):
                name = document['Name']
                try:
                    perm = self.ssmClient.describe_document_permission(
                        Name=name,
                        PermissionType="Share"
                    )
                    # If "AllAccounts" present, it's shared publicly
                    if "AllAccounts" in perm.get("AccountIds", []):
                        non_compliant_documents.append(name)
                except Exception as e:
                    _warn(f"Could not check permissions for document {name}: {e}")

            if not non_compliant_documents:
                self.results['ssmDocumentsNotPublic'] = [1, 'All SSM documents are not publicly accessible']
            else:
                self.results['ssmDocumentsNotPublic'] = [-1, f'SSM documents that are publicly accessible: {non_compliant_documents}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list SSM documents. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _check_ir_training_completed(self):
        try:
            response = self.ssmClient.get_parameter(Name='/org/ir/trainingCompleted')
            if response['Parameter']['Value'] == 'true':
                self.results['irTrainingCompleted'] = [1, 'IR training has been completed']
            else:
                self.results['irTrainingCompleted'] = [-1, 'IR training has not been completed']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to get IR training status. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkIncidentRunbookValidator(self):
        """Check if SSM Automation Documents (runbooks) exist."""
        try:
            docs = self.ssmClient.list_documents(
                DocumentFilterList=[
                    {'key': 'Owner', 'value': 'Self'},  # your account’s docs
                    {'key': 'DocumentType', 'value': 'Automation'}
                ]
            )['DocumentIdentifiers']
            
            # Filter documents with names indicating incident or IR
            ir_docs = [d for d in docs if 'incident' in d['Name'].lower() or 'response' in d['Name'].lower()]
            
            if len(ir_docs) > 0:
                self.results['incidentRunbookValidator'] = [1, f"Found {len(ir_docs)} incident/IR runbook(s)"]
            else:
                self.results['incidentRunbookValidator'] = [-1, "No incident/IR runbooks found"]
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list SSM documents. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
            
    def _check_rpo_rto_defined(self):
        """Check if RPO and RTO parameters are defined in SSM Parameter Store."""
        try:
            params = self.ssmClient.describe_parameters()["Parameters"]
            defined = any("RPO" in p["Name"] or "RTO" in p["Name"] for p in params)
            if defined:
                self.results["rpoRtoDefined"] = [1, "RPO and/or RTO parameters are defined"]
            else:
                self.results["rpoRtoDefined"] = [-1, "RPO and/or RTO parameters are not defined"]
        except botocore.exceptions.ClientError as e:
            ecode = e.response["Error"]["Code"]
            if ecode == "AccessDeniedException":
                _warn("Unable to describe SSM parameters. It is likely that this account is part of AWS Organizations")
            else:
                print(ecode)

    def _checkSagemakerNoDirectInternet(self):
        bad_notebooks = []
        
        notebooks = self.sageMakerClient.list_notebook_instances()['NotebookInstances']
        for nb in notebooks:
            desc = self.sageMakerClient.describe_notebook_instance(NotebookInstanceName=nb['NotebookInstanceName'])
            if desc['DirectInternetAccess'] == 'Enabled':
                bad_notebooks.append(nb['NotebookInstanceName'])

        if bad_notebooks:
            self.results['SagemakerDirectInternet'] = [-1, f"Notebooks with direct internet: {bad_notebooks}"]
        else:
            self.results['SagemakerDirectInternet'] = [1, "All notebooks private only"]
            
    def _checkSagemakerEndpointKMS(self):
        bad_endpoints = []
        try:
            endpoints = self.sagemakerClient.list_endpoints().get('Endpoints', [])
            for ep in endpoints:
                desc = self.sagemakerClient.describe_endpoint(
                    EndpointName=ep['EndpointName']
                )
                if not desc.get('KmsKeyId'):
                    bad_endpoints.append(ep['EndpointName'])

            if bad_endpoints:
                self.results['SagemakerEndpointKMS'] = [
                    -1,
                    f"Endpoints without KMS: {bad_endpoints}"
                ]
            else:
                self.results['SagemakerEndpointKMS'] = [1, "All endpoints use KMS"]

        except Exception as e:
            self.results['SagemakerEndpointKMS'] = [-1, f"Error: {str(e)}"]
            
    def _checkElasticsearchInVPC(self):
        try:
            domains = self.esClient.list_domain_names()
            non_compliant_domains = []
            non_logging_domains = []
            node_to_node_encryption_issues = []

            for domain in domains['DomainNames']:
                domain_info = self.esClient.describe_elasticsearch_domain(DomainName=domain['DomainName'])
                if domain_info['DomainStatus']['VPCOptions']['SubnetIds']:
                    non_compliant_domains.append(domain['DomainName'])
                logs = domain_info["DomainStatus"].get("LogPublishingOptions", {})
                has_logs = any(logs[log_type].get("CloudWatchLogsLogGroupArn") for log_type in logs)
                if has_logs:
                    non_logging_domains.append(domain['DomainName'])
                    
                if domain_info['DomainStatus'].get('NodeToNodeEncryptionOptions', {}).get('Enabled', False):
                    node_to_node_encryption_issues.append(domain['DomainName'])
                    
            if node_to_node_encryption_issues:
                self.results['ElasticsearchNodeToNodeEncryption'] = [-1, f'Elasticsearch domains without node-to-node encryption: {node_to_node_encryption_issues}']
            else:
                self.results['ElasticsearchNodeToNodeEncryption'] = [1, 'All Elasticsearch domains have node-to-node encryption enabled']
                
            if not non_compliant_domains:
                self.results['ElasticsearchInVPC'] = [1, 'All Elasticsearch domains are in a VPC']
            else:
                self.results['ElasticsearchInVPC'] = [-1, f'Elasticsearch domains not in a VPC: {non_compliant_domains}']
                
            if not non_logging_domains:
                self.results['ElasticsearchLoggingEnabled'] = [1, 'All Elasticsearch domains have logging enabled']
            else:
                self.results['ElasticsearchLoggingEnabled'] = [-1, f'Elasticsearch domains without logging: {non_logging_domains}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Elasticsearch domains. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkEBSManagedUpdates(self):
        try:
            envs = self.ebsClient.describe_environments()["Environments"]
            non_compliant_envs = []
            for env in envs:
                cfg = self.ebsClient.describe_configuration_settings(
                ApplicationName=env["ApplicationName"],
                EnvironmentName=env["EnvironmentName"]
                )["ConfigurationSettings"][0]
                for option in cfg["OptionSettings"]:
                    if option["Namespace"] == "aws:elasticbeanstalk:managedactions" and option["OptionName"] == "ManagedActionsEnabled":
                        if option["Value"] == "false":
                            non_compliant_envs.append(env["EnvironmentName"])
            if not non_compliant_envs:
                self.results['EBSManagedUpdates'] = [1, 'All Elastic Beanstalk environments have managed updates enabled']
            else:
                self.results['EBSManagedUpdates'] = [-1, f'Elastic Beanstalk environments without managed updates: {non_compliant_envs}']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Elastic Beanstalk environments. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkECRImageScanning(self):
        try:
            repos = self.ecrClient.describe_repositories()
            non_compliant_repos = []

            for repo in repos['repositories']:
                if not repo.get("imageScanningConfiguration", {}).get("scanOnPush", False):
                    non_compliant_repos.append(repo['repositoryName'])

            if not non_compliant_repos:
                self.results['ECRImageScanning'] = [1, 'All ECR repositories have image scanning on push enabled']
            else:
                self.results['ECRImageScanning'] = [-1, f'ECR repositories without image scanning on push: {non_compliant_repos}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list ECR repositories. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkBackupRecoveryPointEncryption(self):
        try:
            vaults = self.backupClient.list_backup_vaults()
            non_compliant_vaults = []

            for vault in vaults['BackupVaultList']:
                if not vault.get('EncryptionKeyArn'):
                    non_compliant_vaults.append(vault['BackupVaultName'])
    
            if not non_compliant_vaults:
                self.results['BackupRecoveryPointEncryption'] = [1, 'All Backup vaults have encryption enabled']
            else:
                self.results['BackupRecoveryPointEncryption'] = [-1, f'Backup vaults without encryption: {non_compliant_vaults}']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Backup vaults. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
            
    def _checkECSTaskMemoryHardLimit(self):
        try:
            paginator = self.ecsclient.get_paginator('list_task_definitions')
            page_iterator = paginator.paginate()
            non_compliant_tasks = []

            for page in page_iterator:
                for task_arn in page.get('taskDefinitionArns', []):
                    task_response = self.ecsclient.describe_task_definition(taskDefinition=task_arn)
                    task = task_response.get('taskDefinition', {})
                    
                    # Optional: Skip non-EC2 tasks
                    if task.get("requiresCompatibilities") and "EC2" not in task["requiresCompatibilities"]:
                        continue

                    containers = task.get('containerDefinitions', [])
                    for container in containers:
                        memory = container.get('memory')
                        memory_reservation = container.get('memoryReservation')

                        # Validate hard memory limit
                        if memory is None or (memory_reservation is not None and memory_reservation >= memory):
                            non_compliant_tasks.append(task_arn)
                            break  # No need to check other containers in this task

            if not non_compliant_tasks:
                self.results['ECSTaskMemoryHardLimit'] = [1, 'All ECS tasks have hard memory limits set']
            else:
                self.results['ECSTaskMemoryHardLimit'] = [-1, f'ECS tasks without valid hard memory limits: {non_compliant_tasks}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                print('WARNING: Unable to list ECS Task Definitions. It is likely that this account is part of AWS Organizations or lacks permissions.')
            else:
                print(f"AWS Error: {ecode}")

    def _check_backup_plan_frequency_and_retention(self):
        try:
            plans = self.backupClient.list_backup_plans()
            non_compliant_plans = []

            for plan in plans.get('BackupPlansList', []):
                plan_id = plan['BackupPlanId']
                plan_details = self.backupClient.get_backup_plan(BackupPlanId=plan_id)
                rules = plan_details.get('BackupPlan', {}).get('Rules', [])
                
                for rule in rules:
                    frequency = rule.get('ScheduleExpression')
                    retention = rule.get('Lifecycle', {}).get('DeleteAfterDays')
                    
                    # Check if frequency is at least daily and retention is at least 30 days
                    if not frequency or not frequency.startswith('cron(0 0') or (retention is None or retention < 30):
                        non_compliant_plans.append(plan['BackupPlanName'])
                        break  # No need to check other rules in this plan

            if not non_compliant_plans:
                self.results['BackupPlanFrequencyAndRetention'] = [1, 'All backup plans have appropriate frequency and retention']
            else:
                self.results['BackupPlanFrequencyAndRetention'] = [-1, f'Backup plans with insufficient frequency or retention: {non_compliant_plans}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Backup plans. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _check_recovery_point_retention(self):
        try:
            vaults = self.backupClient.list_backup_vaults()['BackupVaultList']
            non_compliant_vaults = []
            
            for vault in vaults:
                recovery_points = self.backupClient.list_recovery_points_by_backup_vault(
                    BackupVaultName=vault['BackupVaultName']
                )['RecoveryPoints']

                for rp in recovery_points:
                    retention = (rp['CalculatedLifecycle'].get('DeleteAt') - rp['CreationDate']).days
                    
                    if retention < 30:
                        non_compliant_vaults.append(vault['BackupVaultName'])
                        break  # No need to check other recovery points in this vault
            if not non_compliant_vaults:
                self.results['RecoveryPointRetention'] = [1, 'All recovery points have at least 30 days retention']
            else:
                self.results['RecoveryPointRetention'] = [-1, f'Vaults with recovery points having less than 30 days retention: {non_compliant_vaults}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Backup vaults or recovery points. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _check_acm_certificate_expiration(self):
        try:
            paginator = self.acmClient.get_paginator('list_certificates')
            page_iterator = paginator.paginate()
            expiring_certificates = []

            for page in page_iterator:
                for cert_summary in page.get('CertificateSummaryList', []):
                    cert_arn = cert_summary['CertificateArn']
                    cert_details = self.acmClient.describe_certificate(CertificateArn=cert_arn)
                    not_after = cert_details['Certificate']['NotAfter']
                    
                    if (not_after - datetime.now(tz=tzlocal())).days < 30:
                        expiring_certificates.append(cert_summary['DomainName'])

            if not expiring_certificates:
                self.results['ACMCertificateExpiration'] = [1, 'No ACM certificates expiring within 30 days']
            else:
                self.results['ACMCertificateExpiration'] = [-1, f'ACM certificates expiring within 30 days: {expiring_certificates}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list ACM certificates. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _check_access_analyzer_findings(self):
        try:
            analyzers = self.accessanalyzerClient.list_analyzers()['analyzers']
            if not analyzers:
                self.results['AccessAnalyzerFindings'] = [-1, 'No Access Analyzer found in the account']
                return
            
            findings_issues = []
            for analyzer in analyzers:
                findings = self.accessanalyzerClient.list_findings(analyzerName=analyzer['name'])['findings']
                for finding in findings:
                    name = analyzer['name']
                    findings = self.accessanalyzerClient.list_findings(
                        analyzerName=name,
                        filter={
                            'status': {'eq': ['ACTIVE']}
                        }
                    )['findings']
                    
                if findings:
                    findings_issues.append((analyzer['name'], len(findings)))
                    
            if not findings_issues:
                self.results['AccessAnalyzerFindings'] = [1, 'No active Access Analyzer findings']
            else:
                details = ', '.join([f"{name} ({count} findings)" for name, count in findings_issues])
                self.results['AccessAnalyzerFindings'] = [-1, f'Active Access Analyzer findings: {details}']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Access Analyzers or findings. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkVendorAssessment(self):
        try:
            assessments = self.auditmanagerClient.list_assessments()['assessmentMetadata']
            compliant_assessments = []

            for assessment in assessments:
                if assessment['status'] == 'COMPLETE':
                    compliant_assessments.append(assessment['name'])

            if not compliant_assessments:
                self.results['VendorAssessment'] = [1, 'No compliant Audit Manager assessments found']
            else:
                self.results['VendorAssessment'] = [-1, f'Compliant Audit Manager assessments: {compliant_assessments}']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Audit Manager assessments. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkConformancePacksApplied(self):
        try:
            packs = self.configClient.describe_conformance_packs()['ConformancePackNames']
            if packs:
                self.results['ConformancePacksApplied'] = [1, f'Conformance packs applied: {packs}']
            else:
                self.results['ConformancePacksApplied'] = [-1, 'No conformance packs applied']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Config conformance packs. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkComplianceFrameworksApplied(self):
        try:
            frameworks = self.auditmanagerClient.list_assessment_frameworks(type='STANDARD')['frameworkMetadataList']
            applied = any(f['name'] in ['SOC 2','ISO 27001','GDPR','HIPAA'] for f in frameworks)
            
            if applied:
                self.results['ComplianceFrameworksApplied'] = [1, 'At least one major compliance framework applied']
            else:
                self.results['ComplianceFrameworksApplied'] = [-1, 'No major compliance frameworks applied']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Audit Manager frameworks. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)
                
    def _checkServiceControlPolicies(self):
        try:
            policies = self.orgClient.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']
            if policies:
                self.results['ServiceControlPolicies'] = [1, f'Service Control Policies exist: {[p["Name"] for p in policies]}']
            else:
                self.results['ServiceControlPolicies'] = [-1, 'No Service Control Policies found']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to list Service Control Policies. It is likely that this account is part of AWS Organizations')
            else:
                print(ecode)