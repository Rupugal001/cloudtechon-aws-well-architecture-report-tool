import json
import os
import sys
from datetime import datetime, timedelta

import botocore
import boto3

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator
import constants as _C

class LambdaCommon(Evaluator):
    RUNTIME_PREFIX = [
        'nodejs',
        'python',
        'java',
        'dotnetcore',
        'dotnet',
        'go',
        'ruby'
    ]

    CUSTOM_RUNTIME_PREFIX = [
        'provided'
    ]

    RUNTIME_PATH = _C.BOTOCORE_DIR + '/data/lambda/2015-03-31/service-2.json'
    CW_HISTORY_DAYS = [30, 7]

    def __init__(self, lambda_, lambda_client, iam_client, cloudwatch_client, role_count):
        self.lambda_ = lambda_
        self.function_name = lambda_['FunctionName']
        self.role_count = role_count
        self.lambda_client = lambda_client
        self.iam_client = iam_client
        self.cloudwatch_client = cloudwatch_client
        self.sqs = boto3.client('sqs')
        self.sns = boto3.client('sns')
        self._resourceName = self.function_name

        self.results = {}
        self.init()
    
    @staticmethod
    def get_arn_role_name(arn):
        array = arn.split("/")
        role_name = array[-1]
        return role_name

    def get_invocation_count(self, day):
        cw_client = Config.get('CWClient')

        dimensions = [
            {
                'Name': 'FunctionName',
                'Value': self.function_name
            }
        ]

        results = cw_client.get_metric_statistics(
            Dimensions=dimensions,
            Namespace='AWS/Lambda',
            MetricName='Invocations',
            StartTime=datetime.utcnow() - timedelta(days=day),
            EndTime=datetime.utcnow(),
            Period=day * 24 * 60 * 60,
            Statistics=['SampleCount']
        )

        if not results['Datapoints']:
            return 0
        else:
            for result in results['Datapoints']:
                return result['SampleCount']
            
    def _get_sqs_url_from_arn(self, arn):
        parts = arn.split(":")
        region = parts[3]
        account_id = parts[4]
        queue_name = parts[5]
        return f"https://sqs.{region}.amazonaws.com/{account_id}/{queue_name}"

    
    def _check_architectures_is_arm(self):
        if 'arm64' in self.lambda_['Architectures']:
            return
        
        self.results['UseArmArchitecture'] = [-1, ', '.join(self.lambda_['Architectures'])]
    
    def _check_function_url_in_used_and_auth(self):
        try:
            url_config = self.lambda_client.list_function_url_configs(
                FunctionName=self.function_name
            )
            if url_config['FunctionUrlConfigs']:
                self.results['lambdaURLInUsed'] = [-1, "Enabled"]

                for config in url_config['FunctionUrlConfigs']:
                    if config['AuthType'] == 'NONE':
                        self.results['lambdaURLWithoutAuth'] = [-1, config['AuthType']]
                        return

        except botocore.exceptions.ClientError as e:
            print("No permission to access lambda:list_function_url_configs")
        return

    def _check_missing_role(self):
        role_arn = self.lambda_['Role']
        role_name = self.get_arn_role_name(role_arn)

        try:
            role = self.iam_client.get_role(
                RoleName=role_name
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                self.results['lambdaMissingRole'] = [-1, '']
            else:
                raise e
        return

    def _check_code_signing_disabled(self):
        if self.lambda_['PackageType'] != 'Zip':
            return
        try:
            code_sign = self.lambda_client.get_function_code_signing_config(
                FunctionName=self.function_name
            )
            if not code_sign.get('CodeSigningConfigArn'):
                self.results['lambdaCodeSigningDisabled'] = [-1, 'Disabled']
        except botocore.exceptions.ClientError as e:
            print("No permission to access get_function_code_signing_config")

        return

    def _check_dead_letter_queue_disabled(self):
        config = self.lambda_client.get_function_configuration(
            FunctionName=self.function_name
        )
        dlq = config.get('DeadLetterConfig', {})
        if not dlq:
            self.results['lambdaDeadLetterQueueDisabled'] = [-1, 'Disabled']
        else:
            self.results['lambdaDeadLetterQueueDisabled'] = [1, 'Enabled']

        if not dlq.get('TargetArn'):
            self.results['lambdaGracefulDegradation'] = [-1, 'Disabled']
        else:
            self.results['lambdaGracefulDegradation'] = [1, 'Enabled']
            
        if not config.get('Timeout') or config.get('Timeout') < 3:
            self.results['lambdaClientTimeouts'] = [-1, 'Timeout less than 3 seconds']
        else:
            self.results['lambdaClientTimeouts'] = [1, 'Timeout is ' + str(config.get('Timeout')) + ' seconds']

        self.results["Stateless"] = [0, "Cannot automatically validate statelessness"]
        
        # 7. Emergency Levers (DLQ accessibility)
        if dlq:
            dlq_arn = config.get('DeadLetterConfig').get('TargetArn', '')
            if dlq_arn:
                if dlq_arn.startswith("arn:aws:sqs"):
                    try:
                        self.sqs.get_queue_attributes(
                            QueueUrl=self._get_sqs_url_from_arn(dlq_arn),
                            AttributeNames=["QueueArn"]
                        )
                        self.results["EmergencyLevers"] = [1, f"SQS DLQ exists: {dlq_arn}"]
                    except Exception as e:
                        self.results["EmergencyLevers"] = [-1, f"SQS DLQ not accessible: {str(e)}"]
                elif dlq_arn.startswith("arn:aws:sns"):
                    try:
                        self.sns.get_topic_attributes(
                            TopicArn=dlq_arn
                        )
                        self.results["EmergencyLevers"] = [1, f"SNS DLQ exists: {dlq_arn}"]
                    except Exception as e:
                        self.results["EmergencyLevers"] = [-1, f"SNS DLQ not accessible: {str(e)}"]
                else:
                    self.results["EmergencyLevers"] = [0, f"Unknown DLQ type: {dlq_arn}"]
            else:
                self.results["EmergencyLevers"] = [-1, "No DLQ configured"]
        else:
            self.results["EmergencyLevers"] = [-1, "No DLQ configured"]
        return

    def _check_env_var_default_key(self):
        function_name = self.lambda_['FunctionName']
        if not self.lambda_.get('KMSKeyArn'):
            self.results['lambdaCMKEncryptionDisabled'] = [-1, 'Disabled']
        return

    def _check_enhanced_monitor(self):
        if 'Layers' in self.lambda_:
            layers = self.lambda_['Layers']
            for layer in layers:
                if 'LambdaInsightsExtension' in layer['Arn']:
                    return

        self.results['lambdaEnhancedMonitoringDisabled'] = [-1, 'Disabled']
        return

    def _check_provisioned_concurrency(self):
        concurrency = self.lambda_client.get_function_concurrency(
            FunctionName=self.function_name
        )

        if not concurrency.get('ReservedConcurrentExecutions'):
            self.results['lambdaReservedConcurrencyDisabled'] = [-1, 'Disabled']
        else:
            self.results['lambdaReservedConcurrencyDisabled'] = [1, 'Enabled']

        return

    def _check_tracing_enabled(self):
        if 'TracingConfig' in self.lambda_ and 'Mode' in self.lambda_['TracingConfig'] and self.lambda_['TracingConfig']['Mode'] == 'PassThrough':
            self.results['lambdaTracingDisabled'] = [-1, 'Disabled']

        return

    def _check_role_reused(self):
        if self.role_count[self.lambda_['Role']] > 1:
            self.results['lambdaRoleReused'] = [-1, self.lambda_['Role']]
        return
    
    ## <TODO>
    ## Cache the runtime_version and enum instead of looping everytime
    def _check_runtime(self):
        if not os.path.exists(self.RUNTIME_PATH):
            print("Skipped runtime version check due to unable to locate runtime option path")
            return
        
        ## Container based will skip
        if self.lambda_['PackageType'] != 'Zip':
            return

        arr = Config.get('lambdaRunTimeList', False)
        if arr == False:
            with open(self.RUNTIME_PATH, 'r') as f:
                arr = json.load(f)
                
            Config.set('lambdaRunTimeList', arr)

        runtime = self.lambda_['Runtime']

        runtime_prefix = ''
        runtime_version = ''

        for prefix in self.CUSTOM_RUNTIME_PREFIX:
            if runtime.startswith(prefix):
                return

        for prefix in self.RUNTIME_PREFIX:
            if runtime.startswith(prefix):
                runtime_prefix = prefix

                replace_arr = [runtime_prefix]
                if prefix in ['go', 'nodejs']:
                    replace_arr.append('.x')
                if prefix == 'nodejs':
                    replace_arr.append('-edge')

                runtime_version = runtime
                for item in replace_arr:
                    runtime_version = runtime_version.replace(item, '')
                break

        # skip java check
        if runtime_prefix == 'java':
            return

        for option in arr['shapes']['Runtime']['enum']:
            if not option.startswith(runtime_prefix):
                continue
            else:
                option_version = option
                for item in replace_arr:
                    option_version = option_version.replace(item, '')
                if option_version == '':
                    option_version = 0

                if float(option_version) > float(runtime_version):
                    self.results['lambdaRuntimeUpdate'] = [-1, runtime]
                    return

        return
    
    
    def _check_function_in_used(self):
        for day in self.CW_HISTORY_DAYS:
            cnt = self.get_invocation_count(day)

            if cnt == 0:
                self.results['lambdaNotInUsed' + str(day) + 'Days'] = [-1, '']
                return

        return
    
    def _check_function_public_access(self):
        try:
            results = self.lambda_client.get_policy(
                FunctionName=self.function_name
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return
            else:
                raise e
                
        if results.get('Policy'):
            doc = json.loads(results.get('Policy'))
            pObj = Policy(doc)
            pObj.inspectPrinciple()
            
            if pObj.hasPublicAccess() == True:
                self.results['lambdaPublicAccess'] = [-1, 'Enabled']
            else:
                self.results['lambdaPublicAccess'] = [1, 'No public access']
            
        return

    def _checkLambdaInsideVpc(self):
        if 'VpcConfig' in self.lambda_ and 'VpcId' in self.lambda_['VpcConfig']:
            self.results['lambdaInsideVpc'] = [1, self.lambda_['VpcConfig']['VpcId']]
        else:
            self.results['lambdaInsideVpc'] = [-1, 'Not Configured']
        return
    
    def _checkLambdaConcurrency(self):
        
        try:
            response = self.lambda_client.get_function_configuration(FunctionName=self.function_name)
            reserved_concurrency = response.get('ReservedConcurrentExecutions', None)
            # For simplicity, let's assume the default account concurrency limit (10000) as a placeholder
            account_concurrency_limit = 10000 
            
            # Get the current date for fetching CloudWatch metrics
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=1)
            
            # Retrieve CloudWatch metrics for Lambda usage
            metrics = self.cloudwatch_client.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='ConcurrentExecutions',
                Dimensions=[
                    {
                        'Name': 'FunctionName',
                        'Value': self.function_name
                    },
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,  # Hourly intervals
                Statistics=['Sum']
            )
            # Calculate the total concurrency usage from the CloudWatch metrics
            if metrics['Datapoints']:
                total_concurrency_usage = max(dp['Sum'] for dp in metrics['Datapoints'])
            else:
                total_concurrency_usage = 0
                
            # Check if there are concurrency limits and compare
            if reserved_concurrency:
                if total_concurrency_usage > reserved_concurrency:
                    self.results['lambdaConcurrency'] = [-1, 'Exceeded']
                else:
                    self.results['lambdaConcurrency'] = [1, 'Within limits']
            else:
                if total_concurrency_usage > account_concurrency_limit:
                    self.results['lambdaConcurrency'] = [-1, 'Exceeded account limit']
                else:
                    self.results['lambdaConcurrency'] = [1, 'Within account limits']
        except botocore.exceptions.ClientError as e:
            print(f"Error fetching Lambda concurrency data: {e}")
            self.results['lambdaConcurrency'] = [-1, 'Error fetching data']

    def _checkControlAndLimitRetries(self):
        retry_checks = []
        mappings = self.lambda_client.list_event_source_mappings(FunctionName=self.function_name)["EventSourceMappings"]

        for mapping in mappings:
            retry = mapping.get("MaximumRetryAttempts")
            retry_checks.append(retry if retry is not None else "default")
        
        if not retry_checks:
            self.results['lambdaControlAndLimitRetries'] = [-1, 'No event source mappings']
        else:
            self.results['lambdaControlAndLimitRetries'] = [1, 'All checks passed']

        return
    
    def _check_lambda_multi_az(self):
        if 'VpcConfig' not in self.lambda_ or not self.lambda_['VpcConfig'].get('SubnetIds'):
            self.results['lambdaMultiAZ'] = [-1, 'Not in VPC']
            return
        
        subnet_ids = self.lambda_['VpcConfig']['SubnetIds']
        ec2_client = boto3.client('ec2')
        
        try:
            subnets = ec2_client.describe_subnets(SubnetIds=subnet_ids)['Subnets']
            azs = {subnet['AvailabilityZone'] for subnet in subnets}
            
            if len(azs) > 1:
                self.results['lambdaMultiAZ'] = [1, f'Multiple AZs: {", ".join(azs)}']
            else:
                self.results['lambdaMultiAZ'] = [-1, f'Single AZ: {list(azs)[0]}']
        except botocore.exceptions.ClientError as e:
            print(f"Error fetching subnet data: {e}")
            self.results['lambdaMultiAZ'] = [-1, 'Error fetching subnet data']