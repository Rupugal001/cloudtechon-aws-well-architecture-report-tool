import boto3
import botocore
import datetime
import time
from utils.Config import Config

from datetime import timedelta
from services.Evaluator import Evaluator

import constants as _C

import json

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super().default(obj)

        # print(json.dumps(self.ec2InstanceData, indent=4, cls=DateTimeEncoder))


class EC2SSMManage(Evaluator):
    def __init__(self, instance, ssmClient, ec2Client, codebuildClient):
        super().__init__()
        self.instance = instance
        self.ssmClient = ssmClient
        self.ec2Client = ec2Client
        self.codebuildClient = codebuildClient
    
        self._resourceName = instance['InstanceId']

        self.init()

    def _checkEC2ManagedBySSM(self):
        all_instances = []
        for r in self.ec2Client.describe_instances()['Reservations']:
            for i in r['Instances']:
                all_instances.append(i['InstanceId'])
                
        non_managed = [i for i in all_instances if i != self.instance['InstanceId']]
        
        if non_managed:
            self.results['EC2ManagedBySSM'] = [-1, f"Instances not managed: {non_managed}"]
        else:
            self.results['EC2ManagedBySSM'] = [1, "All instances managed by SSM"]
            
    def _checkEC2ManagedInstanceCompliance(self):
        non_compliant = []
        compliance = self.ssmClient.list_compliance_items(
                ResourceIds=[self.instance['InstanceId']],
                ResourceTypes=['ManagedInstance'],
                Filters=[
                    {
                        'Key': 'ComplianceType',
                        'Values': ['Patch'],
                        'Type': 'EQUAL'
                    }
                ]
            )
        if not compliance['ComplianceItems']:
                non_compliant.append(self.instance['InstanceId'])
                
        if non_compliant:
            self.results['EC2ManagedInstanceCompliance'] = [-1, f"Instances missing patch compliance: {non_compliant}"]
        else:
            self.results['EC2ManagedInstanceCompliance'] = [1, "All instances patch compliant"]

    
    def _checkCodeBuildEnvVarCreds(self):
        # Get all project names
        # print("Checking CodeBuild Projects for plaintext credentials in environment variables...")
        projects = self.codebuildClient.list_projects()
        project_names = projects['projects']

        insecure_projects = []

        # Process in chunks of 100
        for i in range(0, len(project_names), 100):
            chunk = project_names[i:i+100]
            project_batch = self.codebuildClient.batch_get_projects(names=chunk)

            for project in project_batch['projects']:
                env_vars = project['environment'].get('environmentVariables', [])
                for var in env_vars:
                    if (
                        var['type'] == 'PLAINTEXT' and
                        ('AWS_SECRET_ACCESS_KEY' in var['name'] or 'AWS_ACCESS_KEY_ID' in var['name'])
                    ):
                        insecure_projects.append(project['name'])
                        break  # no need to scan more env vars in this project

        if insecure_projects:
            self.results['CodeBuildEnvVarCreds'] = [-1, f"Projects with creds in env vars: {insecure_projects}"]
        else:
            self.results['CodeBuildEnvVarCreds'] = [1, "No projects with creds in env vars"]

    def _checkCodebuildArtifactEncryption(self):
        # Get all project names
        projects = self.codebuildClient.list_projects()
        non_encrypted = []
        
        for project in projects['projects']:
            project_info = self.codebuildClient.batch_get_projects(names=[project])
            enc = project_info['projects'][0].get('encryptionKey', {})

            if not enc:
                non_encrypted.append(project)

        if non_encrypted:
            self.results['CodeBuildArtifactEncryption'] = [-1, f"Projects with unencrypted artifacts: {non_encrypted}"]
        else:
            self.results['CodeBuildArtifactEncryption'] = [1, "All projects have artifact encryption enabled"]

            
    def _checkPatchCompliance(self):
        # Check if the instance is compliant with patch baselines
        compliance = self.ssmClient.describe_instance_patch_states(
            InstanceIds=[self.instance['InstanceId']]
        )

        non_compliant = []
        for patch in compliance['InstancePatchStates']:
            # Check if there are any missing or failed patches
            if patch.get('MissingCount', 0) > 0 or patch.get('FailedCount', 0) > 0:
                non_compliant.append(self.instance['InstanceId'])

        if non_compliant:
            self.results['PatchCompliance'] = [-1, f"Instances missing patch compliance: {non_compliant}"]
        else:
            self.results['PatchCompliance'] = [1, "All instances patch compliant"]


    def _checkSSMAssociationCompliance(self):
        """
        Checks if the instance has any non-compliant SSM associations.
        Updates self.results['SSMAssociationCompliance'] with the result.
        """
        instance_id = self.instance['InstanceId']
        non_compliant = []

        try:
            response = self.ssmClient.list_instance_associations(
                InstanceId=instance_id
            )
            associations = response.get('InstanceAssociations', [])
        except Exception as e:
            self.results['SSMAssociationCompliance'] = [-1, f"Error retrieving associations for {instance_id}: {str(e)}"]
            return

        if not associations:
            # Treat instance with no associations as non-compliant
            non_compliant.append(instance_id)
        else:
            for association in associations:
                assoc_id = association['AssociationId']
                try:
                    compliance = self.ssmClient.describe_instance_association_status(
                        InstanceAssociationId=assoc_id
                    )
                    status = compliance['InstanceAssociationStatusInfo']['Status']
                    if status != 'Success':
                        non_compliant.append(instance_id)
                        break  # Stop at first non-compliant association
                except Exception as e:
                    self.results['SSMAssociationCompliance'] = [-1, f"Error checking association {assoc_id} for {instance_id}: {str(e)}"]
                    return

        if non_compliant:
            self.results['SSMAssociationCompliance'] = [-1, f"Instances with non-compliant associations: {non_compliant}"]
        else:
            self.results['SSMAssociationCompliance'] = [1, "All instances have compliant SSM associations"]
