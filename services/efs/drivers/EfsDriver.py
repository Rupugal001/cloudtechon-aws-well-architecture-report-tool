from services.Evaluator import Evaluator

import boto3
import botocore

class EfsDriver(Evaluator):
    def __init__(self, efs, efs_client):
        self.efs = efs
        self.efs_client = efs_client
        self.backup_client = boto3.client('backup')
        self.__config_prefix = 'efs::'

        self.results = {}

        self._resourceName = efs['FileSystemId']
        print('Init EFS')
        self.init()

    def _checkEncrypted(self):
        self.results['EncryptedAtRest'] = [1, 'Enabled']
        if self.efs['Encrypted'] != 1:
            self.results['EncryptedAtRest'] = [-1, 'Disabled']

    def _checkLifecycle_configuration(self):
        self.results['Lifecycle'] = [1, 'Enabled']
        efs_id = self.efs['FileSystemId']

        life_cycle = self.efs_client.describe_lifecycle_configuration(
            FileSystemId=efs_id
        )

        if len(life_cycle['LifecyclePolicies']) == 0:
            self.results['EnabledLifecycle'] = [-1, 'Disabled']

    def _checkBackupPolicy(self):
        self.results['AutomatedBackup'] = [1, 'Enabled']
        efs_id = self.efs['FileSystemId']

        try:
            backup = self.efs_client.describe_backup_policy(
                FileSystemId=efs_id
            )
        except self.efs_client.exceptions.PolicyNotFound as e:
            print("(Not showstopper): Error encounter during efs describe_backup_policy {}".format(e.response['Error']['Code']))
            return
        

        if backup['BackupPolicy']['Status'] == 'DISABLED':
            self.results['AutomatedBackup'] = [-1, 'Disabled']
            
    def _checkEFSInBackupPlan(self):
        protected_resources = self.backup_client.list_protected_resources()['Results']

        for res in protected_resources:
            if res['ResourceType'] == 'EFS':
                if res['ResourceArn'].endswith(self.efs['FileSystemId']):
                    self.results['EFSBackup'] = [1, 'In backup plan']
                else:
                    self.results['EFSBackup'] = [-1, 'Not in backup plan']

    def _checkSingleAZ(self):
        if 'AvailabilityZoneName' in self.efs:
            self.results['IsSingleAZ'] = [-1, self.efs['AvailabilityZoneName']]

    def _checkAccessPointUserIdentity(self):
        self.results['AccessPointUserIdentity'] = [1, 'Enabled']
        efs_id = self.efs['FileSystemId']

        access_points = self.efs_client.describe_access_points(
            FileSystemId=efs_id
        )

        for access_point in access_points['AccessPoints']:
            if access_point['OwnerId'] != self.efs['OwnerId']:
                self.results['AccessPointUserIdentity'] = [-1, 'Disabled']
                break
