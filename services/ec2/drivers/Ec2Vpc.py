import boto3
import botocore

from services.Evaluator import Evaluator

class Ec2Vpc(Evaluator):
    def __init__(self, vpc, flowLogs, ec2Client):
        super().__init__()
        self.vpc = vpc
        self.flowLogs = flowLogs
        self.ec2Client = ec2Client

        self._resourceName = vpc['VpcId']

        self.init()
        return
        
    def _checkVpcFlowLogEnabled(self):
        vpcId = self.vpc['VpcId']
        for flowLog in self.flowLogs:
            if flowLog['ResourceId'] == vpcId and flowLog['TrafficType'] != 'ACCEPT':
                self.results['VPCFlowLogEnabled'] = [1, vpcId]
                return
                
        self.results['VPCFlowLogEnabled'] = [-1, self.vpc['VpcId']]
        return
    
    def _checkEC2InVPC(self):
        vpcId = self.vpc['VpcId']
        try:
            response = self.ec2Client.describe_instances(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpcId]
                    }
                ]
            )
            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append(instance['InstanceId'])
                    
            if len(instances) > 0:
                self.results['EC2InVPC'] = [1, f"{vpcId} has {len(instances)} EC2 instances"]
            else:
                self.results['EC2InVPC'] = [-1, f"{vpcId} has no EC2 instances"]
                
        except botocore.exceptions.ClientError as e:
            self.results['EC2InVPC'] = [-1, f"Error checking EC2 instances in VPC {vpcId}: {str(e)}"]
        
        return
    
    