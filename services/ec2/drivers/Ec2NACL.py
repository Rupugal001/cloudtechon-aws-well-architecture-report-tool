import boto3
import botocore

from services.Evaluator import Evaluator

class Ec2NACL(Evaluator):
    def __init__(self, nacl, ec2Client):
        super().__init__()
        self.nacl = nacl
        self.ec2Client = ec2Client

        self._resourceName = nacl['NetworkAclId']

        self.init()
        return
    
    def _checkNACLAssociation(self):
        if not self.nacl['Associations']:
            self.results['NACLAssociated'] = [-1, self.nacl['NetworkAclId']]
        else:
            assocCount = len(self.nacl['Associations'])
            if assocCount > 1:
                self.results['NACLAssociated'] = [1, assocCount]
            
        return
        
    def _checkNACLIngressSensitivePort(self):
        sensitivePort = [22, 3389]
        violations = []
        for entry in self.nacl['Entries']:
            if entry['RuleAction'] == 'allow' and entry['Egress'] == False:
                if ('CidrBlock' in entry and entry['CidrBlock'] == '0.0.0.0/0') or ('Ipv6CidrBlock' in entry and entry['Ipv6CidrBlock'] == '::/0'):
                    if 'PortRange' in entry:
                        portFrom = entry['PortRange']['From']
                        portTo = entry['PortRange']['To']
                        for port in sensitivePort:
                            if portFrom <= port and portTo >= port:
                                violations.append(port)
                                # self.results['NACLSensitivePort'] = [-1, self.nacl['NetworkAclId']]
                                # return
        if violations:
            self.results['NACLSensitivePort'] = [-1, list(set(violations))]
        else:
            self.results['NACLSensitivePort'] = [1, self.nacl['NetworkAclId']]

        return