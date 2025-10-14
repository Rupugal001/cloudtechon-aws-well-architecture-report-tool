import boto3
import botocore

import constants as _C

from services.Evaluator import Evaluator

class Ec2ElbClassic(Evaluator):
    def __init__(self, elb, elbClient):
        super().__init__()
        self.elb = elb
        self.elbClient = elbClient

        self._resourceName = elb['LoadBalancerName']

        self.init()
        
    def _checkClassicLoadBalancer(self):
        self.results['ELBClassicLB'] = ['-1', self.elb['LoadBalancerName']]
        return
        
    def _checkListenerPortEncrypt(self):
        listeners = self.elb['ListenerDescriptions']
        
        for listener in listeners:
            if listener['Listener']['Protocol'] in ['HTTP', 'TCP']:
                self.results['ELBListenerInsecure'] = ['-1', listener['Listener']['Protocol']]
            else:
                self.results['ELBListenerSecure'] = ['1', listener['Listener']['Protocol']]
        return
        
    def _checkSecurityGroupNo(self):
        if(len(self.elb['SecurityGroups']) > 50):
            self.results['ELBSGNumber'] = [-1, len(self.elb['SecurityGroups'])]
        
        return
    
    def _checkAttributes(self):
        results = self.elbClient.describe_load_balancer_attributes(
            LoadBalancerName = self.elb['LoadBalancerName']    
        )
        
        attributes = results['LoadBalancerAttributes']
        
        if 'CrossZoneLoadBalancing' in attributes and attributes['CrossZoneLoadBalancing']['Enabled'] != 1:
            self.results['ELBCrossZone'] = ['-1', attributes['CrossZoneLoadBalancing']['Enabled']]
            
        if 'ConnectionDraining' in attributes and attributes['ConnectionDraining']['Enabled'] != 1:
            self.results['ELBConnectionDraining'] = ['-1', attributes['ConnectionDraining']['Enabled']]
            
        return
    
    
    def _check_elb_acm_certificate_required(self):
        listeners = self.elb['ListenerDescriptions']
        non_acm_cert_listeners = []
        
        for listener in listeners:
            if listener['Listener']['Protocol'] in ['HTTPS', 'SSL']:
                cert_arn = listener['Listener'].get('SSLCertificateId', '')
                if not cert_arn.startswith('arn:aws:acm:'):
                    non_acm_cert_listeners.append(cert_arn)
        
        if non_acm_cert_listeners:
            self.results['ELBListenerACMCertRequired'] = [-1, f'Listeners with non-ACM certificates: {non_acm_cert_listeners}']
        else:
            self.results['ELBListenerACMCertRequired'] = [1, 'All SSL/HTTPS listeners use ACM certificates']