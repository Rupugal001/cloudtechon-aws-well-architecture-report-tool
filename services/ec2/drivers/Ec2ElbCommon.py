from xmlrpc import client
import boto3
import botocore

import constants as _C

from services.Evaluator import Evaluator
from services.ec2.drivers.Ec2SecGroup import Ec2SecGroup

class Ec2ElbCommon(Evaluator):
    def __init__(self, elb, sgList, elbClient, wafv2Client):
        super().__init__()
        self.elb = elb
        self.sgList = sgList
        self.wafv2Client = wafv2Client
        self.elbClient = elbClient

        self._resourceName = elb['LoadBalancerArn']

        self.init()
    
    # checks    
    def _checkListenerPortEncrypt(self):
        arn = self.elb['LoadBalancerArn']
        result = self.elbClient.describe_listeners(
            LoadBalancerArn = arn
        )
        
        listeners = result['Listeners']
        for listener in listeners:
            if listener['Port'] in Ec2SecGroup.NONENCRYPT_PORT:
                self.results['ELBListenerInsecure'] = [-1, listener['Port']]
        
        return
    
    def _checkSecurityGroupNo(self):
        elb = self.elb
        
        if 'SecurityGroups' in elb and len(elb['SecurityGroups']) > 50:
            self.results['ELBListenerInsecure'] = [-1, len(elb['SecurityGroups'])]
            
        return
    
    def _checkCrossZoneLB(self):
        elb = self.elb
        arn = elb['LoadBalancerArn']
        
        results = self.elbClient.describe_load_balancer_attributes(
            LoadBalancerArn = arn
        )
        
        
        for attr in results['Attributes']:
            if attr['Key'] == 'load_balancing.cross_zone.enabled' and attr['Value'] == 'false':
                self.results['ELBCrossZone'] = [-1, 'Disabled']
            else:
                self.results['ELBCrossZone'] = [1, 'Enabled']
        
        return
    
    def _checkWAFEnabled(self):
        if self.elb['Type'] != 'application':
            return
        
        wafv2Client = self.wafv2Client
        arn = self.elb['LoadBalancerArn']
        
        results = wafv2Client.get_web_acl_for_resource(
            ResourceArn = arn
        )
        
        if 'WebACL' not in results:
            self.results['ELBEnableWAF'] = [-1, 'Disabled']
        else:
            self.results['ELBEnableWAF'] = [1, 'Enabled']

        return
    
    def _checkWAFRegionalRuleNotEmpty(self):
        """Check if associated WebACL has rules"""
        if self.elb.get('Type') != 'application':
            return

        wafv2Client = self.wafv2Client
        arn = self.elb['LoadBalancerArn']

        results = wafv2Client.get_web_acl_for_resource(ResourceArn=arn)
        webacl = results.get('WebACL')

        if not webacl:
            self.results['ELBEnableWAFRuleNotEmpty'] = [-1, 'No WebACL associated']
            return

        rules = webacl.get('Rules', [])
        if not rules:
            self.results['ELBEnableWAFRuleNotEmpty'] = [-1, 'WebACL has no rules']
        else:
            self.results['ELBEnableWAFRuleNotEmpty'] = [1, f"WebACL has {len(rules)} rules"]
        return
    
    def _checkAPIGatewayWAFAssociation(self, api_arn):
        """Check if API Gateway is associated with WAF"""
        wafv2Client = self.wafv2Client

        results = wafv2Client.get_web_acl_for_resource(ResourceArn=api_arn)
        webacl = results.get('WebACL')

        if not webacl:
            self.results['APIGatewayEnableWAF'] = [-1, 'No WebACL associated']
        else:
            self.results['APIGatewayEnableWAF'] = [1, f"WebACL {webacl['Name']} associated"]
            
    def _checkWAFRegionalRuleGroupNotEmpty(self):
        """Check if all WAF RuleGroups are not empty"""
        wafv2Client = self.wafv2Client
        paginator = wafv2Client.get_paginator('list_rule_groups')

        empty_groups = []
        total_groups = 0

        for page in paginator.paginate(Scope='REGIONAL'):
            for rg in page.get('RuleGroups', []):
                total_groups += 1
                details = wafv2Client.get_rule_group(
                    Name=rg['Name'], Scope='REGIONAL', Id=rg['Id']
                )
                rules = details['RuleGroup'].get('Rules', [])
                if not rules:
                    empty_groups.append(rg['Name'])

        if empty_groups:
            self.results['WAFRuleGroups'] = [-1, f"{len(empty_groups)} of {total_groups} RuleGroups are empty: {', '.join(empty_groups)}"]
        else:
            self.results['WAFRuleGroups'] = [1, f"All {total_groups} RuleGroups have rules"]


    def _checkWAFRegionalWebACLNotEmpty(self):
        """Check if all WAF WebACLs are not empty"""
        wafv2Client = self.wafv2Client
        paginator = wafv2Client.get_paginator('list_web_acls')

        empty_acls = []
        total_acls = 0

        for page in paginator.paginate(Scope='REGIONAL'):
            for acl in page.get('WebACLs', []):
                total_acls += 1
                details = wafv2Client.get_web_acl(
                    Name=acl['Name'], Scope='REGIONAL', Id=acl['Id']
                )
                rules = details['WebACL'].get('Rules', [])
                if not rules:
                    empty_acls.append(acl['Name'])

        if empty_acls:
            self.results['WAFWebACLs'] = [-1, f"{len(empty_acls)} of {total_acls} WebACLs are empty: {', '.join(empty_acls)}"]
        else:
            self.results['WAFWebACLs'] = [1, f"All {total_acls} WebACLs have rules"]
            
    def _checkALBSGPortMatch(self):
        ## NLB not supported
        if self.elb['Type'] != 'application':
            return
        
        arn = self.elb['LoadBalancerArn']
        results = self.elbClient.describe_listeners(
            LoadBalancerArn = arn
        )
        
        portList = []
        for listener in results.get('Listeners'):
            portList.append(listener.get('Port'))
            
        unmatchPortList = portList
        
        flaggedSGs = []
        for group in self.sgList:
            for perm in group.get('IpPermissions'):
                if perm.get('FromPort') != perm.get('ToPort') or perm.get('FromPort') not in portList:
                    flaggedSGs.append(group.get('GroupId'))
        
        if len(flaggedSGs) > 0:
            self.results['ELBSGRulesMatch'] = [-1, ', '.join(flaggedSGs)]
        
        return
    
    def _checkELBLogging(self):
        elb = self.elb
        arn = elb['LoadBalancerArn']
        
        results = self.elbClient.describe_load_balancer_attributes(
            LoadBalancerArn = arn
        )
        
        for attr in results['Attributes']:
            if attr['Key'] == 'access_logs.s3.enabled' and attr['Value'] == 'false':
                self.results['ELBLogging'] = [-1, 'Disabled']
            else:
                self.results['ELBLogging'] = [1, 'Enabled']

        return

    def _checkELBDeletionProtection(self):
        """Check if ELB deletion protection is enabled"""
        elb = self.elb
        arn = elb['LoadBalancerArn']

        results = self.elbClient.describe_load_balancer_attributes(
            LoadBalancerArn=arn
        )

        for attr in results['Attributes']:
            if attr['Key'] == 'deletion_protection.enabled' and attr['Value'] == 'false':
                self.results['ELBDeletionProtection'] = [-1, 'Disabled']
            else:
                self.results['ELBDeletionProtection'] = [1, 'Enabled']

    def _check_alb_http_to_https_redirection(self):
        """Check if ALB has HTTP to HTTPS redirection"""
        lbs = self.elbClient.describe_load_balancers()['LoadBalancers']
        listeners = self.elbClient.describe_listeners(LoadBalancerArn=lbs[0]['LoadBalancerArn'])['Listeners']
        
        for listener in listeners:
            if listener['Protocol'] == 'HTTP':
                for action in listener.get('DefaultActions', []):
                    if action['Type'] == 'redirect' and action.get('RedirectConfig', {}).get('Protocol') == 'HTTPS':
                        redirect_found = True
                        break
            if redirect_found:
                break

        if redirect_found:
            self.results['ALBHTTPToHTTPSRedirection'] = [1, 'HTTP to HTTPS redirection is configured']
        else:
            self.results['ALBHTTPToHTTPSRedirection'] = [-1, 'No HTTP to HTTPS redirection found']

        return
    
    def _check_elbv2_acm_certificate_required(self):
        """Check if ALB/NLB listeners use ACM certificates"""
        lbs = self.elbClient.describe_load_balancers()['LoadBalancers']
        non_compliant_listeners = []
        
        for lb in lbs:
            listeners = self.elbClient.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])['Listeners']
            for listener in listeners:
                if listener['Protocol'] in ['HTTPS', 'TLS']:
                    cert_arns = [cert['CertificateArn'] for cert in listener.get('Certificates', [])]
                    if not any(cert_arn.startswith('arn:aws:acm:') for cert_arn in cert_arns):
                        non_compliant_listeners.append(f"{lb['LoadBalancerName']}:{listener['Port']}")

        if non_compliant_listeners:
            self.results['ELBV2ListenerACMCertRequired'] = [-1, f'Listeners without ACM certificates: {non_compliant_listeners}']
        else:
            self.results['ELBV2ListenerACMCertRequired'] = [1, 'All listeners use ACM certificates']

        return
    def check_alb_drop_invalid_headers(self):
        """Check if ALB is configured to drop invalid headers"""
        lbs = self.elbClient.describe_load_balancers()['LoadBalancers']
        non_compliant_listeners = []
        for lb in lbs:
            attrs = self.elbClient.describe_load_balancer_attributes(LoadBalancerArn=lb['LoadBalancerArn'])['Attributes']
            drop_invalid = next((a['Value'] for a in attrs if a['Key'] == 'routing.http.drop_invalid_header_fields.enabled'), 'false')
            if drop_invalid != 'true':
                non_compliant_listeners.append(lb['LoadBalancerName'])

        if non_compliant_listeners:
            self.results['ALBDropInvalidHeaders'] = [-1, 'Not configured to drop invalid headers']
        else:
            self.results['ALBDropInvalidHeaders'] = [1, 'Configured to drop invalid headers']

        return

    
