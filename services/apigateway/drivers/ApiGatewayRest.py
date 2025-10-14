import boto3
import botocore
import constants as _C
import json

from services.Service import Service
from services.Evaluator import Evaluator

class ApiGatewayRest(Evaluator):
    
    def __init__(self, api, apiClient):
        super().__init__()
        self.apiClient = apiClient
        self.api = api

        self._resourceName = api['name']

        return

    def _checkStage(self):
        resp = self.apiClient.get_stages(
            restApiId = self.api['id'],
        )
        item = resp['item']
        if item == []:
            self.results['IdleAPIGateway'] = [-1, "No stages found"]
            return
        # for stage in item:
        #     if stage['methodSettings'] == []:
        #         self.results['ExecutionLogging'] = [-1, "Stage name: " + stage['stageName']]
        #         self.results['CachingEnabled'] = [-1, "Stage name: " + stage['stageName']]
            
        #     for k, json in stage['methodSettings'].items():
        #         for key, value in json.items():
        #             if key == 'loggingLevel' and value != 'INFO' or 'ERROR':
        #                 self.results['ExecutionLogging'] = [-1, "Stage name: " + stage['stageName']]    
        #             if key == 'cachingEnabled' and value is True:
        #                 self.results['CachingEnabled'] = [1, "Stage name: " + stage['stageName']]
        #                 self.results['EncryptionAtRest'] = [-1, "Stage name: " + stage['stageName']]
        #                 if key == 'cacheDataEncrypted' and value is False:
        #                     self.results['EncryptionAtRest'] = [-1, "Stage name: " + stage['stageName']]
            
        #     try:
        #         certid = stage['clientCertificateId']
        #     except KeyError:
        #         self.results['EncryptionInTransit'] = [-1, "Stage name: " + stage['stageName']]
            
        #     if not stage['tracingEnabled']:
        #         self.results['XRayTracing'] = [-1, "Stage name: " + stage['stageName']]
            
        #     try:
        #         wacl = stage['webAclArn']
        #     except KeyError:
        #         self.results['WAFWACL'] = [-1, "Stage name: " + stage['stageName']]
            
        # return
        for stage in item:
            stage_name = stage['stageName']

            # --- Method Settings ---
            method_settings = stage.get('methodSettings', {})
            require_auth = method_settings.get('/*/*', {}).get('requireAuthorizationForCacheControl', False)
            
            if not method_settings:
                self.results['ExecutionLogging'] = [-1, f"Stage {stage_name} (No methodSettings)"]
                self.results['CachingEnabled'] = [-1, f"Stage {stage_name} (No methodSettings)"]
                
            if require_auth:
                self.results['RequireAuthForCacheControl'] = [1, f"Stage {stage_name} (Require Authorization for Cache Control)"]
            else:
                self.results['RequireAuthForCacheControl'] = [-1, f"Stage {stage_name} (Do NOT Require Authorization for Cache Control)"]

            for _, settings in method_settings.items():
                # Execution Logging
                logging_level = settings.get('loggingLevel')
                if logging_level in ('INFO', 'ERROR'):
                    self.results['ExecutionLogging'] = [1, f"Stage {stage_name} (Execution Logging Enabled: {logging_level})"]
                else:
                    self.results['ExecutionLogging'] = [-1, f"Stage {stage_name} (Execution Logging Disabled/Invalid)"]

                # Caching
                if settings.get('cachingEnabled'):
                    self.results['CachingEnabled'] = [1, f"Stage {stage_name} (Caching Enabled)"]
                else:
                    self.results['CachingEnabled'] = [0, f"Stage {stage_name} (Caching Disabled)"]

                # Encryption at Rest
                if settings.get('cacheDataEncrypted'):
                    self.results['EncryptionAtRest'] = [1, f"Stage {stage_name} (Cache Data Encrypted)"]
                else:
                    self.results['EncryptionAtRest'] = [-1, f"Stage {stage_name} (Cache Data NOT Encrypted)"]

            # --- Encryption in Transit ---
            certid = stage.get('clientCertificateId')
            if certid:
                self.results['EncryptionInTransit'] = [1, f"Stage {stage_name} (Client Certificate Attached: {certid})"]
            else:
                self.results['EncryptionInTransit'] = [-1, f"Stage {stage_name} (No Client Certificate)"]

            # --- X-Ray Tracing ---
            if stage.get('tracingEnabled'):
                self.results['XRayTracing'] = [1, f"Stage {stage_name} (X-Ray Tracing Enabled)"]
            else:
                self.results['XRayTracing'] = [-1, f"Stage {stage_name} (X-Ray Tracing Disabled)"]

            # --- WAF WebACL ---
            wacl = stage.get('webAclArn')
            if wacl:
                self.results['WAFWACL'] = [1, f"Stage {stage_name} (WAF WebACL Attached: {wacl})"]
            else:
                self.results['WAFWACL'] = [-1, f"Stage {stage_name} (No WAF WebACL)"]

        return
    
    def _checkMinTLSVersion(self):
        resp = self.apiClient.get_domain_names()
        items = resp.get("items", [])

        if not items:
            self.results["MinTLSVersion"] = [0, "No custom domain names found"]
            return

        insecure = []
        secure = []
        for domain in items:
            policy = domain.get("securityPolicy")
            if policy == "TLS_1_2":
                secure.append(f"{domain['domainName']} ({policy})")
            else:
                insecure.append(f"{domain['domainName']} ({policy})")

        if insecure:
            self.results["MinTLSVersion"] = [-1, "Insecure domains: " + ", ".join(insecure)]
        else:
            self.results["MinTLSVersion"] = [1, "All domains secure: " + ", ".join(secure)]

        return