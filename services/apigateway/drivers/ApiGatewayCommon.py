import boto3
import botocore
import constants as _C

from services.Service import Service
from services.Evaluator import Evaluator

class ApiGatewayCommon(Evaluator):
    
    def __init__(self, api, apiClient):
        super().__init__()
        self.apiClient = apiClient
        self.api = api

        self._resourceName = api['Name']

        return
    
    def _checkStage(self):
        resp = self.apiClient.get_stages(
                ApiId = self.api['ApiId'],
            )
        items = resp['Items']
        # for stage in items:

        #     if self.api['ProtocolType'] == 'WEBSOCKET':           
        #         # if stage['DefaultRouteSettings']['LoggingLevel'] != 'INFO' or 'ERROR':
        #         #     self.results['ExecutionLogging'] = [-1, "Stage name: " + stage['StageName']]
        #         logging_level = stage.get('DefaultRouteSettings', {}).get('LoggingLevel')

        #         if logging_level in ("INFO", "ERROR"):
        #             self.results['ExecutionLogging'] = [1, f"Stage name: {stage['StageName']} (Logging Enabled: {logging_level})"]
        #         elif logging_level in ("OFF", None, ""):
        #             self.results['ExecutionLogging'] = [0, f"Stage name: {stage['StageName']} (Execution Logging Disabled)"]
        #         else:
        #             self.results['ExecutionLogging'] = [-1, f"Stage name: {stage['StageName']} (Invalid LoggingLevel: {logging_level})"]

        #     try:
        #         accesslogs = stage['AccessLogSettings']
        #     except KeyError:
        #         self.results['AccessLogging'] = [-1, "Stage name: " + stage['StageName']]
        # return
        for stage in items:
            stage_name = stage['StageName']

            # --- Execution Logging check ---
            if self.api['ProtocolType'] == 'WEBSOCKET':
                logging_level = stage.get('DefaultRouteSettings', {}).get('LoggingLevel', "OFF")

                if logging_level in ("INFO", "ERROR"):
                    result = [1, f"Stage name: {stage_name} (Execution Logging Enabled: {logging_level})"]
                elif logging_level == "OFF":
                    result = [0, f"Stage name: {stage_name} (Execution Logging Disabled)"]
                else:
                    result = [-1, f"Stage name: {stage_name} (Invalid LoggingLevel: {logging_level})"]

                self.results.setdefault('ExecutionLogging', []).append(result)

            # --- Access Logging check ---
            accesslogs = stage.get('AccessLogSettings')
            if accesslogs:
                dest_arn = accesslogs.get('DestinationArn')
                fmt = accesslogs.get('Format')
                if dest_arn and fmt:
                    result = [1, f"Stage name: {stage_name} (Access Logging Enabled)"]
                else:
                    result = [-1, f"Stage name: {stage_name} (Invalid AccessLogSettings: {accesslogs})"]
            else:
                result = [0, f"Stage name: {stage_name} (Access Logging Disabled)"]

            self.results.setdefault('AccessLogging', []).append(result)

        return
            
    def _checkRoute(self):
        resp = self.apiClient.get_routes(
                ApiId = self.api['ApiId'],
            )
        items = resp['Items']
        # for route in items:
        #     if route['AuthorizationType'] == 'NONE':
        #         self.results['AuthorizationType'] = [-1, "Route key: " + route['RouteKey']]
        # return
        for route in items:
            route_key = route['RouteKey']
            auth_type = route.get('AuthorizationType')

            if auth_type and auth_type != 'NONE':
                self.results['AuthorizationType'] = [1, f"Route key: {route_key} (Authorization: {auth_type})"]
            elif auth_type == 'NONE':
                self.results['AuthorizationType'] = [0, f"Route key: {route_key} (Authorization Disabled)"]
            else:
                self.results['AuthorizationType'] = [-1, f"Route key: {route_key} (Invalid AuthorizationType: {auth_type})"]

        return