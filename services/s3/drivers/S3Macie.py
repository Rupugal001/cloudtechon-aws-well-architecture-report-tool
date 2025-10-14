import urllib.parse
from datetime import date

import boto3
import botocore

from utils.Config import Config
from utils.Policy import Policy
from utils.Tools import _warn
from services.Evaluator import Evaluator

class S3Macie(Evaluator):
    def __init__(self, macieV2Client):
        super().__init__()
        self.macieV2Client = macieV2Client
        
        self._resourceName = 'Macie'

        self.init()
    
    def _checkMacieEnable(self):
        """Validate whether Amazon Macie is enabled in the account/region."""
        try:
            # Try to get the session configuration directly (cleaner than list_findings)
            session_status = self.macieV2Client.get_macie_session()
            if session_status['status'] == 'ENABLED':
                self.results['MacieToEnable'] = [1, "Macie is enabled"]
            else:
                self.results['MacieToEnable'] = [0, "Macie is not enabled"]

        except self.macieV2Client.exceptions.ResourceNotFoundException:
            # This exception means Macie is disabled in this region
            self.results['MacieToEnable'] = [-1, "Macie not enabled in this region"]

        except self.macieV2Client.exceptions.AccessDeniedException:
            # Possible missing permissions or service disabled
            self.results['MacieToEnable'] = [-1, "Access denied or Macie not configured"]

        except botocore.exceptions.EndpointConnectionError as connErr:
            _warn(f"Connection error: {connErr}")
            self.results['MacieToEnable'] = [-1, "Endpoint connection issue"]

        except Exception as e:
            _warn(f"Unexpected error: {e}")
            self.results['MacieToEnable'] = [-1, str(e)]