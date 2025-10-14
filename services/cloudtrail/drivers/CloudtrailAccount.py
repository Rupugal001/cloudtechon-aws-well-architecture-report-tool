import botocore

from utils.Config import Config
from services.Evaluator import Evaluator

class CloudtrailAccount(Evaluator):
    def __init__(self, ctClient, sizeofTrail):
        super().__init__()
        self.ctClient = ctClient
        self.sizeofTrail = sizeofTrail
        
        self._resourceName = 'General'

        self.init()
    
    ## For General Trail purpose
    def _checkHasOneTrailConfiguredCorrectly(self):
        if self.sizeofTrail == 0:
            self.results['NeedToEnableCloudTrail'] = [-1, '']
        else:
            self.results['NeedToEnableCloudTrail'] = [1, f'{self.sizeofTrail} trail(s) enabled']
        
        if Config.get('CloudTrail_hasOneMultiRegion') == False:
            self.results['HasOneMultiRegionTrail'] = [-1, '']
        else:
            self.results['HasOneMultiRegionTrail'] = [1, 'Multi-region trail is enabled']

        if Config.get('CloudTrail_hasGlobalServEnabled') == False:
            self.results['HasCoverGlobalServices'] = [-1, '']
        else:
            self.results['HasCoverGlobalServices'] = [1, 'Global services are covered']

        if Config.get('CloudTrail_hasManagementEventsCaptured') == False:
            self.results['HasManagementEventsCaptured'] = [-1, '']
        else:
            self.results['HasManagementEventsCaptured'] = [1, 'Management events are captured']

        if Config.get('CloudTrail_hasDataEventsCaptured') == False:
            self.results['HasDataEventsCaptured'] = [-1, '']
        else:
            self.results['HasDataEventsCaptured'] = [1, 'Data events are captured']
            
        lists = Config.get('CloudTrail_listGlobalServEnabled')
        if len(lists) > 1:
            self.results['DuplicateGlobalTrail'] = [-1, '<br>'.join(lists)]
        else:
            self.results['DuplicateGlobalTrail'] = [1, 'No duplicate global service trails']
        if Config.get('CloudTrail_hasS3DataEventsCaptured') == False:
            self.results['HasS3DataEventsCaptured'] = [-1, '']
        else:
            self.results['HasS3DataEventsCaptured'] = [1, 'S3 Data events are captured']