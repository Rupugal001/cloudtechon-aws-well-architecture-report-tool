import os
import boto3

# from botocore.config import Config
from services.Service import Service
from utils.Config import Config as Config_int

from services.efs.drivers.EfsDriver import EfsDriver

from utils.Tools import _pi

class Efs(Service):
    def __init__(self, region):
        super().__init__(region)
        
        ssBoto = self.ssBoto
        self.efs_client = ssBoto.client('efs', config=self.bConfig)

    def get_resources(self):
        resources = self.efs_client.describe_file_systems()
        results = resources['FileSystems']

        if not self.tags:
            return results

        filtered_results = []
        for efs in results:
            if self.resourceHasTags(efs['Tags']):
                filtered_results.append(efs)

        return filtered_results

    def advise(self):
        objs = {}

        efs_list = self.get_resources()
        # print(f"EFS list found: {efs_list}")
        # if not efs_list:
        #     return {
        #     "results": {
        #         "AccessPointUserIdentity": [1, "No EFS resources found"],
        #         "EncryptedAtRest": [1, "No EFS resources found"],
        #         "AutomatedBackup": [1, "No EFS resources found"],
        #         "Lifecycle": [1, "No EFS resources found"],
        #         "IsSingleAZ": [1, "No EFS resources found"],
        #     },
        #     "InventoryInfo": {},
        #     "chartData": {},
        #     "classname": "EfsDriver",
        #     "_resourceName": "NoEFS",
        # }
        
        # driver = 'EfsDriver'
        # if globals().get(driver):
        # print('EFS service')
        for efs in efs_list:
            _pi('EFS', efs['FileSystemId'])
            obj = EfsDriver(efs, self.efs_client)
            obj.run(self.__class__)

            objs['EFS::' + efs['FileSystemId']] = obj.getInfo()
            del obj

        return objs


if __name__ == "__main__":
    Config_int.init()
    o = Efs('ap-southeast-1')
    out = o.advise()
    print(out)
