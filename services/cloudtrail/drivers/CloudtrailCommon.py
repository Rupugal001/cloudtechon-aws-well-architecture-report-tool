from datetime import datetime, timedelta
import botocore
import boto3

from utils.Config import Config
from services.Evaluator import Evaluator

class CloudtrailCommon(Evaluator):
    def __init__(self, trail, ctClient, snsClient, s3Client):
        super().__init__()
        self.trail = trail
        self.ctClient = ctClient
        self.snsClient = snsClient
        self.s3Client = s3Client
        
        self._resourceName = trail['TrailARN']

        r = self.ctClient.describe_trails(
            trailNameList=[self.trail['TrailARN']]
        )
        
        s = self.ctClient.get_event_selectors(
            TrailName=self.trail['TrailARN']
        )
        
        self.trailInfo = r.get('trailList')[0]
        self.trailSelector = {
            'Event': s.get('EventSelectors'), 
            'AdvancedEvent': s.get('AdvancedEventSelectors')
        }
        
        self.init()
    
    ## For General Trail purpose
    def _checkHasGeneralTrailSetup(self):
        if Config.get('CloudTrail_hasOneMultiRegion') == False and self.trailInfo['IsMultiRegionTrail'] == True:
            Config.set('CloudTrail_hasOneMultiRegion', True)
        
        if  self.trailInfo['IncludeGlobalServiceEvents'] == True:
            gList = Config.get('CloudTrail_listGlobalServEnabled')
            gList.append(self.trail['TrailARN'])
            
            Config.set('CloudTrail_hasGlobalServEnabled', True)
            Config.set('CloudTrail_listGlobalServEnabled', gList)
    
    def _checkTrailBestPractices(self):
        if not self.trailInfo['LogFileValidationEnabled'] == True:
            self.results['LogFileValidationEnabled'] = [-1, '']
        else:
            self.results['LogFileValidationEnabled'] = [1, 'Log file validation is enabled']
            
        if (not 'CloudWatchLogsLogGroupArn' in self.trailInfo) or (len(self.trailInfo['CloudWatchLogsLogGroupArn']) == 0):
            self.results['CloudWatchLogsLogGroupArn'] = [-1, '']   
        else:
            self.results['CloudWatchLogsLogGroupArn'] = [1, 'CloudTrail is integrated with CloudWatch Logs'] 
    
        if (not 'KmsKeyId' in self.trailInfo):
            self.results['RequiresKmsKey'] = [-1, '']
        else:
            self.results['RequiresKmsKey'] = [1, 'KMS Key is enabled for encrypting CloudTrail logs']
            
            
        if (not 'HasInsightSelectors' in self.trailInfo) or (self.trailInfo['HasInsightSelectors'] == False):
            self.results['HasInsightSelectors'] = [-1, '']
            
    def _checkEvents(self):
        e = self.trailSelector['Event']
        if e == None:
            return
        
        if 'IncludeManagementEvents' in e and e['IncludeManagementEvents'] == True:
            Config.set('CloudTrail_hasManagementEventsCaptured', True)
        
        if 'DataResources' in e and len(e['DataResources']) > 0:
            Config.set('CloudTrail_hasDataEventsCaptured', True)
            
        has_s3 = any(
            event.get("DataResources") and any(dr["Type"] == "AWS::S3::Object" for dr in event["DataResources"])
            for event in e
        )
        if has_s3:
            Config.set('CloudTrail_hasS3DataEventsCaptured', True)
            
    def _checkSNSTopicValid(self):
        if (not 'SnsTopicARN' in self.trailInfo) or (self.trailInfo['SnsTopicARN'] == None):
            self.results['SetupSNSTopicForTrail'] = [-1, '']
            return
        
        snsArn = self.trailInfo['SnsTopicARN']
        try:
            r = self.snsClient.get_topic_attributes(TopicArn = snsArn)
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == 'NotFoundException':
                self.results['SNSTopicNoLongerValid'] = [-1, self.trail['TrailARN']]
            else:
                print(snsArn, err.response['Error']['Code'])
    
    def _checkSNSEncryptedKMS(self):
        topics = self.snsClient.list_topics()["Topics"]
        kmsKeys= []
        for topic in topics:
            arn = topic['TopicArn']
            try:
                r = self.snsClient.get_topic_attributes(TopicArn = arn)
                if 'KmsMasterKeyId' in r['Attributes']:
                    kmsKeys.append(r['Attributes']['KmsMasterKeyId'])
            except botocore.exceptions.ClientError as err:
                if err.response['Error']['Code'] == 'NotFoundException':
                    continue
                else:
                    print(arn, err.response['Error']['Code'])
        if len(kmsKeys) > 0:
            self.results['SNSTopicEncryptedWithKMS'] = [1, kmsKeys]
        else:
            self.results['SNSTopicEncryptedWithKMS'] = [-1, '']

    def _checkTrailStatus(self):
        r = self.ctClient.get_trail_status(
            Name=self.trail['TrailARN']
        )
        
        if not 'IsLogging' in r or r.get('IsLogging') == False:
            self.results['EnableCloudTrailLogging'] = [-1, '']
        else:
            self.results['EnableCloudTrailLogging'] = [1, 'CloudTrail logging is enabled']
        
        # Only check for delivery errors if the attribute exists and is not 'None'
        if 'LatestDeliveryError' in r and r.get('LatestDeliveryError') != 'None':
            self.results['TrailDeliverError'] = [-1, r.get('LatestDeliveryError')]
        else:
            self.results['TrailDeliverError'] = [1, 'No delivery errors detected']
            
    def _checkS3BucketSettings(self):
        ## For safety purpose, though all trails must have bucket
        if 'S3BucketName' in self.trailInfo and len(self.trailInfo['S3BucketName']) > 0:
            s3Bucket = self.trailInfo['S3BucketName']
            # help me retrieve s3 bucket public
            try:
                resp = self.s3Client.get_public_access_block(
                    Bucket=s3Bucket
                )
                
                for param, val in resp['PublicAccessBlockConfiguration'].items():
                    if val == False:
                        self.results['EnableS3PublicAccessBlock'] = [-1, None]
                        break
                    
            except botocore.exceptions.ClientError as e:
                print('-- Unable to capture Public Access Block settings:', e.response['Error']['Code'])
            
            try:
                r = self.s3Client.get_bucket_versioning(
                    Bucket=s3Bucket
                )
                
                mfaDelete = r.get('MFADelete')
                if mfaDelete == None or mfaDelete == 'Disabled':
                    self.results['EnableTrailS3BucketMFADelete'] = [-1, '']
                
                versioning = r.get('Status')
                if versioning == None or versioning == 'Disabled':
                    self.results['EnableTrailS3BucketVersioning'] = [-1, '']
                    
            except botocore.exceptions.ClientError as e:
                print('-- Unable to capture S3 MFA settings:', e.response['Error']['Code'])
        
            try:
                r = self.s3Client.get_bucket_logging(
                    Bucket=s3Bucket
                )
                logEnable = r.get('LoggingEnabled')
                if logEnable == None or not type(logEnable) is dict:
                    self.results['EnableTrailS3BucketLogging'] = [-1, '']
            except botocore.exceptions.ClientError as e:
                print('-- Unable to capture S3 Logging settings:', e.response['Error']['Code'])
                
            try:
                resp = self.s3Client.get_bucket_lifecycle(
                    Bucket=s3Bucket
                )
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] ==  'NoSuchLifecycleConfiguration':
                    self.results['EnableTrailS3BucketLifecycle'] = [-1, 'Off']
                    
                    
    def _checkSNSAlertsIntegrated(self):
        integrated = False
        topics = self.snsClient.list_topics().get('Topics', [])

        if not topics:
            self.results['SNSAlertsIntegrated'] = [-1, 'No SNS topics found in the account']
            return

        for topic in topics:
            subs = self.snsClient.list_subscriptions_by_topic(TopicArn=topic['TopicArn']).get('Subscriptions', [])
            active_subs = [s for s in subs if s.get('SubscriptionArn') != 'PendingConfirmation']
            if active_subs:
                integrated = True
                break

        if integrated:
            self.results['SNSAlertsIntegrated'] = [1, 'SNS topic has active subscriptions and alerts are integrated']
        else:
            self.results['SNSAlertsIntegrated'] = [-1, 'SNS topics found, but no active subscriptions detected']
            
    def _checkRecentFailures(self):
        error_events = []
        events = self.ctClient.lookup_events(MaxResults=20)
        for event in events.get('Events', []):
            if 'error' in event.get('CloudTrailEvent', '').lower():
                error_events.append(event)
        if error_events:
            self.results['RecentDeliveryFailures'] = [-1, f"Found {len(error_events)} error events in the last 20 CloudTrail events"]
        else:
            self.results['RecentDeliveryFailures'] = [1, 'No recent delivery failures found']
            
    def _check_dr_drills_performed(self):
        end = datetime.utcnow()
        start = end - timedelta(days=30)
        
        events = self.ctClient.lookup_events(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "StartDRDrill"}],
        StartTime=start,
        EndTime=end
    )
        performed = len(events.get("Events", [])) > 0
        if performed:
            self.results['DRDrillsPerformed'] = [1, 'DR drills have been performed recently']
        else:
            self.results['DRDrillsPerformed'] = [-1, 'No DR drills found in the last 30 days']
