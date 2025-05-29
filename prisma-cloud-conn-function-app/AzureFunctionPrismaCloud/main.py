import asyncio
import aiohttp
import json
import time
import os
import re
import logging
from datetime import datetime

import azure.functions as func

from .state_manager_async import StateManagerAsync
from .sentinel_connector_async import AzureSentinelMultiConnectorAsync

logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.ERROR)

WORKSPACE_ID = os.environ['AzureSentinelWorkspaceId']
SHARED_KEY = os.environ['AzureSentinelSharedKey']
API_URL = os.environ['PrismaCloudAPIUrl']
COMPUTE_API_URL = os.environ['PrismaCloudComputeAPIUrl']
USER = os.environ['PrismaCloudAccessKeyID']
PASSWORD = os.environ['PrismaCloudSecretKey']
FILE_SHARE_CONN_STRING = os.environ['AzureWebJobsStorage']
ALERT_LOG_TYPE = 'PaloAltoPrismaCloudAlert'
AUDIT_LOG_TYPE = 'PaloAltoPrismaCloudAudit'
COMPUTE_INCIDENT_LOG_TYPE = 'PaloAltoPrismaCloudComputeIncident'
LOGTYPE = os.environ.get('LogType',"alert, audit", "compute_incident")

# if ts of last event is older than now - MAX_PERIOD_MINUTES -> script will get events from now - MAX_PERIOD_MINUTES
MAX_PERIOD_MINUTES = 60 * 6

LOG_ANALYTICS_URI = os.environ.get('logAnalyticsUri')

if not LOG_ANALYTICS_URI or str(LOG_ANALYTICS_URI).isspace():
    LOG_ANALYTICS_URI = 'https://' + WORKSPACE_ID + '.ods.opinsights.azure.com'

pattern = r'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$'
match = re.match(pattern, str(LOG_ANALYTICS_URI))
if not match:
    raise Exception("Invalid Log Analytics Uri.")


async def main(mytimer: func.TimerRequest):
    logging.info('Script started.')
    async with aiohttp.ClientSession() as session:
        async with aiohttp.ClientSession() as session_sentinel:
            prisma = PrismaCloudConnector(API_URL, COMPUTE_API_URL, USER, PASSWORD, session=session, session_sentinel=session_sentinel)

            tasks = [
                prisma.process_alerts()
            ]

            logging.info('LOGTYPE value : {}'.format(LOGTYPE))
            if LOGTYPE.lower().__contains__('audit') :
                tasks.append(prisma.process_audit_logs())
            
            if LOGTYPE.lower().__contains__('compute_incident') :
                tasks.append(prisma.process_compute_incidents())

            await asyncio.gather(*tasks)

    logging.info('Program finished. {} events have been sent.'.format(prisma.sentinel.successfull_sent_events_number))


class PrismaCloudConnector:
    def __init__(self, api_url, compute_api_url,  username, password, session: aiohttp.ClientSession, session_sentinel: aiohttp.ClientSession):
        self.api_url = api_url
        self.compute_api_url = compute_api_url
        self.__username = username
        self.__password = password
        self.session = session
        self.session_sentinel = session_sentinel
        self._token = None
        self._auth_lock = asyncio.Lock()
        self.alerts_state_manager = StateManagerAsync(FILE_SHARE_CONN_STRING, share_name='prismacloudcheckpoint', file_path='prismacloudlastalert')
        self.auditlogs_state_manager = StateManagerAsync(FILE_SHARE_CONN_STRING, share_name='prismacloudcheckpoint', file_path='prismacloudlastauditlog')
        self.compute_incidents_state_manager = StateManagerAsync(FILE_SHARE_CONN_STRING, share_name='prismacloudcheckpoint', file_path='prismacloudlastcomputeincident')
        self.sentinel = AzureSentinelMultiConnectorAsync(self.session_sentinel, LOG_ANALYTICS_URI, WORKSPACE_ID, SHARED_KEY, queue_size=10000)
        self.sent_alerts = 0
        self.sent_audit_logs = 0
        self.sent_compute_incidents = 0
        self.last_alert_ts = None
        self.last_audit_ts = None
        self.last_compute_incident_ts = None

    async def process_alerts(self):
        last_alert_ts_ms = await self.alerts_state_manager.get()
        max_period = (int(time.time()) - MAX_PERIOD_MINUTES * 60) * 1000
        if not last_alert_ts_ms or int(last_alert_ts_ms) < max_period:
            alert_start_ts_ms = max_period
            logging.info('Last alert was too long ago or there is no info about last alert timestamp.')
        else:
            alert_start_ts_ms = int(last_alert_ts_ms) + 1
        logging.info('Starting searching alerts from {}'.format(alert_start_ts_ms))

        async for alert in self.get_alerts(start_time=alert_start_ts_ms):
            last_alert_ts_ms = alert['alertTime']
            alert = self.sanitize_alert_payload(alert)
            await self.sentinel.send(alert, log_type=ALERT_LOG_TYPE)
            self.sent_alerts += 1

        self.last_alert_ts = last_alert_ts_ms

        conn = self.sentinel.get_log_type_connector(ALERT_LOG_TYPE)
        if conn:
            await conn.flush()
            logging.info('{} alerts have been sent'.format(self.sent_alerts))
        await self.save_alert_checkpoint()

    async def process_audit_logs(self):
        last_log_ts_ms = await self.auditlogs_state_manager.get()
        max_period = (int(time.time()) - MAX_PERIOD_MINUTES * 60) * 1000
        if not last_log_ts_ms or int(last_log_ts_ms) < max_period:
            log_start_ts_ms = max_period
            logging.info('Last audit log was too long ago or there is no info about last log timestamp.')
        else:
            log_start_ts_ms = int(last_log_ts_ms) + 1
        logging.info('Starting searching audit logs from {}'.format(log_start_ts_ms))

        async for event in self.get_audit_logs(start_time=log_start_ts_ms):
            if not last_log_ts_ms:
                last_log_ts_ms = event['timestamp']
            elif event['timestamp'] > int(last_log_ts_ms):
                last_log_ts_ms = event['timestamp']
            await self.sentinel.send(event, log_type=AUDIT_LOG_TYPE)
            self.sent_audit_logs += 1

        self.last_audit_ts = last_log_ts_ms

        conn = self.sentinel.get_log_type_connector(AUDIT_LOG_TYPE)
        if conn:
            await conn.flush()
            logging.info('{} audit logs have been sent'.format(self.sent_audit_logs))
        await self.save_audit_checkpoint()
    
    async def process_compute_incidents(self):
        last_compute_incident_ts_ms = await self.compute_incidents_state_manager.get()
        max_period = (int(time.time()) - MAX_PERIOD_MINUTES * 60) * 1000
        if not last_compute_incident_ts_ms or int(last_compute_incident_ts_ms) < max_period:
            compute_incident_start_ts_ms = max_period
            logging.info('Last compute_incident was too long ago or there is no info about last compute_incident timestamp.')
        else:
            compute_incident_start_ts_ms = int(last_compute_incident_ts_ms) + 1
        print('Starting searching compute_incidents from {}'.format(compute_incident_start_ts_ms))

        async for compute_incident in self.get_compute_incidents(start_time=compute_incident_start_ts_ms):
            # last_compute_incident_ts_ms = compute_incident['time']
            # print(compute_incident['_id'])
            incident_time = int(datetime.fromisoformat(compute_incident['time']).timestamp()*1000)
            if not last_log_ts_ms:
                last_log_ts_ms = incident_time
            elif incident_time > int(last_log_ts_ms):
                last_log_ts_ms = incident_time
            await self.sentinel.send(compute_incident, log_type=AUDIT_LOG_TYPE)
            self.sent_compute_incidents += 1

        self.last_compute_incident_ts = last_log_ts_ms

        conn = self.sentinel.get_log_type_connector(COMPUTE_INCIDENT_LOG_TYPE)
        if conn:
            await conn.flush()
            logging.info('{} compute incidents have been sent'.format(self.sent_compute_incidents))
        await self.save_compute_incident_checkpoint()


    async def _authorize(self):
        async with self._auth_lock:
            if not self._token:
                uri = self.api_url + '/login'
                headers = {
                    "Accept": "application/json; charset=UTF-8",
                    "Content-Type": "application/json; charset=UTF-8"
                }
                data = {
                    'username': self.__username,
                    'password': self.__password
                }
                data = json.dumps(data)
                async with self.session.post(uri, data=data, headers=headers) as response:
                    if response.status != 200:
                        raise Exception('Error while getting Prisma Cloud auth token. HTTP status code: {}'.format(response.status))
                    res = await response.text()

                res = json.loads(res)
                self._token = res['token']
                logging.info('Auth token for Prisma Cloud was obtained.')

    async def _authorize_compute(self):
        async with self._auth_lock:
            if not self._compute_token:
                uri = self.compute_api_url + '/authenticate'
                headers = {
                    "Accept": "application/json; charset=UTF-8",
                    "Content-Type": "application/json; charset=UTF-8"
                }

                data = {
                    'username':self.__username,
                    'password':self.__password
                }

                async with self.session.post(uri, json=data ) as response:
                    if response.status != 200:
                        raise Exception('Error while getting Prisma Cloud Compute auth token. HTTP status code: {}'.format(response.status))
                    res = await response.json()

                self._compute_token = res['token']
                logging.info('Auth token for Prisma Cloud Compute was obtained.')

    async def get_alerts(self, start_time):
        await self._authorize()
        uri = self.api_url + '/v2/alert'
        headers = {
            'x-redlock-auth': self._token,
            "Accept": "application/json; charset=UTF-8",
            "Content-Type": "application/json; charset=UTF-8"
        }

        unix_ts_now = (int(time.time()) - 10) * 1000
        data = {
            "timeRange": {
                "type": "absolute",
                "value": {
                    "startTime": start_time,
                    "endTime": unix_ts_now
                }
            },
            "sortBy": ["alertTime:asc"],        
            "detailed": True
        }
        data = json.dumps(data)
        async with self.session.post(uri, headers=headers, data=data) as response:
            if response.status != 200:
                raise Exception('Error while getting alerts. HTTP status code: {}'.format(response.status))
            res = await response.text()
            res = json.loads(res)

        for item in res['items']:

            yield item

        while 'nextPageToken' in res:
            data = {
                'pageToken': res['nextPageToken']
            }
            data = json.dumps(data)
            async with self.session.post(uri, headers=headers, data=data) as response:
                if response.status != 200:
                    raise Exception('Error while getting alerts. HTTP status code: {}'.format(response.status))
                res = await response.text()
                res = json.loads(res)
            for item in res['items']:
                yield item
    



    @staticmethod
    def sanitize_alert_payload(alert):
        """
        Modifies the alert payload by:
        - Removing 'data' field from 'resource'.
        - Adding a 'callback_url' field with a link to the alert.
        - Filtering 'complianceMetadata' to keep only MITRE ATT&CK-related entries.
        """
        resource = alert.get('resource', {})
        policy = alert.get('policy', {})

        # Remove 'data' from 'resource'
        if 'data' in resource:
            del resource['data']

        return alert

    async def get_compute_incidents(self, start_time):
        await self._authorize_compute()

        uri = self.compute_api_url + '/audits/incidents'
        headers = {
            'Authorization': 'Bearer '+ self._compute_token,
            "Accept": "application/json; charset=UTF-8",
            "Content-Type": "application/json; charset=UTF-8"
        }
  
        unix_ts_now = (int(time.time()) - 10) * 1000

        limit = 50
        offset = 0
        res = True

        while res:
            params = {
                'acknowledged': 'false',
                'reverse': 'false',
                'from': datetime.fromtimestamp(start_time/1000).isoformat(timespec='milliseconds')+'Z',
                'to': datetime.fromtimestamp(unix_ts_now/1000).isoformat(timespec='milliseconds')+'Z',
                'limit': limit,
                'offset': offset,
            }
        
            async with self.session.get(uri, headers=headers, params=params) as response:
                if response.status != 200:
                    raise Exception('Error while getting compute_incidents. HTTP status code: {}'.format(response.status))
                
                offset=offset+limit
                res = await response.json()
            if res:
                for item in res:
                    yield item

    async def get_audit_logs(self, start_time):
        await self._authorize()
        uri = self.api_url + '/audit/redlock'
        headers = {
            'x-redlock-auth': self._token,
            "Accept": "*/*",
            "Content-Type": "application/json"
        }

        unix_ts_now = (int(time.time()) - 10) * 1000
        params = {
            'timeType': 'absolute',
            'startTime': start_time,
            'endTime': unix_ts_now
        }
        async with self.session.get(uri, headers=headers, params=params) as response:
            if response.status != 200:
                raise Exception('Error while getting audit logs. HTTP status code: {}'.format(response.status))
            res = await response.text()
            res = json.loads(res)

        for item in res:
            yield item

    async def save_alert_checkpoint(self):
        if self.last_alert_ts:
            await self.alerts_state_manager.post(str(self.last_alert_ts))
            logging.info('Last alert ts saved - {}'.format(self.last_alert_ts))

    async def save_audit_checkpoint(self):
        if self.last_audit_ts:
            await self.auditlogs_state_manager.post(str(self.last_audit_ts))
            logging.info('Last audit ts saved - {}'.format(self.last_audit_ts))
    
    async def save_compute_incident_checkpoint(self):
        if self.last_compute_incident_ts:
            await self.compute_incidents_state_manager.post(str(self.last_compute_incident_ts))
            logging.info('Last compute_incident ts saved - {}'.format(self.last_compute_incident_ts))
