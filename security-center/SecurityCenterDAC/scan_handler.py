import time
import os
from configparser import ConfigParser
from .misc import GET_SCANS, PAGE_OFFSET


class SecurityCenter:
    def __init__(self):
        self.current_time_epoch = int(time.time())
        self.configfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.conf')
        self.config = self.get_config()

    def get_config(self):
        config = ConfigParser()
        config.read(self.configfile)
        return config

    def update_config(self):
        with open(self.configfile, 'w') as fp:
            self.config.write(fp)

    def get_scan_result(self, sc_conn, last_fetched, current_epoch):
        # Lets get the list of scans that had completed within the time frame that we
        # had specified.
        data = GET_SCANS
        data['startTime'] = last_fetched
        data['endTime'] = current_epoch
        resp_json = sc_conn.connect('GET', 'scanResult', data=data)
        data = resp_json['usable']
        return data

    # Method get_only_latest_scan
    # Description :- Sort scans based on latest scan
    # Input:- scans : List of all collected scans based on time
    # scan_result : global dict to hold only latest scan data.
    def get_only_latest_scan(self, scans, scan_result):
        # Sort the scanResult in latest only. Required to drop repeated scan results.
        scan_name_id = {}
        for item in scans:
            scan = scan_result.get(item['name'], None)
            if scan is None:
                if item['importStatus'] == 'Finished':  # and item['completedChecks'] != '0':
                    scan_result[item['name']] = item
                    scan_name_id[item['name']] = item['id']
            else:
                # Check for latest finish time.
                if int(item['finishTime']) > int(scan['finishTime']):
                    if str(item['importStatus']) == 'Finished':  # and item['completedChecks'] is not '0':
                        scan_result[item['name']] = item
                        scan_name_id[item['name']] = item['id']
        return scan_name_id

    def get_scan_specific_data_from_sc(self, sc_conn, scan_id, scan_name, payload, response, startOffset=0):
        offset = PAGE_OFFSET
        payload['query']['startOffset'] = startOffset
        payload['query']['endOffset'] = startOffset + offset
        payload['scanID'] = scan_id
        payload['query']['scanID'] = scan_id
        payload['query']['scanName'] = scan_name
        json_res = sc_conn.connect('POST', 'analysis', data=payload)
        if json_res is not None:
            result = json_res['results']
            length = len(result)
            # Add result to the plugin result set.
            if length is not 0:
                response += result
            if length == offset:
                self.get_scan_specific_data_from_sc(sc_conn, scan_id, scan_name, payload, response,
                                                    payload['query']['endOffset'])

    def get_vulns_from_ip(self, sc_conn, asset, payload, response, startOffset=0):
        offset = PAGE_OFFSET
        payload['query']['startOffset'] = startOffset
        payload['query']['endOffset'] = startOffset + offset
        payload['query']['filters'][0]['value'] = asset
        json_resp = sc_conn.connect('POST', 'analysis', data=payload)
        if json_resp is not None:
            result = json_resp['results']
            length = len(result)
            # Add result to the plugin result set.
            if length is not 0:
                response += result
            if length == offset:
                self.get_vulns_from_ip(sc_conn, asset, payload, response, payload['query']['endOffset'])

    def get_asset_specific_data_from_sc(self, sc_conn, scan_id, scan_name, asset, payload, response, startOffset=0):
        offset = PAGE_OFFSET
        payload['query']['startOffset'] = startOffset
        payload['query']['endOffset'] = startOffset + offset
        payload['scanID'] = scan_id
        payload['query']['scanID'] = scan_id
        payload['query']['scanName'] = scan_name
        payload['query']['filters'][0]['value'] = asset
        json_resp = sc_conn.connect('POST', 'analysis', data=payload)
        if json_resp is not None:
            result = json_resp['results']
            length = len(result)
            # Add result to the plugin result set.
            if length is not 0:
                response += result
            if length == offset:
                self.get_asset_specific_data_from_sc(sc_conn, scan_id, scan_name, asset, payload, response,
                                                    payload['query']['endOffset'])
