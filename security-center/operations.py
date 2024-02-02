"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError
from .SecurityCenterDAC.scan_handler import SecurityCenter
from .SecurityCenterDAC.base import SecurityCenterBase
from .SecurityCenterDAC.misc import HOST_VULN, ASSET_INFO, HOST_VULN_WITHOUT_SCAN_INFO


logger = get_logger('security-center')


days_mapping = {'Last Fetch': 0, 'Last 24 Hours': 1, 'Last 3 Days': 3, 'Last 5 Days': 5,
                'Last 7 Days': 7, 'Last 15 Days': 15, 'Last 25 Days': 25, 'Last 30 Days': 30,
                'Last 50 Days': 50, 'Last 60 Days': 60,  'Last 90 Days': 90, 'Last 120 Days': 120, 'Last 180 Days': 180
               }
last_24_hrs = 86400


def mapping_fun(dict_list, result):
    ip, port, pluginId = 'ip', 'port', 'pluginID'
    for item in dict_list:
        mapping_key = str(item.get(ip)) + str(item.get(port)) + str(item.get(pluginId))
        result[mapping_key] = item


def handle_last_fetch_time(sc, completion_time):
    """
    Check for the last fetched epoch time, if its zero then check for
    the default days and set since accordingly for subsequent calls.
    """
    last_fetched = int(sc.config.get('conf', 'last_fetch'))
    if completion_time == 0:
        if last_fetched == 0:
            last_fetched = sc.current_time_epoch - int(sc.config.get('conf', 'default_fetch_days')) * \
                                                   int(sc.config.get('conf', 'one_day_seconds'))
    else:
        last_fetched = sc.current_time_epoch - completion_time * int(sc.config.get('conf', 'one_day_seconds'))
    sc.config.set('conf', 'last_fetch', str(sc.current_time_epoch))  # update last fetch time with current time
    sc.update_config()
    return last_fetched


def get_scan_specific_assets(security_center, sc_conn, scan_name, scan_id):
    try:
        new_assets_record = []
        security_center.get_scan_specific_data_from_sc(sc_conn, scan_id, scan_name, ASSET_INFO, new_assets_record)
        return new_assets_record
    except Exception as err:
        logger.exception('Error:get_scan_specific_assets: [{0}]'.format(err))
        raise ConnectorError('Error:get_scan_specific_assets: [{0}]'.format(err))


def get_all_assets(config, params):
    scan_details = params['scan_details']
    assets_records = []
    result = {}
    try:
        sc_conn = SecurityCenterBase(config)
        sc_conn.login()
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))
    try:
        security_center = SecurityCenter()
        if not isinstance(scan_details, dict):
            raise ConnectorError('Invalid input format')
        for scan_name, scan_id in scan_details.items():
            asset_data = {}
            asset_data['assets'] = get_scan_specific_assets(security_center, sc_conn, scan_name, scan_id)
            asset_data['scan_name'] = scan_name
            assets_records.append(asset_data)
        sc_conn.logout()
        result['assets_records'] = assets_records
        return result
    except Exception as err:
        sc_conn.logout()
        logger.exception('Error:[{0}]'.format(err))
        raise ConnectorError('Error: [{0}]'.format(err))


def get_all_scans(config, params):
    scan_result = {'message': 'No records found', 'scans_records': ''}
    scans_records = {}
    completion_time_in_days = days_mapping.get(params['days'], 7)
    try:
        sc_conn = SecurityCenterBase(config)
        sc_conn.login()
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))
    try:
        security_center = SecurityCenter()
        current_epoch = security_center.current_time_epoch
        last_fetched = handle_last_fetch_time(security_center, int(completion_time_in_days))
        all_scans = security_center.get_scan_result(sc_conn, last_fetched, current_epoch)
        sc_conn.logout()
        # extract only latest useful scans.
        scan_id_name_dict = security_center.get_only_latest_scan(all_scans, scans_records)
        if scans_records:
            scan_result['message'] = 'Records Found'
        scan_result['scans_records'] = scans_records
        scan_result['name_id_mapping'] = scan_id_name_dict
        return scan_result
    except Exception as err:
        sc_conn.logout()
        logger.exception('Error:[{0}]'.format(err))
        raise ConnectorError('Error: [{0}]'.format(err))


def get_vulnerabilities(asset_param, scan_id, scan_name, sc_conn, security_center):
    result = {}
    new_vulns_record = []
    security_center.get_vulns_from_ip(sc_conn, asset_param, HOST_VULN_WITHOUT_SCAN_INFO, new_vulns_record)
    if new_vulns_record:
        return new_vulns_record
    try:
        for i in range(len(scan_id)):
            new_vulns_record = []
            security_center.get_asset_specific_data_from_sc(sc_conn, scan_id[i], scan_name[i],
                                                            asset_param, HOST_VULN, new_vulns_record)
            mapping_fun(new_vulns_record, result)
        return list(result.values())
    except Exception as e:
        logger.exception('Exception occurred {}'.format(e))
        raise ConnectorError('{}'.format(e))


def get_asset_vulns(config, params):
    security_center = SecurityCenter()
    asset_param = params['asset_info']
    scan_id = params['scan_id'] if isinstance(params['scan_id'], list) else [params['scan_id']]
    scan_name = params['scan_name'] if isinstance(params['scan_name'], list) else [params['scan_name']]
    try:
        sc_conn = SecurityCenterBase(config)
        sc_conn.login()
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))
    try:
        result = {'message': 'Records Found', 'vulns_data': [], 'asset_param': ''}
        vulns_records = get_vulnerabilities(asset_param, scan_id, scan_name, sc_conn, security_center)
        if vulns_records:
            result.update({'vulns_data': vulns_records, 'asset_param': asset_param})
        else:
            result['message'] = 'No records found'
            result['asset_param'] = asset_param
        sc_conn.logout()
        return result
    except Exception as e:
        sc_conn.logout()
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def _check_health(config):
    try:
        sc_conn = SecurityCenterBase(config)
        sc_conn.login()
        sc_conn.logout()
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))

operations = {
    'get_all_scans': get_all_scans,
    'get_all_assets': get_all_assets,
    'get_asset_vulns': get_asset_vulns
}
