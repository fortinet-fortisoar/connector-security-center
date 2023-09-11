PAGE_OFFSET = 50000

SCAN_RESULT_FILEDS = 'canUse,canManage,owner,groups,ownerGroup,status,name,details,diagnosticAvailable,' \
                     'importStatus,createdTime,startTime,finishTime,importStart,importFinish,running,totalIPs,' \
                     'scannedIPs,completedIPs,completedChecks,totalChecks,downloadAvailable,downloadFormat,' \
                     'repository,resultType,resultSource,scanDuration'

GET_SCANS = {'filter': 'usable', 'fields': SCAN_RESULT_FILEDS, 'startTime': 0}

SCAN_ANALYSIS = {
    "query": {
        "name": "",
        "description": "",
        "context": "",
        "status": -1,
        "createdTime": 0,
        "modifiedTime": 0,
        "groups": [],
        "type": "vuln",
        "tool": "sumid",
        "sourceType": "individual",
        "startOffset": 0,
        "endOffset": 0,
        "filters": [
            {"id": "firstSeen", "filterName": "firstSeen", "operator": "=", "type": "vuln", "isPredefined": True,
             "value": "00:2"}],
        "sortColumn": "severity",
        "sortDirection": "desc",
        "scanID": "",
        "view": "all",
        "scanName": ""
    },
    "sourceType": "individual",
    "scanID": "",
    "sortField": "severity",
    "sortDir": "desc",
    "columns": [],
    "type": "vuln"
}

GET_VULNS_ANALYSIS = {
    "query": {
        "name": "",
        "description": "",
        "context": "",
        "status": -1,
        "groups": [],
        "type": "vuln",
        "tool": "listvuln",
        "sourceType": "individual",
        "startOffset": 0,
        "endOffset": 0,
        "filters": [],
        "vulnTool": "listvuln",
        "scanID": "",
        "view": "all",
        "scanName": ""
    },
    "sourceType": "individual",
    "scanID": "",
    "columns": [],
    "type": "vuln"}

PLUGINS_FILETER = {"id": "pluginID",
                   "filterName": "pluginID",
                   "operator": "=",
                   "type": "vuln",
                   "isPredefined": True,
                   "value": ""}

ASSET_INFO = {"query":
    {
        "name": "",
        "description": "",
        "context": "",
        "status": -1,
        "createdTime": 0,
        "modifiedTime": 0,
        "groups": [],
        "type": "vuln",
        "tool": "sumip",
        "sourceType": "individual",
        "startOffset": 0,
        "endOffset": 0,
        "sortDirection": "desc",
        "vulnTool": "sumip",
        "scanID": "",
        "view": "all",
        "scanName": ""
    },
    "sourceType": "individual",
    "scanID": "",
    "columns": [],
    "type": "vuln"
}


HOST_VULN = {
  "query": {
    "name": "",
    "description": "",
    "context": "",
    "status": -1,
    "createdTime": 0,
    "modifiedTime": 0,
    "groups": [],
    "type": "vuln",
    "tool": "vulndetails",
    "sourceType": "individual",
    "startOffset": 0,
    "endOffset": 50,
    "filters": [
      {
        "id": "ip",
        "filterName": "ip",
        "operator": "=",
        "type": "vuln",
        "isPredefined": True,
        "value": ""
      }
    ],
    "vulnTool": "vulndetails",
    "scanID": "",
    "view": "all",
    "scanName": ""
  },
  "sourceType": "individual",
  "scanID": "",
  "columns": [],
  "type": "vuln"
}

HOST_VULN_WITHOUT_SCAN_INFO = {
  "query": {
    "name": "",
    "description": "",
    "context": "",
    "status": -1,
    "createdTime": 0,
    "modifiedTime": 0,
    "groups": [],
    "type": "vuln",
    "tool": "vulndetails",
    "sourceType": "cumulative",
    "startOffset": 0,
    "endOffset": 50,
    "filters": [
      {
        "id": "ip",
        "filterName": "ip",
        "operator": "=",
        "type": "vuln",
        "isPredefined": True,
        "value": ""
      }
    ],
    "vulnTool": "vulndetails"
  },
  "sourceType": "cumulative",
  "columns": [],
  "type": "vuln"
}
