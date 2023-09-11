import requests
import json
import re
from connectors.core.connector import get_logger, ConnectorError
logger = get_logger('security-center')


class SecurityCenterBase:
    def __init__(self, config):
        self.base_url = config.get('server').strip()
        if not self.base_url.startswith('https://'):
            self.base_url = 'https://' + self.base_url
        self._verify = config['verify_ssl']
        self.password = config['password']
        self.username = config['username']
        self._token = ''
        self._cookie = ''
        self.match = []

    def authenticate(self):
        if self._token == '':
            return False
        else:
            return True

    def login(self):
        try:
            request_payload = {'username': self.username, 'password': self.password}
            resp = self.connect('POST', 'token', request_payload)
            if not resp:
                request_payload['releaseSession'] = True
                resp = self.connect('POST', 'token', request_payload)
                if not resp:
                    logger.error('Release Session, Too many sessions in use')
                    raise ConnectorError('Too many sessions in use')
            if resp is not None:
                self._token = str(resp['token'])
        except Exception as err:
            logger.error(err)
            raise ConnectorError(err)

    def logout(self):
        self.connect('DELETE', 'token')
        self._token = ''
        self._cookie = ''

    def connect(self, method, resource, data=None):
        headers = {
            'Content-Type': 'application/json',
            "Accept":"application/json, text/javascript, */*; q=0.01"
        }
        if self._token != '':
            headers['X-SecurityCenter'] = self._token
        if self._cookie != '':
            headers['Cookie'] = self._cookie
        # Only convert the data to JSON if there is data.
        if data is not None and method is not 'GET':
            data = json.dumps(data)
        url = "{0}/rest/{1}".format(self.base_url, resource)
        try:
            session = requests.Session()
            if method == 'POST':
                response = session.post(url, data=data, headers=headers, verify=self._verify)
            elif method == 'PUT':
                response = session.put(url, data=data, headers=headers, verify=self._verify)
            elif method == 'DELETE':
                response = session.delete(url, data=data, headers=headers, verify=self._verify)
            else:
                response = session.get(url, params=data, headers=headers, verify=self._verify)
        except requests.exceptions.SSLError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('SSL certificate validation failed')
        except Exception as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('Invalid endpoint')
        except requests.ConnectionError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(e))
        # Make sure we have a JSON response. If not then return None.
        try:
            contents = response.json()
            json_resp = contents['response']
            if json_resp and json_resp.get('releaseSession', False):
                return False
            elif contents.get('error_code', 0) == 161:
                raise ConnectorError('Invalid login credentials')
        except ValueError as e:
            return None
        if response.headers.get('set-cookie') is not None:
            cookie = session.cookies.get_dict()
            match = re.findall("TNS_SESSIONID=[^,]*", response.headers.get('set-cookie'))
            sess_cookie = cookie.get("TNS_SESSIONID")
            for item in match:
                if sess_cookie in item:
                    self._cookie = item
        # If the response status is not 200 OK, there is an error.
        if contents['error_code'] != 0:
            return None
        # Return the contents of the response field from the SecurityCenter
        # response.
        return contents['response']