import base64
import json
import urllib
import urlparse

import requests

from datetime import datetime
from jose import jwt


class OidcClient(object):
  def __init__(self, discovery_uri, client_id, client_secret=None,
      verify=False):
    self.discovery_uri = discovery_uri
    self.client_id = client_id
    self.client_secret = client_secret
    self.verify = verify

  def _discover(self):
    if not hasattr(self, 'well_known'):
      self.well_known = self._get_url(self.discovery_uri)
      self.certs = {item['kid']: item for item in
                    self._get_url(get_property('jwks_uri', self.well_known))[
                      'keys']}
      self.auth_uri = get_property('authorization_endpoint',
                                   self.well_known)
      self.token_uri = get_property('token_endpoint', self.well_known)
      self.logout_uri = get_property('end_session_endpoint',
                                     self.well_known)

  def _get_url(self, url):
    resp = None
    try:
      resp = requests.get(url, verify=self.verify)
      if resp.status_code != 200:
        raise CommunicationError(
            'Could not connect to endpoint, {}, Code: {}'.format(url, str(
                resp.status_code)))
      return resp.json()
    finally:
      if resp is not None:
        resp.close()

  def create_auth_url(self, response_type, redirect_uri, scopes, state):
    self._discover()
    query_params = {
      'response_type': response_type,
      'client_id': self.client_id,
      'redirect_uri': redirect_uri,
      'scope': _get_scope_string(scopes),
      'state': state
    }
    return _add_query_params_to_url(self.auth_uri, query_params)

  def get_tokens_from_code(self, url, redirect_uri, scopes, state):
    self._discover()
    params = dict(urlparse.parse_qsl(urlparse.urlparse(url).query))
    if 'code' not in params:
      raise AuthenticationError('Authorization code not found in response')
    if state is not None:
      if 'state' not in params:
        raise AuthenticationError('Response does not contain a state')
      if state != params['state']:
        raise AuthenticationError(
            'Response state does not match the session state')
    req_params = {
      'grant_type': 'authorization_code',
      'scope': _get_scope_string(scopes),
      'code': params['code'],
      'redirect_uri': redirect_uri,
      'client_id': self.client_id
    }

    headers = {
      'Authorization': 'Basic ' + base64.b64encode(
          '{}:{}'.format(self.client_id, self.client_secret)),
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
      'Accept': 'application/json'
    }
    resp = None
    try:
      resp = requests.post(self.token_uri, data=req_params, headers=headers,
                           verify=self.verify)
      if resp.status_code != 200:
        raise AuthenticationError(resp.text)
      return resp.json()
    finally:
      if resp is not None:
        resp.close()

  def validate_jwt(self, token, **kwargs):
    self._discover()
    if type(token) not in [str, unicode]:
      raise ValidationError('Token should be a string type')
    split = token.split('.')
    if len(split) != 3:
      raise ValidationError('Invalid token provided for validation')
    # Correct the padding
    split[0] += "=" * ((4 - len(split[0]) % 4) % 4)
    key_spec = json.loads(base64.b64decode(split[0]))
    key_id = key_spec['kid']
    if key_id not in self.certs:
      raise ValidationError('The token is signed by an unknown key')
    cert = self.certs[key_id]
    return jwt.decode(token=token, key=cert, **kwargs)

  def get_logout_endpoint(self, redirect=None):
    self._discover()
    if redirect is None:
      return str(self.logout_uri)
    return str(self.logout_uri) + '?redirect_uri=' + redirect


def get_property(prop_name, config, error=False):
  if prop_name not in config:
    if error:
      raise EnvironmentError(
          'The value for ' + prop_name + ' could not be found')
    else:
      return None
  return config[prop_name]


def _get_scope_string(scopes):
  if type(scopes) in [list, set, tuple]:
    return " ".join(str(i) for i in scopes)
  return scopes


def _add_query_params_to_url(url, params):
  scheme, location, path, url_params, query, fragment = urlparse.urlparse(url)
  query_string = urlparse.parse_qsl(query, keep_blank_values=True)
  query_string.extend(params.items())
  query = urllib.urlencode(query_string)
  return urlparse.urlunparse(
      (scheme, location, path, url_params, query, fragment))


class CommunicationError(Exception):
  pass


class AuthenticationError(Exception):
  pass


class ValidationError(Exception):
  pass
