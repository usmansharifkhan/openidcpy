import base64
import json
import sys
import time
import unittest

import requests
from mock import Mock
from requests import Response
from jose import jwt

from openidcpy.client import OidcClient

sys.path.insert(0, '../superset/custom')

WELL_KNOWN = '{\"issuer\":\"http:\/\/localhost:8080\/auth\/realms\/teamplay\",\"authorization_endpoint\":\"http:\/\/localhost:8080\/auth\/realms\/teamplay\/protocol\/openid-connect\/auth\",\"token_endpoint\":\"http:\/\/localhost:8080\/auth\/realms\/teamplay\/protocol\/openid-connect\/token\",\"token_introspection_endpoint\":\"http:\/\/localhost:8080\/auth\/realms\/teamplay\/protocol\/openid-connect\/token\/introspect\",\"userinfo_endpoint\":\"http:\/\/localhost:8080\/auth\/realms\/teamplay\/protocol\/openid-connect\/userinfo\",\"end_session_endpoint\":\"http:\/\/localhost:8080\/auth\/realms\/teamplay\/protocol\/openid-connect\/logout\",\"jwks_uri\":\"http:\/\/localhost:8080\/auth\/realms\/teamplay\/protocol\/openid-connect\/certs\",\"check_session_iframe\":\"http:\/\/localhost:8080\/auth\/realms\/teamplay\/protocol\/openid-connect\/login-status-iframe.html\",\"grant_types_supported\":[\"authorization_code\",\"implicit\",\"refresh_token\",\"password\",\"client_credentials\"],\"response_types_supported\":[\"code\",\"none\",\"id_token\",\"token\",\"id_token token\",\"code id_token\",\"code token\",\"code id_token token\"],\"subject_types_supported\":[\"public\",\"pairwise\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"userinfo_signing_alg_values_supported\":[\"RS256\"],\"request_object_signing_alg_values_supported\":[\"none\",\"RS256\"],\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],\"registration_endpoint\":\"http:\/\/localhost:8080\/auth\/realms\/teamplay\/clients-registrations\/openid-connect\",\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\"],\"token_endpoint_auth_signing_alg_values_supported\":[\"RS256\"],\"claims_supported\":[\"sub\",\"iss\",\"auth_time\",\"name\",\"given_name\",\"family_name\",\"preferred_username\",\"email\"],\"claim_types_supported\":[\"normal\"],\"claims_parameter_supported\":false,\"scopes_supported\":[\"openid\",\"profile\",\"phone\",\"offline_access\",\"email\",\"address\"],\"request_parameter_supported\":true,\"request_uri_parameter_supported\":true,\"code_challenge_methods_supported\":[\"plain\",\"S256\"],\"tls_client_certificate_bound_access_tokens\":true}'
KEYS = '{\"keys\":[{\"kid\":\"gUp7OURQn7iAbgzJXfJimdz1lBlcIgxkPhthkE9h9B8\",\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"h3VxiZbdsK1jlz89TpnOjmg63WULdKxo9UnvOel-eIlJ8zzHQsrvNinVB4g-h9GSEG0VrV1ZY-pkqHfPfar0BjJ_LUdf_uFQLmxUMNk3evFfcVna6FClDA094D9iCRVxtOCTsz_-WjfZo0yBEv8FTsbKluXflNHxb72rqUHKpezIBAXXyLHCN2N3Qt7eeH6f57k4MpQutqibwZHeVEryUyRHN4P1fkf98NvnakjWe4LdXiK2CA_kf3oZ40LLDZWCOiKPh25SxW6ZP1ZHdDtlZZNTL54K_xTE3mvHL9zyB55-pLAr_gHUhENIR3I3AFsSshDvAhPL4JaYre3KedAviw\",\"e\":\"AQAB\"}]}'


def ordered(obj):
  if isinstance(obj, dict):
    return sorted((k, ordered(v)) for k, v in obj.items())
  if isinstance(obj, list):
    return sorted(ordered(x) for x in obj)
  else:
    return obj


def close():
  pass


class TestOidcClient(unittest.TestCase):
  def test_discover(self):
    def get(url, verify):
      response = Response()
      response.status_code = 200
      response.close = close
      if url == 'http://localhost:8080/auth/realms/teamplay/.well-known/openid-configuration':
        response.json = lambda: json.loads(WELL_KNOWN)
      elif url == 'http://localhost:8080/auth/realms/teamplay/protocol/openid-connect/certs':
        response.json = lambda: json.loads(KEYS)
      else:
        self.fail('Unexpected url: {}'.format(url))
      return response

    requests.get = Mock(side_effect=get)
    client = OidcClient(
        discovery_uri='http://localhost:8080/auth/realms/teamplay/.well-known/openid-configuration',
        client_id='asdf')

    client._discover()
    well_known = json.loads(WELL_KNOWN)
    self.assertTrue(
        ordered(client.well_known) == ordered(well_known))
    self.assertEqual(client.auth_uri, well_known['authorization_endpoint'])
    self.assertEqual(client.token_uri, well_known['token_endpoint'])
    jwks = json.loads(KEYS)
    self.assertTrue(
        ordered(client.certs[jwks['keys'][0]['kid']]) == ordered(
            jwks['keys'][0]))

  def test_create_auth_url(self):
    def get(url, verify):
      response = Response()
      response.status_code = 200
      response.close = close
      if url == 'http://localhost:8080/auth/realms/teamplay/.well-known/openid-configuration':
        response.json = lambda: json.loads(WELL_KNOWN)
      elif url == 'http://localhost:8080/auth/realms/teamplay/protocol/openid-connect/certs':
        response.json = lambda: json.loads(KEYS)
      else:
        self.fail('Unexpected url: {}'.format(url))
      return response

    requests.get = Mock(side_effect=get)
    client = OidcClient(
        discovery_uri='http://localhost:8080/auth/realms/teamplay/.well-known/openid-configuration',
        client_id='asdf')
    url = client.create_auth_url('code', 'http://yourwebsite.com/redirect',
                                 ['abc', 'def'], 'wyoming')
    self.assertTrue(
        'http://localhost:8080/auth/realms/teamplay/protocol/openid-connect/auth' in url)
    self.assertTrue('scope=abc+def' in url)
    self.assertTrue('state=wyoming' in url)
    self.assertTrue(
        'redirect_uri=http%3A%2F%2Fyourwebsite.com%2Fredirect' in url)
    self.assertTrue('response_type=code' in url)
    self.assertTrue('client_id=asdf' in url)

  def test_get_auth_url_single_scope(self):
    def get(url, verify):
      response = Response()
      response.status_code = 200
      response.close = close
      if url == 'http://localhost:8080/auth/realms/teamplay/.well-known/openid-configuration':
        response.json = lambda: json.loads(WELL_KNOWN)
      elif url == 'http://localhost:8080/auth/realms/teamplay/protocol/openid-connect/certs':
        response.json = lambda: json.loads(KEYS)
      else:
        self.fail('Unexpected url: {}'.format(url))
      return response

    requests.get = Mock(side_effect=get)
    client = OidcClient(
        discovery_uri='http://localhost:8080/auth/realms/teamplay/.well-known/openid-configuration',
        client_id='asdf')
    url = client.create_auth_url('code', 'http://yourwebsite.com/redirect',
                                 'abc', 'wyoming')
    self.assertTrue(
        'http://localhost:8080/auth/realms/teamplay/protocol/openid-connect/auth' in url)
    self.assertTrue('scope=abc' in url)
    self.assertTrue('state=wyoming' in url)
    self.assertTrue(
        'redirect_uri=http%3A%2F%2Fyourwebsite.com%2Fredirect' in url)
    self.assertTrue('response_type=code' in url)
    self.assertTrue('client_id=asdf' in url)

  def test_get_tokens_from_code(self):
    url = 'http://localhost:8088/oidc-authorized?state=mystate&code=mycode'

    def get(url, verify):
      response = Response()
      response.status_code = 200
      response.close = close
      if url == 'http://localhost:8080/auth/realms/teamplay/.well-known/openid-configuration':
        response.json = lambda: json.loads(WELL_KNOWN)
      elif url == 'http://localhost:8080/auth/realms/teamplay/protocol/openid-connect/certs':
        response.json = lambda: json.loads(KEYS)
      else:
        self.fail('Unexpected url: {}'.format(url))
      return response

    def post(url, data, headers, verify):
      self.assertEqual(url,
                       'http://localhost:8080/auth/realms/teamplay/protocol/openid-connect/token')
      self.assertTrue(ordered(data) == ordered(
          {'code': 'mycode', 'scope': 'abc def',
           'grant_type': 'authorization_code', 'client_id': 'thetick',
           'redirect_uri': 'http://yourwebsite.com/redirect'}))
      self.assertTrue(ordered(headers) == ordered(
          {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
           'Accept': 'application/json',
           'Authorization': 'Basic dGhldGljazphcnRodXI='}))
      response = Response()
      response.status_code = 200
      response.close = close
      response.json = lambda: {'access_token': 'I grant thy access'}
      return response

    requests.get = Mock(side_effect=get)
    requests.post = Mock(side_effect=post)
    client = OidcClient(
        discovery_uri='http://localhost:8080/auth/realms/teamplay/.well-known/openid-configuration',
        client_id='thetick', client_secret='arthur')
    token = client.get_tokens_from_code(url, 'http://yourwebsite.com/redirect',
                                        ['abc', 'def'], 'mystate')
    self.assertTrue('access_token' in token)
    self.assertTrue(token['access_token'], 'I grant thy access')

  def test_validate_jwt(self):

    def get(url, verify):
      response = Response()
      response.status_code = 200
      response.close = close
      if url == 'http://localhost:8080/auth/realms/teamplay/.well-known/openid-configuration':
        response.json = lambda: json.loads(WELL_KNOWN)
      elif url == 'http://localhost:8080/auth/realms/teamplay/protocol/openid-connect/certs':
        response.json = lambda: json.loads(KEYS)
      else:
        self.fail('Unexpected url: {}'.format(url))
      return response

    requests.get = Mock(side_effect=get)
    client = OidcClient(
        discovery_uri='http://localhost:8080/auth/realms/teamplay/.well-known/openid-configuration',
        client_id='unittest')

    test_header = {
      'kid': 'gUp7OURQn7iAbgzJXfJimdz1lBlcIgxkPhthkE9h9B8',
      'alg': 'RS256'
    }
    test_payload = {
      'iss': 'keycloak',
      'sub': 'testing',
      'aud': 'unittest',
      'iat': int(time.time()),
      'nbf': int(time.time()),
      'exp': int(time.time()) + 60,
      'jti': 'my-jwt',
      'username': 'bushido'
    }

    token_str = '{}.{}.{}'.format(base64.b64encode(json.dumps(test_header).encode("utf-8")).decode("utf-8"),
                                  base64.b64encode(json.dumps(test_payload).encode("utf-8")).decode("utf-8"),
                                  'my-signature')

    def decode_jwt(token, key, audience):
      self.assertEqual(audience, test_payload['aud'])
      self.assertEqual(token, token_str)
      return json.loads(base64.b64decode(token.split('.')[1]))

    jwt.decode = decode_jwt
    claims = client.validate_jwt(token_str)

    self.assertTrue(ordered(claims) == ordered(test_payload))


if __name__ == '__main__':
  unittest.main()
