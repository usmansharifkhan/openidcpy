## Openidcpy
A package that implements the Authorization Flow client for the OpenID Connect relying party. The package can be used to fetch OpenID Connect tokens using Authorization Flow and validate them using JWKS. The client has been implemented with KeyCloak as the OpenID Connect Authorization Provider.

#### Usage

The only class of use is `OidcClient` which can be imported in code as:

```python
from openidcpy import OidcClient
```

You'd need to initialize this client as follows:

```python
discovery_url = 'The .well_known discovery endpoint'
client_id = 'The client id assigned to the RP'
client_secret = 'The client secret assigned to RP if the client is private, otherwise None'
client = OidcClient(discovery_url=discovery_url, client_id=client_id, client_secret=client_secret)
```

The client basically exposes 3 methods that, if called in sequence, complete the Authorization Flow. The first call is to create the authorization code url:

```python
response_type = 'code'  # Always `code` for Authorization Flow
redirect_uri = 'uri where the relying party is running'
scopes = ['openid', 'email', 'profile'] # Array of requested scopes
state = 'Some random generated value that is returned in the redirect, prevents csrf'
url = client.create_auth_url(response_type=response_type, redirect_uri=redirect_uri, scopes=scopes, state=state)
```

You'll need to redirect your application to the above url. The redirection will cause the auth server's login page to be displayed. Once the user logs in, the browser is redirected to the `redirect_uri` passed into the above call with an authorization code. You'll need to exchange the code with the JWT token as follows:

```python
url = 'redirect_uri + query params, basically the endpoint on which the auth server redirected'
redirect_uri = 'uri where the relying party is running'
scopes = ['openid', 'email', 'profile'] # Array of requested scopes
state = 'Same value from the previous request'
tokens = client.get_tokens_from_code(url=url, redirect_uri=redirect_uri, scopes=scopes, state=state)
```

Now, depending on the scopes you used the `tokens` dictionary can have either `access_token`, the `id_token` or both.

The next step is to validate these tokens, for which the client provides the following method:

```python
id_token = tokens['id_token']
claims = client.validate_jwt(id_token)
```
The method validates the signature of the token, the audience (whether the token was intended for you) and the expiration of the token.
The `claims` dictionary will contain the decoded contents of the token. Based on the scopes you specified, it can contain the `email` or `preferred_username`.

#### External Dependencies

* requests (2.20.0)
* python-jose (3.0.1)


#### Contributions

Contributions are strongly encouraged, since this is just a basic implementation of the Authorization and there's a lot more to OpenId Connect that can be added here. I will try to add the rest whenever I find the time but if I can't, feel free to add it yourself.