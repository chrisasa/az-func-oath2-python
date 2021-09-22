from functools import wraps
import requests
from jose import jwt
import json
import logging
import os
from flask import Flask, request, jsonify, _request_ctx_stack, redirect, url_for, session
# Error handler


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


class AadAuth:
    def __init__(self, flask_app, tenant_name, tenant_id, api_audience, srv_app_client_name, srv_app_client_id, srv_app_client_secret) -> None:
        self.app = flask_app

        self.TENANT_NAME = tenant_name
        self.TENANT_ID = tenant_id
        self.API_AUDIENCE = api_audience

        self.session_token_key = "auth_token"
        self.session_login_origin = ""

        self.SRV_APP_CLIENT_NAME = srv_app_client_name
        self.SRV_APP_CLIENT_ID = srv_app_client_id
        self.SRV_APP_CLIENT_SECRET = srv_app_client_secret
        self.AUTH_CALLBACK_ENDPOINT = "callback"

        @self.app.route(f"/{self.AUTH_CALLBACK_ENDPOINT}")
        def login_callback():
            aad_code = request.args.get('code')
            srv_app_client_redirect_uri = request.url_root + "callback"
            headers = {
                'Accept': '*/*',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Host': 'login.microsoftonline.com',
                'accept-encoding': 'gzip, deflate',
                'cache-control': 'no-cache'
            }

            payload = {
                'redirect_uri': srv_app_client_redirect_uri,
                'client_id': self.SRV_APP_CLIENT_ID,
                'grant_type': 'authorization_code',
                'code': aad_code,
                'client_secret': self.SRV_APP_CLIENT_SECRET,
                'scope': f"https://{self.SRV_APP_CLIENT_NAME}.{self.TENANT_NAME}.onmicrosoft.com/user_impersonation"
            }

            url = f"https://login.microsoftonline.com/{self.TENANT_NAME}.onmicrosoft.com/oauth2/v2.0/token"
            rsp = requests.request("POST", url, headers=headers, data=payload)
            json_data = json.loads(rsp.text)
            token_value = json_data["access_token"]
            token_type = json_data["token_type"]
            auth_token_full = f"{token_type} {token_value}"
            session[self.session_token_key] = auth_token_full

            # url_ree = url_for("vmInfo")
            url_ree = session.get(self.session_login_origin)

            return redirect(location=url_ree, code=301)

        @self.app.errorhandler(AuthError)
        def handle_auth_error(ex):
            print('handling error')
            response = jsonify(ex.error)
            response.status_code = ex.status_code
            return response

    def get_token_auth_header(self):
        """Obtains the Access Token from the Authorization Header
        """
        auth = self.get_bearer_token()
        parts = auth.split()
        if parts[0].lower() != "bearer":
            raise AuthError({"code": "invalid_header",
                            "description":
                             "Authorization header must start with"
                             " Bearer"}, 401)
        elif len(parts) == 1:
            raise AuthError({"code": "invalid_header",
                            "description": "Token not found"}, 401)
        elif len(parts) > 2:
            raise AuthError({"code": "invalid_header",
                            "description":
                             "Authorization header must be"
                             " Bearer token"}, 401)
        token = parts[1]
        return token

    def get_bearer_token(self):
        auth_header = request.headers.get("Authorization", None)
        auth_ses = session.get(self.session_token_key)
        if auth_header:
            auth = auth_header
        elif auth_ses:
            auth = auth_ses
        else:
            auth = None
        return auth

    def trigger_login(self):
        if session.get(self.session_token_key):
            session.pop(self.session_token_key)
        srv_app_client_redirect_uri = request.url_root + self.AUTH_CALLBACK_ENDPOINT
        request_response_code_url_with_id = f"https://login.microsoftonline.com/{self.TENANT_ID}/oauth2/v2.0/authorize" \
            "?response_type=code" + \
            f"&client_id={self.SRV_APP_CLIENT_ID}" + \
            f"&redirect_uri={srv_app_client_redirect_uri}" + \
            "&scope=openid"
        return redirect(request_response_code_url_with_id, code=302)

    def requires_auth(self, f):
        """Determines if the Access Token is valid
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            try:

                session[self.session_login_origin] = request.base_url
                auth = self.get_bearer_token()
                if not auth:
                    return self.trigger_login()
                token = self.get_token_auth_header()
                jsonurl = requests.get(
                    "https://login.microsoftonline.com/" + self.TENANT_ID + "/discovery/v2.0/keys")
                jwks = json.loads(jsonurl.content)
                unverified_header = jwt.get_unverified_header(token)
                rsa_key = {}
                for key in jwks["keys"]:
                    if key["kid"] == unverified_header["kid"]:
                        rsa_key = {
                            "kty": key["kty"],
                            "kid": key["kid"],
                            "use": key["use"],
                            "n": key["n"],
                            "e": key["e"]
                        }
            except Exception:
                raise AuthError({"code": "invalid_header",
                                "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)
            if rsa_key:
                try:
                    payload = jwt.decode(
                        token=token,
                        key=rsa_key,
                        algorithms=["RS256"],
                        audience=self.API_AUDIENCE,
                        issuer="https://sts.windows.net/" + self.TENANT_ID + "/"
                    )
                except jwt.ExpiredSignatureError:
                    # raise AuthError({"code": "token_expired",
                    #                  "description": "token is expired"}, 401)
                    return self.trigger_login()
                except jwt.JWTClaimsError:
                    raise AuthError({"code": "invalid_claims",
                                    "description":
                                     "incorrect claims,"
                                     "please check the audience and issuer"}, 401)
                except Exception:
                    raise AuthError({"code": "invalid_header",
                                    "description":
                                     "Unable to parse authentication"
                                     " token."}, 401)
                _request_ctx_stack.top.current_user = payload

                return f(*args, **kwargs)
            raise AuthError({"code": "invalid_header",
                            "description": "Unable to find appropriate key"}, 401)
        return decorated

    # Controllers API

    # def requires_scope(required_scope):
    #     """Determines if the required scope is present in the Access Token
    #     Args:
    #         required_scope (str): The scope required to access the resource
    #     """
    #     token = get_token_auth_header()
    #     unverified_claims = jwt.get_unverified_claims(token)
    #     if unverified_claims.get("scope"):
    #         token_scopes = unverified_claims["scope"].split()
    #         for token_scope in token_scopes:
    #             if token_scope == required_scope:
    #                 return True
    #     return False
