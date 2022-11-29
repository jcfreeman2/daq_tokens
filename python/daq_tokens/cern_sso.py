#
# Adapted from https://gitlab.cern.ch/authzsvc/docs/auth-get-sso-cookie
#

import logging
import sys, requests, time, uuid
from requests_gssapi import HTTPKerberosAuth, OPTIONAL
from bs4 import BeautifulSoup

try:
    from urllib.parse import parse_qs
except ImportError:  # python 2.7 compatibility
    from cookielib import MozillaCookieJar, Cookie
    from urlparse import parse_qs

def login_with_kerberos(login_page, verify_cert, auth_hostname, silent):
    """Simulates a browser session to log in using SPNEGO protocol"""

    session = requests.Session()
    if not silent:
        logging.info("Fetching target URL and its redirects")
    r_login_page = session.get(login_page, verify=verify_cert)
    if not silent:
        logging.info("Parsing landing page to get the Kerberos login URL")
    soup = BeautifulSoup(r_login_page.text, features="html.parser")
    kerberos_button = soup.find(id="social-kerberos")
    if not kerberos_button:
        raise Exception("Landing page not recognized as the Keycloak login page")
    kerberos_path = kerberos_button.get("href")
    if not silent:
        logging.info("Fetching Kerberos login URL")
    r_kerberos_redirect = session.get(
        "https://{}{}".format(auth_hostname, kerberos_path)
    )
    if not silent:
        logging.info("Logging in using Kerberos Auth")
    r_kerberos_auth = session.get(
        r_kerberos_redirect.url,
        auth=HTTPKerberosAuth(mutual_authentication=OPTIONAL),
        allow_redirects=False,
    )
    while (
        r_kerberos_auth.status_code == 302
        and auth_hostname in r_kerberos_auth.headers["Location"]
    ):
        r_kerberos_auth = session.get(
            r_kerberos_auth.headers["Location"], allow_redirects=False
        )
    if r_kerberos_auth.status_code != 302:
        logging.debug("Not automatically redirected")
        raise Exception("Not automatically redirected: not trying SAML")
    return session, r_kerberos_auth

def get_sso_token_from_kerberos(url, clientid, verify_cert=True, auth_hostname='auth.cern.ch', auth_realm='cern', silent=False):
    """Get an OIDC token by logging in in the Auhtorization URL using Kerberos

    :param url: Application or Redirect URL. Required for the OAuth request.
    :param clientid: Client ID of a client with implicit flow enabled.
    :param verify_cert: Verify certificate.
    :param auth_hostname: Keycloak hostname.
    :param auth_realm: Authentication realm.
    :param silent: Flag for printing log messages (default: False).
    """
    try:
        random_state = str(uuid.uuid4()).split("-")[0]
        authz_url = "https://{}/auth/realms/{}/protocol/openid-connect/auth?client_id={}&response_type=code&state={}&redirect_uri={}".format(
                auth_hostname, auth_realm, clientid, random_state, url
            )
        login_response = login_with_kerberos(authz_url, verify_cert, auth_hostname, silent=silent)[1]
        authz_response = parse_qs(login_response.headers["Location"].split("?")[1])

        if authz_response["state"][0] != random_state:
            raise Exception("The authorization response doesn't contain the expected state value.")

        r = requests.post(
            "https://{}/auth/realms/{}/protocol/openid-connect/token".format(
                auth_hostname, auth_realm
            ),
            data={
                "client_id": clientid,
                "grant_type": "authorization_code",
                "code": authz_response["code"][0],
                "redirect_uri": url,
            },
        )

        if not silent:
            if not r.ok:
                logging.error("The token response was not successful: {}".format(r.json()))
                r.raise_for_status()

        token_response = r.json()

        return token_response
    except Exception as e:
        if not silent:
            logging.error(
                "An error occurred while trying to fetch user token, {}".format(e)
            )
        raise e

def get_sso_token_from_password(url, clientid, user, password, verify_cert=True, auth_hostname='auth.cern.ch', auth_realm='cern', silent=False):
    """Get an OIDC token by logging in in the Auhtorization URL using user name and password.

    :param url: Application or Redirect URL. Required for the OAuth request.
    :param clientid: Client ID of a client with implicit flow enabled.
    :param user: the user name.
    :param password: the password to authenticat.
    :param verify_cert: Verify certificate.
    :param auth_hostname: Keycloak hostname.
    :param auth_realm: Authentication realm.
    :param silent: Flag for printing log messages (default: False).
    """
    try:
        r = requests.post(
            "https://{}/auth/realms/{}/protocol/openid-connect/token".format(
                auth_hostname, auth_realm
            ),
            data={
                "client_id": clientid,
                "grant_type": "password",
                "username" : user,
                "password" : password,
                "redirect_uri": url,
            },
        )

        if not silent:
            if not r.ok:
                logging.error("The token response was not successful: {}".format(r.json()))
                r.raise_for_status()

        token_response = r.json()

        return token_response
    except Exception as e:
        if not silent:
            logging.error(
                "An error occurred while trying to fetch user token, {}".format(e)
            )
        raise e

def get_sso_token_from_browser(client_id, redirect_uri = 'http://localhost', auth_host = 'auth.cern.ch', auth_realm = 'cern'):
    """
    Retrieve an SSO token with the help of the user's web browser.

    This is only useful for interactive sessions where it is
    possible to start a new browser or open a window in an
    existing one.

    The 'redirect' url should be 'http://localhost'.
    """

    from http.server import HTTPServer, BaseHTTPRequestHandler

    class HandleCode(BaseHTTPRequestHandler):
        """
        HTTP request handler to retrieve the
        'code' and 'state' entries from the
        redirect URL
        """

        def log_message(format, *args):
            """
            Do not print out log messages.
            """
            pass

        def do_GET(self):
            """
            Handle redirected GET request.
            Extracts code and status from query string
            """

            # Ignore everything but the root location
            if self.path[:self.path.find('?')] != '/':
                self.send_response(404, 'Not found')
                return

            # Even if the authentication has failed,
            # we will print out a helpful message here.
            self.send_response(302,'Redirect')

            from urllib.parse import parse_qs
            options = parse_qs(self.path[self.path.find('?')+1:])
            if 'state' in options and 'code' in options:
                self.server.reply_code = { 'state' : options['state'][0],
                                           'code'  : options['code'][0] }
                self.send_header('Location', os.environ.get('TDAQ_TOKEN_AUTH_SUCCESS', "https://atlas-tdaq-sw.web.cern.ch/atlas-tdaq-sw/auth/success.html"))
            else:
                self.send_header('Location', os.environ.get('TDAQ_TOKEN_AUTH_FAILURE', "https://atlas-tdaq-sw.web.cern.ch/atlas-tdaq-sw/auth/failure.html"))
            self.end_headers()

    # Prepare local web server
    server = HTTPServer(('',0), HandleCode)
    server.reply_code = None

    # Generate random state
    import uuid
    random_state = str(uuid.uuid4()).split("-")[0]

    redirect_uri = redirect_uri + ':' + str(server.server_port)
    authz_url = "https://{}/auth/realms/{}/protocol/openid-connect/auth?client_id={}&response_type=code&state={}&redirect_uri={}".format(
        auth_host,
        auth_realm,
        client_id,
        random_state,
        redirect_uri)

    import threading
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    import webbrowser, os
    save_out = os.dup(1)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 1)
    os.close(devnull)
    try:
        if not webbrowser.open(authz_url):
            server.shutdown()
            raise RuntimeError("Cannot start browser")
    finally:
        os.dup2(save_out, 1)

    from time import sleep
    import sys
    while server.reply_code == None:
        sleep(2)

    server.shutdown()

    if server.reply_code['state'] != random_state:
        raise RuntimeError('Invalid state: ' + reply_code['state'] + ' expected:' + random_state)

    import requests
    r = requests.post('https://auth.cern.ch/auth/realms/cern/protocol/openid-connect/token',
                      data = {
                          'client_id': 'atlas-tdaq-token',
                          'grant_type': 'authorization_code',
                          'code': server.reply_code['code'],
                          'redirect_uri': redirect_uri
                      })
    if r.ok:
        return r.json()
    else:
        raise RuntimeError('Could not get SSO token:' + r.reason)

def get_sso_token_from_refresh_token(refresh_token, client_id = 'atlas-tdaq-token', auth_hostname='auth.cern.ch', auth_realm='cern'):
    import requests
    r = requests.post('https://' + auth_hostname + '/auth/realms/' + auth_realm + '/protocol/openid-connect/token',
                      data =
                      {
                          'grant_type': 'refresh_token',
                          'client_id' : client_id,
                          'refresh_token' : refresh_token
                      }
    )
    if r.ok:
        return r.json()
    else:
        raise RuntimeError("Cannot refresh token: " + r.reason)

if __name__ == '__main__':
    import sys
    import json
    import argparse

    parser = argparse.ArgumentParser(description='Acquire CERN SSO token')
    parser.add_argument('-c', '--client', help='Client ID', required=True)
    parser.add_argument('-s', '--secret', help='Client secret')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-k', '--krb5',  action="store_true", help='Use Kerberos 5 authentication')
    group.add_argument('-b', '--browser', action="store_true", help='Use browser authentication')
    group.add_argument('-p', '--password', action="store_true", help='Use password authentication')
    group.add_argument('-r', '--refresh', help='Use refresh token')
    parser.add_argument('-u', '--user', help='User name (default: logged in user)')
    parser.add_argument('-f', '--file', help='File containing user password')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    args = parser.parse_args()

    if args.output:
        out = open(args.output, 'w')
    else:
        out = sys.stdout

    if args.krb5:
        json.dump(get_sso_token_from_kerberos('http://localhost', args.client), out)
    elif args.browser:
        json.dumps(get_sso_token_from_browser(args.client), out)
    elif args.password:
        import getpass
        json.dump(get_sso_token_from_password('ch.cern.atlas.tdaq:/redirect', client, args.user or getpass.getuser(), getpass.getpass()), out)
    elif args.refresh:
        json.dump(get_sso_token_from_refresh_token(args.refresh, args.client), out)
