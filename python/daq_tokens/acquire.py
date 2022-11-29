# Cached token for mode == REUSE
last_access_token = None
last_access_token_time = None

# Cached full reply for last HTTP request
# This contains both access and refresh tokens
last_reply = None
last_reply_time = None

FRESH = 0
REUSE = 1

def acquire(mode=REUSE):
    """
    Acquire a TDAQ JWToken.

      Try to acquire a token via one of the methods
      in the TDAQ_TOKEN_ACQUIRE variable:

        - local
        - kerberos
        - browser
        - password
        - gssapi

      returns   - a string containing the encoded token

    """
    import os
    import time
    import jwt

    token = None
    exception = None

    global last_access_token, last_access_token_time

    if mode == REUSE and last_access_token and time.time() < last_access_token_time + 600:
        return last_access_token

    for method in os.environ.get('TDAQ_TOKEN_ACQUIRE', 'env local kerberos').split(' '):

        if method == 'env':
            if 'BEARER_TOKEN' in os.environ:
                token = os.environ['BEARER_TOKEN'].strip()
                decoded = jwt.decode(token, options={ 'verify_signature': False })
                if decoded['exp'] - 600 < int(time.time()):
                    del os.environ['BEARER_TOKEN']
                    continue
                break
            else:
                uid = os.geteuid()
                if 'BEARER_TOKEN_FILE' in os.environ:
                    file_name = os.environ['BEARER_TOKEN_FILE']
                else:
                    file_name = os.environ.get('XDG_RUNTIME_DIR', '/tmp') + '/bt_u' + str(uid) + '-atlas-tdaq'
                try:
                    stat = os.stat(file_name)
                    if stat.st_uid != uid:
                        del os.environ['BEARER_TOKEN_FILE']
                        continue
                    with open(file_name, 'rt') as f:
                        token = f.readline().strip()
                        decoded = jwt.decode(token, options={ 'verify_signature': False })
                        if decoded['exp'] + 600 < int(time.time()):
                            del os.environ['BEARER_TOKEN_FILE']
                            continue
                    break
                except Exception as ex:
                    exception = ex
                    continue

        if method == 'local':
            if 'TDAQ_TOKEN_PATH' in os.environ:
                for path in os.environ['TDAQ_TOKEN_PATH'].split(':'):
                    try:
                        from socket import socket, AF_UNIX
                        with socket(AF_UNIX) as s:
                            retries = 2
                            while retries > 0:
                                retries = retries - 1
                                try:
                                    s.connect(path)
                                    break
                                except Exception as ex:
                                    exception = ex
                                    if retries > 0:
                                        time.sleep(0.05)
                            if retries <= 0:
                                continue
                            token = s.recv(8192).decode('utf-8')
                            break
                    except Exception as ex:
                        exception = ex
                        continue
                if token:
                    break
                else:
                    continue
            else:
                continue

        if method == 'gssapi':

            try:
                import gssapi
                from socket import socket, AF_INET

                server_host = os.environ.get('TDAQ_TOKEN_GSSAPI_HOST', 'vm-atdaq-token.cern.ch')
                server_port = int(os.environ.get('TDAQ_TOKEN_GSSAPI_PORT', '8991'))

                server = gssapi.Name(f'atdaqjwt@{server_host}', name_type=gssapi.NameType.hostbased_service)
                context = gssapi.SecurityContext(name=server)

                with socket(AF_INET) as s:
                    s.connect((server_host, server_port))

                    to_server = context.step()
                    while not context.complete:
                        length = len(to_server)
                        s.sendall(length.to_bytes(4, byteorder='little'))
                        s.sendall(to_server)
                        length = int.from_bytes(recv_all(s, 4), byteorder='little')
                        from_server = recv_all(s, length)
                        to_server = context.step(from_server)
                        if not to_server:
                            break

                    if not context.complete:
                        raise RuntimeError('GSSAPI failed')

                    length = int.from_bytes(recv_all(s, 4), byteorder='little')
                    token = context.decrypt(recv_all(s, length)).decode('utf-8')
                    break

            except Exception as ex:
                exception = ex
                continue

        global last_reply, last_reply_time

        if last_reply:
            if last_reply_time + last_reply['refresh_expires_in'] > int(time.time()):
                try:
                    last_reply = get_sso_token_from_refresh_token(last_reply['refresh_token'])
                    last_reply_time = int(time.time())
                    token = last_reply['access_token']
                    break;
                except Exception as ex:
                    exception = ex
                    last_reply = None

        if method == 'kerberos':
            from .cern_sso import get_sso_token_from_kerberos
            try:
                last_reply      = get_sso_token_from_kerberos('ch.cern.atlas.tdaq:/redirect', 'atlas-tdaq-token')
                last_reply_time = int(time.time())
            except Exception as ex:
                exception = ex
                continue

        elif method == 'browser':
            from .cern_sso import get_sso_token_from_browser
            try:
                last_reply      = get_sso_token_from_browser('atlas-tdaq-token')
                last_reply_time = int(time.time())
            except Exception as ex:
                exception = ex
                continue

        elif method == 'password':
            from .cern_sso import get_sso_token_from_password
            import getpass
            try:
                last_reply      = get_sso_token_from_password('ch.cern.atlas.tdaq:/redirect', 'atlas-tdaq-token', getpass.getuser(), getpass.getpass())
                last_reply_time = int(time.time())
            except Exception as ex:
                exception = ex
                continue
        else:
            raise RuntimeError("Invalid acquire method: " + method)

        token = last_reply['access_token']

    if mode == REUSE:
        last_access_token = token
        last_access_token_time = int(time.time())

    if token:
        return token
    elif exception:
        raise exception
    else:
        raise RuntimeError("Could not acquire token")

def recv_all(s, length):
        chunks = []
        received = 0
        while received < length:
            chunk = s.recv(min(length - received, 2048))
            if chunk == b'':
                raise RuntimeError("socket connection broken")
            chunks.append(chunk)
            received = received + len(chunk)
        return b''.join(chunks)
