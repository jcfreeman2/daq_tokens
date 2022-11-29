#!/usr/bin/env python3
"""
A daemon to serve TDAQ tokens.

This runs ideally as system daemon, waiting on 
/run/daq_token for clients to connect.
It processes the request and creates a new
signed JWToken with 'sub' as the requesting
user.
"""

from __future__ import print_function

import sys
import signal

from .common import get_private_key, make_token

running = True

def usage():
    print("usage: python3 -m token_meister.local /path/to/private_key [ /path/to/socket ]", file=sys.stderr)

def signal_handler(sig, frame):
    global running
    running = False
    print("token_meister.local: Got SIGTERM, exiting...", file=sys.stderr)
    server.close()

if __name__ == '__main__':

    import os
    import socket
    import json
    from struct import unpack
    from pwd    import getpwuid
    from grp    import getgrgid

    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    private_key_path = sys.argv[1]

    if len(sys.argv) > 2:
        server_name = sys.argv[2]
    else:
        server_name = os.environ.get('XDG_RUNTIME_DIR', '/run') + '/daq_token'

    if 'LISTEN_FDS' in os.environ:
      server = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
    else:
      server = socket.socket(socket.AF_UNIX)
      try:
          os.remove(server_name)
      except:
          pass
      server.bind(server_name)
      server.listen(socket.SOMAXCONN)

    signal.signal(signal.SIGTERM, signal_handler)

    while running:
        try:
            client, addr = server.accept()
            creds  = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 20)
            pid, uid, gid = unpack('3i', creds)
            get_private_key(private_key_path)
            t = make_token(getpwuid(uid).pw_name)
            if isinstance(t, str):
              t = t.encode('utf-8')
            client.send(t)
        except Exception as ex:
            if running:
                print(ex, file=sys.stderr)
        finally:
            client.close()
