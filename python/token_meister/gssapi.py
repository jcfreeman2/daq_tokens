#!/usr/bin/env python3
"""
A daemon to serve TDAQ tokens based on kerberos tokens.

This runs ideally as system daemon, listening on
on a well-defined port.

It processes the request and creates a new
signed JWToken with 'sub' as the requesting
user.
"""

import sys
import signal

from .common import get_private_key, make_token

def receive_all(s, length):
        chunks = []
        received_ = 0
        while received < length:
            chunk = s.recv(min(length - received, 2048))
            if chunk == b'':
                raise RuntimeError("socket connection broken")
            chunks.append(chunk)
            received = received + len(chunk)
        return b''.join(chunks)

running = True

def usage():
    print("usage: python3 -m token_meister.gssapi /path/to/private_key [ port ]", file=sys.stderr)

def gssapi_context(sock):
    import gssapi

    fqdn        = socket.getfqdn()
    server_name = gssapi.Name(f'atdaqjwt@{fqdn}', name_type=gssapi.NameType.hostbased_service)
    creds       = gssapi.Credentials(name=server_name, usage='accept')
    context     = gssapi.SecurityContext(creds=creds)

    length = 0
    while not context.complete:
        length = int.from_bytes(recv_all(sock, 4), byteorder='little')
        from_client = recv_all(sock, length)
        to_client = context.step(from_client)
        if not to_client:
            break
        sock.sendall(len(to_client).to_bytes(4, byteorder='little'))
        sock.sendall(to_client)

    if not context.complete:
        raise RuntimeError("GSSAPI failed")

    return context

def signal_handler(sig, frame):
    global running
    running = False
    print("token_meister.gssapi: Got SIGTERM, exiting...", file=sys.stderr)
    server.close()

if __name__ == '__main__':

    import os
    import socket

    port = 8991

    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    private_key_path = sys.argv[1]

    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    if 'LISTEN_FDS' in os.environ:
      server = socket.fromfd(3, socket.AF_INET6, socket.SOCK_STREAM)
    else:
      server = socket.socket(socket.AF_INET6)
      server.bind(("",port))
      server.listen(socket.SOMAXCONN)

    while running:
        try:
            client, addr = server.accept()
            context = gssapi_context(client)
            user = str(context.initiator_name).split('@',1)[0]
            get_private_key(private_key_path)
            t = make_token(user)
            if isinstance(t, str):
              t = t.encode('utf-8')
            client.sendall(len(t).to_bytes(4, byteorder='little'))
            client.sendall(context.encrypt(t))
        except Exception as ex:
            if running:
                print(ex, file=sys.stderr)
        finally:
            client.close()
