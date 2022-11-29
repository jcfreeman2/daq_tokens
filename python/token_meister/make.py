#!/usr/bin/env python3
"""
A command line program to generate a user's token.

It's purpose is to be called explicitly from the shell
with a path to the private key and a user name.
"""

from __future__ import print_function

import sys
import signal

def usage():
    print("usage: python3 -m token_meister.make /path/to/private_key username", file=sys.stderr)

from .common import get_private_key, make_token

if __name__ == '__main__':

    if len(sys.argv) != 3:
        usage()
        sys.exit(1)

    private_key_path = sys.argv[1]
    user_name        = sys.argv[2]

    get_private_key(private_key_path)
    t = make_token(user_name);
    if isinstance(t, str):
        t = t.encode('utf-8')
    print(t.decode('utf-8'), end=None);
