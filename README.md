
# JSON Web Tokens for authentication in TDAQ software.

This package provides a simple interface to acquire and verify
[JSON Web Tokens](https://jwt.io)(JWT) that are signed and provide proof of the
(UNIX) identity of the originator of the ticket.

## API

The API is on purpose very simple and uses only environment
variables for configuration.

The `acquire()` function can be used to get a JWT. It takes one optional
arguments. The return value is an encoded and signed JWT in the
form of a string that can be passed around without fear of tampering.
The content is not encrypted, however.

The optional argument indicates if the caller is willing to accept
a token that is not unique, i.e. it has been generated and maybe
used already by other callers. This is usually fine as a token
is valid for about 20 minutes and this saves the application from
acquiring and caching tokens on a higher level. 

If, however, a unique token is desired, the argument should be 
the equivalent of `daq::tokens::Mode::Fresh`, depending
on the programming language. Such a token is guaranteed to be
unique and is never mixed with the cached tokens mentioned before.

The `verify()` function can be used to verify a token. It takes
the encoded token as a string as first parameter. The result
is the decoded token that can be inspected by the user.

### General Configuration

The `TDAQ_TOKEN_CHECK` environment variable has to be set to 
`1` to enable the checks in the TDAQ application code. 

The `bool daq::tokens::enabled()` method should be used to
check if checks are enabled.

Note that the following methods work independently of this variable,
this is just to switch the behaviour of the DAQ applications themselves
which behave in a backward compatible way otherwise.

### Configuration for `acquire()`

The acquire function uses the following environment
variable:

#### `TDAQ_TOKEN_PATH`

If this variable is set it should point to a local UNIX
socket who has the `token_meister` server listening on the
other side. The client will connect to the socket and 
receive the signed JWToken.

This is the preferred method in a controlled production environment.
The server side is controlled and the socket is used to retrieve
the identity of the user acquiring a ticket.

If the variable is not set, it will default to
`/run/tdaq_token`.

#### Authorization via CERN SSO

If `TDAQ_TOKEN_PATH` is not set, the `acquire()` function will
do the equivalent of:

```shell
auth-get-sso-token --url ${TDAQ_TOKEN_AUTH_URL:=ch.cern.atlas.tdaq:/redirect} --client ${TDAQ_TOKEN_AUTH_CLIENT:=atlas-tdaq-token}
```

This requires that the user has a valid Kerberos 5 ticket. The arguments can
be overriden by the `TDAQ_TOKEN_AUTH_URL` and `TDAQ_TOKEN_AUTH_CLIENT` environment
variables, rsp.

### Configuration for `verify()`

#### `TDAQ_TOKEN_PUBLIC_KEY_URL`

This variable should be the default method and specifies a URL where
to find the public key(s). The public key will typically be cached
internally by the `verify()` function. So repeated
calls will not trigger multiple HTTP(S) requests.

If it not set, the public key will be retrieved from
`${TDAQ_TOKEN_PUBLIC_KEY_URL:=https://auth.cern.ch/auth/realms/cern/protocol/openid-connect/certs}`, i.e.
it will use the CERN SSO public key.

Note that a user generated public key should be in PEM format, the CERN public
key is in JWK format. Both formats are supported.

More than one public key can be specified by separating the URLs with `|`.
All keys will be kept in an internal key store. Keys in JWK format have already
a key identifier, for raw PEM keys a fingerprint will be calculated based on the
MD5 hash of the public key content.

### Basic Testing

Generate a key pair.

```bash
mkdir keys
chmod og-rwx keys
cd keys
openssl genrsa 2048 | tee private.key | openssl rsa -pubout > public.key
```
For basic tests, simply set these two variables and start the token
server:

```bash
export TDAQ_TOKEN_PATH=$(pwd)/token
export TDAQ_TOKEN_PUBLIC_KEY_URL=file:///path/to/keys/public.key
token_meister /path/to/keys/private.key $TDAQ_TOKEN_PATH &
```

See below under Deployment for a production setup.

### Command Line

Tokens can be acquired and verified via command line scripts.
To acquire a token call the `get_daq_token script`:

```bash
get_daq_token
```

This gets you a new token.

```bash
x=$(get_daq_token)
verify_daq_token ${x}
```

This verifies the token and prints it out.

```bash
get_daq_token | verify_daq_token
```

This receives the token from stdin, verifies and prints it.

```bash
get_daq_token > token.txt
verify_daq_token -f token.txt
```

This takes the token from an existing file.

### Python

Note that in practice an application may require only
one of acquire/verify.

```python
from daq_tokens import acquire, verify, FRESH, REUSE

token = acquire(FRESH)

result = verify(token)
print(result)
print("Originator = ", result["sub"])

# As long as the token is not expired, it will
# be returned:

token = acquire(REUSE)
token2 = acquire(REUSE)
assert(token == token2)
```

### C++

Note that an application may require only
one of acquire/verify.

For the moment the decoded result is returned as
a jwt::decoded_token from the jwt-cpp libary.

```
#include "daq_tokens/acquire.h"
#include "daq_tokens/verify.h"

#include <iostream>

int main()
{
   using daq::tokens::acquire, daq::tokens::verify, daq::tokens::Mode;

   std::string token = acquire(Mode::Fresh);

   auto result = verify(token);

   std::cout << "The originator is: " << result.get_subject() << std::endl;

   std::string token1 = acquire(Mode::Reuse);
   std::string token2 = acquire(Mode::Reuse);
   assert(token1 == token2);
}
```

### Java

The result of the verification is a `Map<String,Object>` which has
been created from the underlying JSON result of the payload.

```java

import java.util.Map;
import daq.tokens.JWToken;


class Test {

   public String getToken()
      throws daq.tokens.AcquireTokenException
   {
       String token = JWToken.acquire();
       return token;
   }

   public bool tokenIsOk(String token)
     throws daq.tokens.VerifyTokenException
   {
       Map<String, Object> result = JWToken.verify(token);
       System.out.println(result.get("aud"));
       System.out.println(result.get("exp"));
       System.out.println(result.get("sub"));
       return true;
   }
```

### Use by Distributed Applications

The use case for these tokens is any place in the current middleware where
a process retrieves the local identity of a user, then sends the user name
via CORBA to a server, who in turn uses the name to contact the
AccessManager for a check.

Instead of

```cpp Client.cxx
{
   ....
   const char *user = getlogin();

   corba_ptr->some_operation(..., user, ...);
}
```

use

```cpp Client.cxx
{
   ...
   std::string token = daq::token::acquire();
   corba_ptr->some_operation(..., token.c_str(), ...);
   ...
}
```

On the receiver side:

```cpp Server.cxx
Server::some_operation(..., const char *user, ....)
{
    ...
    accessManager->check(..., user, ...);
    ...
}
```

use

```cpp Server.cxx
Server::some_operation(..., const char *token, ...)
{
   ...
   std::string user;
   try {
     auto decoded = verify(token);
     user = decoded.get_sub();
   } catch(...) {
     // not verified
   }
   accessManager->check(..., user, ...);
}
```

This is vastly simplified for the case where one wants to quickly
secure an existing API. 

E.g. a tool like `rc_sender` or the `IGui` should acquire the token and send it to the
root controller. The root controller forwards the token to its
child controllers when propagating the commands, and all controllers
use the token when talking to the ProcessManager to start processes.
This way the `pmgserver` will get the token from the initiating user.

Similarly if the expert system initiates an action, it could get a
new token and use it for all commands during a given recovery.

Note than application should not cache the token since it will
expire at some point. Simple call `acquire()` again, any refreshing
will be done internally.

## Advanced configuration

The library supports to acquire a token by a variety of methods. The order
in which the methods are tried is specified by the TDAQ_TOKEN_ACUQIRE environment
variable. The possible methods are:

  * `local`    - Assumes a running token server with socket at `$TDAQ_TOKEN_PATH`.
  * `env`      - Get token from environment, see [WLCG Bearer Token](https://zenodo.org/record/3937438).
  * `kerberos` - Assumes a valid Kerberos ticket in the callers environment.
  * `browser`  - Assumes a graphical user session where a browser is available.
  * `gssapi`   - Get token via custom protocol using GSSAPI (requires Kerberos ticket)
  * `password` - Asks user interactively for a password. Avoid.

The built-in default is `local kerberos`. Only the `local` method is available
at Point 1. The others are merely there for convenience. E.g. a user can interact
with a running partition on the TDAQ testbed (which uses the `local` method) as
long as he can authenticate by any of the other methods.

You can try these by changing the environment of the `get_daq_token` command:

```bash
env TDAQ_TOKEN_ACQUIRE="local browser" get_daq_token
env TDAQ_TOKEN_ACQUIRE="password" get_daq_token
```

## Deployment

### RSA Keys

In a controlled environment, a new key pair should be generated:

```bash
openssl genrsa | tee private.key | openssl rsa -pubout > public.key
```

The public key can be distributed in any way you like:

  * Put it on a web server and point TDAQ_TOKEN_PUBLIC_KEY_URL to it.
  * Put it on a shared file system and point TDAQ_TOKEN_PUBLIC_KEY_URL to it.
  * Distribute it to each node on a local filesystem and point TDAQ_TOKEN_PUBLIC_KEY_URL to it.

The private key file should be synced to every node or be on a shared file system.

The private key should be **only readable by root or the special service account**, depending
under which user id the `token_meister` server is running.

### `token_meister` server

The `token_meister` server should run either as root or a special service user id and
should be the only one being able to read the private key file.

It should be started as a systemd service. It is independent of a specific TDAQ release
so only one running service is needed. The server can use systemd socket activation,
see `etc/systemd/system/tdaq_token.socket` and `etc/systemd/system/tdaq_token.service` for
an example

```shell
Type=simple
User=<service_account_name>
ExecStart=/sw/atlas/tdaq/tdaq/tdaq-09-03-00/installed/share/bin/run_tdaq token_meister /path/to/key/private.key
```

This will create the listening socket by default at `/run/tdaq_token`,
or `${XDG_RUNTIME_DIR}/tdaq_token` if run by hand by a non-root user.

Clients should set `TDAQ_TOKEN_PATH` to either `/run/tdaq_token` (if service
is run as root), or `/run/user/<service_acount_name>/tdaq_token`.

The path of the socket can be explicitly specified by adding it as a second 
command line argument.

```shell
token_meister /path/to/key/private.key /path/to/socket
```

## Updating Keys

Keys should be regularly changed, i.e. regenerated. The `token_meister` server
will check its key file and if it has changed, it will re-read the new key. So
no restart is necessary. 

The distribution and uptake of new keys cannot be guaranteed to be
synchronized, so it is best to do this when all partitions are stopped.

There is initial support for multiple keys for verification: both Python
and C++ implementations keep a key store using a fingerprint of the
key as index. The token_meister puts the fingerprint of the key it
uses into the JWT header. An unknown fingerprint encountered will lead
to a re-read of the public key URL.
