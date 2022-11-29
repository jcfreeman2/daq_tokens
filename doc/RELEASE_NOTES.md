# DAQ Tokens

The various Python based `token_meister` servers
have been replaced by a single C++ version.

The standard deployment for a local Unix domain socket:

```shell
token_meister /path/to/private.key [ /path/to/socket ]
```

The server using GSSAPI deployment requires
a Kerberos keytab with the `atdaqjwt` service.

```shell
cern-get-keytab --service atdaqjwt -o token.keytab
export KRB5_KTNAME=FILE:$(pwd)/token.keytab
token_meister --gssapi /path/to/private.key [ port ]
```

For interactively creating a token (for testing
and impersonating a user):

```shell
token_meister --make /path/to/private.key user
```
For internal timing test:

```shell
token_meister --time /path/to/private.key user
```

Additional options for all versions:

    --hash=<HASHNAME>

where `HASHNAME` is a valid OpenSSL name
for a hash function (e.g. 'SHA256'). To be
backward compatible with tdaq-09-04-00 use
`--hash=md5`.

The binary is statically linked against the stdc++
library and depends otherwise only on system libraries.
It can also be compiled independent from the TDAQ
software (see the [standalone](standalone/README.md) directory).
This means the binary can be just copied to a server
and run if all library dependencies are met.

The old Python based servers are still available.
They do not depend on any other TDAQ software which
can be useful in a system deployment.

They now live in their own `token_meister` package
and can be used like this:

```shell
python3 -m token_meister.local /path/to/key [ /path/to/socket ]
python3 -m token_meister.gssapi /path/to/key [ port ]
python3 -m token_meister.make /path/to/key user
```

### Command line interface to CERN SSO methods

```shell
python3 -m daq_tokens.cern_sso --client atlas-tdaq-token --krb5 -o save
token=$(jq .access_token < save)
```

When the access token is expired, refresh it:

```shell
python3 -m daq_tokens.cern_sso --client atlas-tdaq-token --refresh $(jq .refresh_token < save) -o save

python3 -m daq_tokens.cern_sso --client atlas-tdaq-token --browser -o save
python3 -m daq_tokens.cern_sso --client atlas-tdaq-token --password -o save
```
