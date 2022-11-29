# Build a stand alone executable of `token_meister` server

On a recent system like CentOS 9:

```shell
git clone --recurse-submodules https://gitlab.cern.ch/atlas-tdaq-software/daq_tokens.git
mkdir build
cd build
cmake ../daq_tokens/standalone
make
```

## Compilers/CMake from LCG

We require at least g++ 8 and CMake 3.14. 

You just have to make sure they are in the PATH
and properly setup. 

E.g. using LCG tools from cvmfs:

```shell
export PATH=/cvmfs/sft.cern.ch/lcg/contrib/CMake/3.23.2/Linux-x86_64/bin:$PATH
. /cvmfs/sft.cern.ch/lcg/contrib/gcc/11/x86_64-centos7/setup.sh
mkdir build; cd build
cmake /path/to/daq_tokens/standalone
make
```

## Compilers/CMake from devtoolset

You can also install additional tools on CentOS 7:

```shell
sudo yum install -y \
    devtoolset-11-gcc-c++ 
    devtoolset-11-libstdc++-devel
sudo yum install -y epel-release
sudo yum install cmake3
scl enable devtoolset-11 bash
mkdir build; cd build
cmake3 /path/to/daq_tokens/standalone
make
```

The resulting executable is statically linked against
libstdc++ and libgcc, so at run time it does not
depend on the exact compiler version.

### System Installation

To install the binary and associated systemd files:

```shell
cmake -D CMAKE_INSTALL_PREFIX=/usr .
make
sudo make install
```

The systemd files will have to adjusted for the location
of the private key, and/or the Kerberos keytab file.

To generate the keys:

```shell
sudo openssl genrsa -out /etc/atdtoken/private.key
sudo openssl rsa -in /etc/atdtoken/private.key -pubout > /etc/atdtoken/public.key
```
To generate the keytab (if you want to use the GSSAPI server):

```shell
sudo cern-get-keytab --service atdaqjwt -o /etc/atdtoken/token.keytab
export KRB5_NTFILE=FILE:/etc/atdtoken/token.keytab
```

or put it into the default keytab file (/etc/krb5.keytab):

```shell
sudo cern-get-keytab --service atdaqjwt
```

### Services

```shell
sudo systemctl enable -now tdaq_token.socket
```

```shell
sudo systemctl enable --now tdaq_token_gssapi.socket
```
