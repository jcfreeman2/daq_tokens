
# RPM Generation

## Prerequesites

```shell
yum install rpmdevtools rpmbuild
rpmdev-setuptree
pushd ~/rpmbuild/SOURCES
version=v1.0.1
wget https://gitlab.cern.ch/atlas-tdaq-software/daq_tokens/-/archive/${version}/daq_tokens-${version}.tar.bz2
popd
```

## Building

```shell
rpmbuild -ba daq_tokens.spec
```

