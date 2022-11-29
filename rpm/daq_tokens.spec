Name:           daq_tokens
Version:        v1.0.1
Release:        1%{?dist}
Summary:        TDAQ Token Server 

# Group:          
License:        Apache 2.0
# URL:            
Source:         https://gitlab.cern.ch/atlas-tdaq-software/daq_tokens/-/archive/%{version}/daq_tokens-%{version}.tar.bz2 
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

BuildRequires:  cmake3 openssl-devel krb5-devel devtoolset-11 devtoolset-11-gcc-c++ devtoolset-11-libstdc++-devel
Requires:       openssl-libs krb5-libs pcre

%description
The TDAQ token server.

Provides a JWT token on /run/daq_token for any local client.

%prep
%setup -q -n daq_tokens-%{version}

%build
%cmake
%cmake_build

%install
%cmake_install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
/usr/bin/token_meister
/etc/systemd/system/daq_token.socket
/etc/systemd/system/daq_token.service
/etc/systemd/system/daq_token_gssapi.socket
/etc/systemd/system/daq_token_gssapi.service

%changelog
