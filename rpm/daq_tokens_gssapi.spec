Name:           daq_tokens_gssapi
Version:        v1.0.2
Release:        1%{?dist}
Summary:        TDAQ Token Server using GSSAPI

# Group:          
License:        Apache 2.0
# URL:            
Source:         https://gitlab.cern.ch/atlas-tdaq-software/daq_tokens/-/archive/%{version}/daq_tokens-%{version}.tar.bz2 
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

Requires:      python36 python3-jwt python3-gssapi

%description
The TDAQ token server.

Provides a JWT token via kerberos authentication.

%prep
%setup -q -n daq_tokens-%{version}
%build
%install

rm -rf %{buildroot}
install -d %{buildroot}/%{_bindir} %{buildroot}/%{_sysconfdir}/systemd/system
install bin/token_meister_gssapi %{buildroot}/%{_bindir}
install -m 644 etc/systemd/system/tdaq_token_gssapi.socket %{buildroot}/%{_sysconfdir}/systemd/system
install -m 644 etc/systemd/system/tdaq_token_gssapi.service %{buildroot}/%{_sysconfdir}/systemd/system

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
/usr/bin/token_meister_gssapi
/etc/systemd/system/tdaq_token_gssapi.socket
/etc/systemd/system/tdaq_token_gssapi.service

%changelog
