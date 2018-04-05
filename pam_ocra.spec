Name:           pam_ocra
Version:        1.5alpha1
Release:        1%{?dist}
Summary:        A Pluggable Authentication Module for RFC6287 OCRA

Group:          System Environment/Base
License:        BSD
URL:            https://github.com/sg2342/pam_ocra
Source0:        https://github.com/sg2342/pam_ocra/archive/%{version}/%{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  pam-devel gcc make libdb-devel openssl-devel

%description
This is pam_ocra, a pluggable authentication module that can be used with
Linux-PAM and RFC6287 OCRA (OATH Challenge-Response Algorithm) tokens.

%prep
%setup -q

%build
make

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT libdir=%{_lib}/security bindir=%{_bindir} mandir=%{_mandir} install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE README.md
/%{_lib}/security/pam_ocra.so
%{_bindir}/ocra_tool
%{_mandir}/man8/pam_ocra.8.gz
%{_mandir}/man8/ocra_tool.8.gz

%changelog
* Thu Apr 5 2018 Stefan Grundmann <sg2342@googlemail.com> - 1.5-1
- initial packaging
