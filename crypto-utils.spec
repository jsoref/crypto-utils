# The maintainer of this package is Mark Cox <mjc@redhat.com>

Summary: Stronghold key management utilities
Name: crypto-utils
Version: 1.0
Release: 13
Source: crypto-utils.tar.gz
Source1: genkey-extra.pl
Source2: stronghold-config.pl
Group: Applications/System
License: Various
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildPreReq: openssl-devel, perl
Requires: perl, crypto-rand, newt-perl

%description
Provides tools and programs based on the OpenSSL
cryptographic library needed for Stronghold.

%prep
%setup -q -n crypto-utils

%build 
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

# Pick up any extra flags we might need to build code which is
# used in a shared library.
env CFLAGS="`perl -e 'print $Config{cccdlflags}'`" \
./configure --with-ssl=/usr

# build impkey
(cd impkey && make) || exit 1

%install
%{__mkdir_p} $RPM_BUILD_ROOT/usr/bin/

pushd impkey
make install INSTDIR="$RPM_BUILD_ROOT/usr/bin/"
popd

sed -e "s|^\$bindir.*$|\$bindir = \"/usr/bin\";|" \
    -e "s|^\$ssltop.*$|\$ssltop = \"/usr/share/ssl\";|" \
    -e "s|^\$sslconf.*$|\$sslconf = \"/usr/share/ssl/openssl.cnf\";|" \
    -e "1s|.*|\#\!/usr/bin/perl|g" \
    -e "s/^.*@EXTRA@.*$/finalMessage/g" \
    -e "s/'Challenge',/'Email','Challenge',/g" \
    -e "/@EXTRA@/d" \
    -e "\$r %{SOURCE1}" \
  < scripts/genkey-newt.pl > $RPM_BUILD_ROOT/usr/bin/genkey

scripts="getca getcert gencert change_pass decrypt_key checkcert genreq"

for s in $scripts; do 
   sed -e "s|^SSLTOP=.*$|SSLTOP=/usr/share/ssl|g" -e "s|%INSTDIR%|/usr|g" \
       -e "s|%SERVERROOT%|/usr/share|g" \
       -e "s|/usr/share/conf/ssl|/usr/share/ssl|g" \
       -e "s|lib/openssl.conf|openssl.cnf|g" \
       -e "s|/usr/share/ssl/openssl.conf|/usr/share/ssl/openssl.cnf|g" \
       -e "/PATH/d" \
      < scripts/$s > $RPM_BUILD_ROOT/usr/bin/$s
done

cp %{SOURCE2} $RPM_BUILD_ROOT/usr/bin/stronghold-config

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(0644,root,root,0755)
%attr(0755,root,root) /usr/bin/*

%changelog
* Tue Mar 18 2003 Joe Orton <jorton@redhat.com> 1.0-13
- hide passwords entered for private key

* Wed Sep 11 2002 Joe Orton <jorton@redhat.com> 1.0-12
- rebuild

* Thu Aug 22 2002 Joe Orton <jorton@redhat.com> 1.0-11
- fix location of OpenSSL configuration file in gencert

* Mon Jul 15 2002 Joe Orton <jorton@redhat.com> 1.0-10
- fix getca SERVERROOT, SSLTOP expansion (#68870)

* Mon May 13 2002 Joe Orton <jorton@redhat.com> 1.0-9
- improvements to genkey

* Mon May 13 2002 Joe Orton <jorton@redhat.com> 1.0-8
- add php.ini handling to stronghold-config 

* Mon May 13 2002 Joe Orton <jorton@redhat.com> 1.0-7
- restore stronghold-config

* Tue May 07 2002 Gary Benson <gbenson@redhat.com> 1.0-6
- remove stronghold-config

* Tue Apr 09 2002 Gary Benson <gbenson@redhat.com> 1.0-5
- change the group to match crypto-rand
- change Copyright to License

* Mon Mar 25 2002 Gary Benson <gbenson@redhat.com> 1.0-4
- hack to clean up some cruft that gets left in the docroot after we
  install.

* Fri Mar 22 2002 Gary Benson <gbenson@redhat.com>
- excise interchange.

* Wed Feb 13 2002 Gary Benson <gbenson@redhat.com> 1.0-3
- ask about interchange too.
- make /etc/sysconfig/httpd nicer.

* Thu May 17 2001 Joe Orton <jorton@redhat.com>
- Redone for Red Hat Linux.

* Mon Mar 20 2001 Mark Cox <mjc@redhat.com>
- Changes to make genkey a perl script

* Mon Dec 04 2000 Joe Orton <jorton@redhat.com>
- Put the stronghold/bin -> stronghold/ssl/bin symlink in the %files section
  rather than creating it in %post.

* Fri Nov 24 2000 Mark Cox <mjc@redhat.com>
- No need for .configure scripts, do the substitution ourselves

* Tue Nov 21 2000 Mark Cox <mjc@redhat.com>
- First version. Because this depends on a build environment
- We won't worry about ni-scripts for now, they're not used anyhow

