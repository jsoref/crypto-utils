
%define crver 1.0

Summary: SSL certificate and key management utilities
Name: crypto-utils
Version: 2.1
Release: 3
Source: crypto-rand-%{crver}.tar.gz
Source1: genkey.pl
Source2: certwatch.c
Source3: certwatch.cron
Source4: certwatch.xml
Group: Applications/System
License: Various
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildRequires: openssl-devel, perl, pkgconfig, newt-devel, xmlto
Requires: newt-perl, openssl
Requires: %(eval `perl -V:version`; echo "perl(:MODULE_COMPAT_$version)")
Obsoletes: crypto-rand

%description
This package provides tools for managing and generating
SSL certificates and keys.

%prep
%setup -q -n crypto-rand-%{crver}

%build 
%configure --with-newt=%{_prefix} CFLAGS="-fPIC $RPM_OPT_FLAGS"
make

cc $RPM_OPT_FLAGS -Wall -Werror -I/usr/include/openssl -o certwatch \
   $RPM_SOURCE_DIR/certwatch.c -lcrypto
xmlto man $RPM_SOURCE_DIR/certwatch.xml

pushd Makerand
perl -pi -e "s/Stronghold/Crypt/g" *
CFLAGS="$RPM_OPT_FLAGS" perl Makefile.PL PREFIX=$RPM_BUILD_ROOT/usr INSTALLDIRS=vendor
make
popd

%install
rm -rf $RPM_BUILD_ROOT

pushd Makerand
make install
popd

# fix Newt.so perms
find $RPM_BUILD_ROOT/usr -name Makerand.so | xargs chmod 755

[ -x /usr/lib/rpm/brp-compress ] && /usr/lib/rpm/brp-compress

find $RPM_BUILD_ROOT \( -name perllocal.pod -o -name .packlist \) -exec rm -v {} \;

find $RPM_BUILD_ROOT/usr -type f -print | 
	sed "s@^$RPM_BUILD_ROOT@@g" | 
	grep -v perllocal.pod | 
	grep -v "\.packlist" > filelist
if [ ! -s filelist ] ; then
    echo "ERROR: EMPTY FILE LIST"
    exit 1
fi

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/cron.daily \
         $RPM_BUILD_ROOT%{_mandir}/man1 \
         $RPM_BUILD_ROOT%{_bindir}

# install keyrand
install -c -m 755 keyrand/keyrand $RPM_BUILD_ROOT%{_bindir}/keyrand

# install certwatch
install -c -m 755 certwatch $RPM_BUILD_ROOT%{_bindir}/certwatch
install -c -m 755 $RPM_SOURCE_DIR/certwatch.cron \
   $RPM_BUILD_ROOT%{_sysconfdir}/cron.daily/certwatch
install -c -m 644 certwatch.1 \
   $RPM_BUILD_ROOT%{_mandir}/man1/certwatch.1

# install genkey
sed -e "s|^\$bindir.*$|\$bindir = \"/usr/bin\";|" \
    -e "s|^\$ssltop.*$|\$ssltop = \"/usr/share/ssl\";|" \
    -e "s|^\$sslconf.*$|\$sslconf = \"/usr/share/ssl/openssl.cnf\";|" \
    -e "1s|.*|\#\!/usr/bin/perl|g" \
    -e "s/'Challenge',/'Email','Challenge',/g" \
    -e "/@EXTRA@/d" \
  < $RPM_SOURCE_DIR/genkey.pl > $RPM_BUILD_ROOT%{_bindir}/genkey

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files -f filelist
%defattr(0644,root,root,0755)
%attr(0755,root,root) %{_bindir}/*
%{_sysconfdir}/cron.daily/certwatch
%{_mandir}/man1/certwatch.1*

%changelog
* Wed Oct 13 2004 Joe Orton <jorton@redhat.com> 2.1-3
- send warnings To: root rather than root@localhost (#135533)

* Wed Oct  6 2004 Joe Orton <jorton@redhat.com> 2.1-2
- add BuildRequire newt-devel, xmlto (#134695)

* Fri Sep 10 2004 Joe Orton <jorton@redhat.com> 2.1-1
- add /usr/bin/certwatch
- support --days argument to genkey (#131045)

* Tue Aug 17 2004 Joe Orton <jorton@redhat.com> 2.0-6
- add perl MODULE_COMPAT requirement

* Mon Aug 16 2004 Joe Orton <jorton@redhat.com> 2.0-5
- rebuild

* Mon Sep 15 2003 Joe Orton <jorton@redhat.com> 2.0-4
- hide private key passwords during entry
- fix CSR generation

* Mon Sep  1 2003 Joe Orton <jorton@redhat.com> 2.0-3
- fix warnings when in UTF-8 locale

* Tue Aug 26 2003 Joe Orton <jorton@redhat.com> 2.0-2
- allow upgrade from Stronghold 4.0

* Mon Aug  4 2003 Joe Orton <jorton@redhat.com> 2.0-1
- update for RHEL

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

