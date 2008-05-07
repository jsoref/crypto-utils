# Makefile for source rpm: crypto-utils
# $Id$
NAME := crypto-utils
SPECFILE = $(firstword $(wildcard *.spec))

define find-makefile-common
for d in common ../common ../../common ; do if [ -f $$d/Makefile.common ] ; then if [ -f $$d/CVS/Root -a -w $$/Makefile.common ] ; then cd $$d ; cvs -Q update ; fi ; echo "$$d/Makefile.common" ; break ; fi ; done
endef

MAKEFILE_COMMON := $(shell $(find-makefile-common))

ifeq ($(MAKEFILE_COMMON),)
# attempt a checkout
define checkout-makefile-common
test -f CVS/Root && { cvs -Q -d $$(cat CVS/Root) checkout common && echo "common/Makefile.common" ; } || { echo "ERROR: I can't figure out how to checkout the 'common' module." ; exit -1 ; } >&2
endef

MAKEFILE_COMMON := $(shell $(checkout-makefile-common))
endif

include $(MAKEFILE_COMMON)

certwatch: certwatch.c pemutil.c
	gcc -Wall -Werror -O2 -g $^ -o $@  \
		-lnspr4 -lnss3 -I/usr/include/nspr4 -I/usr/include/nss3

test-certwatch: certwatch
	./certwatch

keyutil: keyutil.c keyutil.h certext.c secutil.c secutil.h secerror.c
	gcc -Wall -Werror -O2 -g $^ -o $@ \
		-lnspr4 -lnss3 -I/usr/include/nspr4 -I/usr/include/nss3
	chmod 755 $@

genkey: genkey.pl keyutil Makefile
	sed -e "s|^\$$bindir.*$$|\$$bindir = \"/usr/bin\";|" \
	    -e "s|^\$$ssltop.*$$|\$$ssltop = \"$(PWD)\";|" \
	    -e "s|^\$$sslconf.*$$|\$$sslconf = \"/etc/pki/tls/openssl.cnf\";|" \
	    -e "s|^\$$cadir.*$$|\$$cadir = \"/etc/pki/CA\";|" \
	    -e "1s|.*|\#\!/usr/bin/perl|	g" \
	    -e "s/'Challenge',/'Email','Challenge',/g" \
	    -e "/@EXTRA@/d" < $< > $@
	chmod 755 $@

test-genkey: genkey
	mkdir -p certs private
	./genkey --test `hostname`

#########################################################################
# Individual testing targets.
#########################################################################

test-genreq-modssl: genkey
	perl ./genkey --genreq test.`hostname`
			
test-makecert-modssl: genkey
	perl ./genkey --makeca test.`hostname`

test-genreq-modnss: genkey
	perl ./genkey --genreq -nss test.`hostname`

test-makecert-modnss: genkey
	perl ./genkey --makeca -nss test.`hostname`

prepare-tests:
	mkdir -p certs private

cleanup-tests: certs private
	rm -f -r certs private

#########################################################################
	
date.xml:
	date +"%e %B %Y" | tr -d '\n' > $@

version.xml:
	echo -n ${VERSION} > $@

man-genkey: genkey.xml date.xml version.xml
	xmlto man genkey.xml
	man ./genkey.1

man-keyrand: keyrand.xml date.xml version.xml
	xmlto man keyrand.xml
	man ./keyrand.1

man-certwatch: certwatch.xml date.xml version.xml
	xmlto man certwatch.xml
	man ./certwatch.1


