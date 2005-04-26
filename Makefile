# Makefile for source rpm: crypto-utils
# $Id: Makefile,v 1.1 2004/09/09 03:59:24 cvsdist Exp $
NAME := crypto-utils
SPECFILE = $(firstword $(wildcard *.spec))

include ../common/Makefile.common

certwatch: certwatch.c
	gcc -Wall -Werror -O2 -g $< -o $@ -lcrypto

test-certwatch: certwatch
	./certwatch
