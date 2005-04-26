# Makefile for source rpm: crypto-utils
# $Id$
NAME := crypto-utils
SPECFILE = $(firstword $(wildcard *.spec))

include ../common/Makefile.common

certwatch: certwatch.c
	gcc -Wall -Werror -O2 -g $< -o $@ -lcrypto

test-certwatch: certwatch
	./certwatch
