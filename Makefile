# Makefile for source rpm: crypto-utils
# $Id$
NAME := crypto-utils
SPECFILE = $(firstword $(wildcard *.spec))

include ../common/Makefile.common
