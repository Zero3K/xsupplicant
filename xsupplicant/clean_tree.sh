#!/bin/bash
# Run autoreconf -vfis to use a cleaned tree. :)

FILES=`find . -iname "Makefile.in"`
FILES="$FILES aclocal.m4 config.guess config.sub configure depcomp install-sh missing mkinstalldirs"

rm  $FILES
echo $FILES | xargs cvs remove

