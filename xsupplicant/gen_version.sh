#!/bin/sh

if test -z "$SUP_VER"; then
    VERSION="svn-repo"
else
    VERSION="$SUP_VER"
fi

echo -n $VERSION
