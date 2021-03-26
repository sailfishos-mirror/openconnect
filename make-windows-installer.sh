#!/bin/bash
#
# Copyright (C) 2021 Daniel Lenski
#
# This builds a Windows installer for OpenConnect using the Fedora nsiswrapper
# program from https://fedoraproject.org/wiki/MinGW, which in turn depends on
# NSIS (https://nsis.sourceforge.io).
#
# This script should be run *after* successfully cross-building openconnect.exe
# and libopenconnect-5.dll.

set -e

SYSROOT=/usr/i686-w64-mingw32/sys-root

# only X.Y.Z.W is allowed for the installer's "product version" property
VERSION=$(cut -f2 -d\" version.c)
PROD_VERSION=$(echo "$VERSION" | perl -ne 'm|v(\d+)\.(\d+)(?:\-(\d+)-g.+)|; print "$1.$2." . ($3 or "0") . ".0"')

if egrep -q '^#define OPENCONNECT_GNUTLS' config.h; then
    TLS_LIBRARY=GnuTLS
elif egrep -q '^#define OPENCONNECT_OPENSSL' config.h; then
    TLS_LIBRARY=OpenSSL
else
    TLS_LIBRARY="Unknown TLS library"
fi

mkdir nsis
cd nsis

# build HTML documentation
make -C ../www update
ln -s ../public docs

# download latest vpnc-script-win.js
curl "https://gitlab.com/openconnect/vpnc-scripts/raw/master/vpnc-script-win.js" > vpnc-script-win.js

# add symlinks to OpenConnect .exe/.dll, and all DLLs installed by package manager
# (so that nsiswrapper can find them)
ln -s ../.libs/openconnect.exe ../.libs/libopenconnect-5.dll $SYSROOT/mingw/{bin,lib}/*.dll .

# build openconnect.nsi (input to makensis)
PATH="$PATH:." nsiswrapper --name OpenConnect --outfile openconnect-installer.exe \
    openconnect.exe docs vpnc-script-win.js > openconnect.nsi.in

# add version information
cat <<EOF > openconnect.nsi
SetCompressor /FINAL lzma
VIAddVersionKey ProductName "OpenConnect"
VIProductVersion "$PROD_VERSION"
VIAddVersionKey ProductVersion "$VERSION"
VIAddVersionKey Comments "OpenConnect multi-protocol VPN client for Windows (command-line version, built with $TLS_LIBRARY). For more information, visit https://openconnect.gitlab.io/openconnect"
EOF

# build installer
cat openconnect.nsi.in >> openconnect.nsi
makensis openconnect.nsi
