#!/bin/sh

config_h="$1"
version_h="$2"
version_nsi="$3"

v="v8.10"

if [ -d ${GIT_DIR:-.git} ] && tag=`git describe --tags`; then
	v="$tag"

	# Update the index from working tree first
	git update-index --refresh --unmerged > /dev/null

	# Does the index show uncommitted changes?
	git diff-index --exit-code HEAD > /dev/null || \
		v="$v"-dirty
elif [ -n "$RPM_PACKAGE_VERSION" ] && [ -n "$RPM_PACKAGE_RELEASE" ]; then
	v="v$RPM_PACKAGE_VERSION-$RPM_PACKAGE_RELEASE"
else # XXX: Equivalent for .deb packages?
	v="$v"-unknown
fi

# Windows "product version" has to be a a.b.c.d (numeric)
windows_quad_version=$(echo "$v" | perl -ne 'm|v(\d+)\.(\d+)(?:\.git\.\|\-)?(\d+)?(?:-g.+\|.*)|; print "$1.$2." . ($3 or "0") . ".0"');

# TLS library name
if test ! -e $config_h; then
    exit 1
elif egrep -q '^#define OPENCONNECT_GNUTLS' $config_h; then
    TLS_LIBRARY=GnuTLS
elif egrep -q '^#define OPENCONNECT_OPENSSL' $config_h; then
    TLS_LIBRARY=OpenSSL
else
    TLS_LIBRARY="Unknown TLS library"
fi

cat <<EOF > $version_h
#define OPENCONNECT_VERSION_STR "$v";
#define OPENCONNECT_WINDOWS_QUAD_VERSION "$windows_quad_version";
#define OPENCONNECT_TLS_LIBRARY "$TLS_LIBRARY";
EOF

sed 's|\#define|!define|; s|;\s*$||;' < $version_h > $version_nsi

echo "New version: $v"
echo "Windows dotted-quad version: $windows_quad_version"
