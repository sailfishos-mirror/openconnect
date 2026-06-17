#!/bin/sh

v="v9.21"

if [ -d ${GIT_DIR:-.git} ] && tag=`git describe --tags`; then
	v="$tag"

	# Update the index from working tree first
	git update-index --refresh --unmerged > /dev/null

	# Does the index show uncommitted changes?
	git diff-index --exit-code HEAD > /dev/null || \
		v="$v"-dirty
elif [ -n "$RPM_PACKAGE_VERSION" ] && [ -n "$RPM_PACKAGE_RELEASE" ]; then
	v="v$RPM_PACKAGE_VERSION-$RPM_PACKAGE_RELEASE"
elif [ -r ${srcdir:-.}/.source-sha256sums ]; then
	# Verify source integrity against the checksums stored at release time.
	# If all files match, the tree is pristine and we can use the clean version.
	if (cd ${srcdir:-.} && sha256sum --quiet -c .source-sha256sums) > /dev/null 2>&1; then
		: # v is already set to the release version above
	else
		v="$v"-modified
	fi
else # XXX: Equivalent for .deb packages?
	v="$v"-unknown
fi

echo "const char openconnect_version_str[] = \"$v\";" > $1
echo "New version: $v"
