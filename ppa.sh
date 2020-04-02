#!/bin/sh

PKGNAME=openconnect
PKGREV=1

SCRATCHDIR=$(mktemp -d /tmp/build-${PKGNAME}-XXXXXX)

COMMITDESC=$(git describe --tags | sed  -e 's/$/-0/' -e 's/v\([^-]\+-[^-]\+\)\(-g[0-9a-f-]\+\|\)/\1/')
COMMITDATE=$(git show -s --format=%cD)

if [ "$SCRATCHDIR" = "" ]; then
    exit 1
fi

git archive HEAD --prefix=${PKGNAME}/ > $SCRATCHDIR/${PKGNAME}.tar
cd $SCRATCHDIR
tar xvf ${PKGNAME}.tar
cd ${PKGNAME}
NOCONFIGURE=1 ./autogen.sh
ln -sf .deb debian
#for DISTRO in bionic ; do
#    sed -e "s/xenial;/${DISTRO};/" \
#	-e "s/%COMMITDESC%/${COMMITDE#SC}~${DISTRO}${PKGREV}/" \
#	-e "s/%COMMITDATE%/${COMMITDATE}/" \
#	debian/changelog.in > debian/changelog
 #   debuild
#    debuild -S -d
 #   echo dput openconnect  ../${PKGNAME}_${COMMITDESC}~${DISTRO}${PKGREV}_source.changes
#done
debuild
echo $SCRATCHDIR
#cd /tmp
#rm -r $SCRATCHDIR
