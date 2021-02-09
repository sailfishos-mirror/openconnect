#!/bin/sh
#
# Copyright 2013-2016 Nikos Mavrogiannopoulos
#
# This file is part of openconnect.
#
# This is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

#this test can only be run as root

if ! test -x /usr/sbin/ocserv;then
	echo "You need ocserv to run this test"
	exit 77
fi

if test "${DISABLE_ASAN_BROKEN_TESTS}" = 1 && test "${PRELOAD}" = 1;then
	echo "This test cannot be run under asan"
	exit 77
fi

OCSERV=/usr/sbin/ocserv
PPPD=/usr/sbin/pppd
test $(id -u) -eq 0 && SUDO= || SUDO=sudo

top_builddir=${top_builddir:-..}
SOCKDIR="./sockwrap.$$.tmp"
mkdir -p $SOCKDIR
export SOCKET_WRAPPER_DIR=$SOCKDIR
export SOCKET_WRAPPER_DEFAULT_IFACE=2
ADDRESS=127.0.0.$SOCKET_WRAPPER_DEFAULT_IFACE
OPENCONNECT="${OPENCONNECT:-${top_builddir}/openconnect}"${EXEEXT}
LOGFILE="$SOCKDIR/log.$$.tmp"

certdir="${srcdir}/certs"
confdir="${srcdir}/configs"

update_config() {
	file=$1
	username=$(whoami)
	group=$(groups|cut -f 1 -d ' ')
	cp "${srcdir}/configs/${file}" "$file.$$.tmp"
	sed -i -e 's|@USERNAME@|'${username}'|g' "$file.$$.tmp" \
	       -e 's|@GROUP@|'${group}'|g' "$file.$$.tmp" \
	       -e 's|@SRCDIR@|'${srcdir}'|g' "$file.$$.tmp" \
	       -e 's|@OTP_FILE@|'${OTP_FILE}'|g' "$file.$$.tmp" \
	       -e 's|@CRLNAME@|'${CRLNAME}'|g' "$file.$$.tmp" \
	       -e 's|@PORT@|'${PORT}'|g' "$file.$$.tmp" \
	       -e 's|@ADDRESS@|'${ADDRESS}'|g' "$file.$$.tmp" \
	       -e 's|@VPNNET@|'${VPNNET}'|g' "$file.$$.tmp" \
	       -e 's|@VPNNET6@|'${VPNNET6}'|g' "$file.$$.tmp" \
	       -e 's|@OCCTL_SOCKET@|'${OCCTL_SOCKET}'|g' "$file.$$.tmp" \
	       -e 's|@TLS_PRIORITIES@|'${TLS_PRIORITIES}'|g' "$file.$$.tmp"
	CONFIG="$file.$$.tmp"
}

launch_simple_sr_server() {
       LD_PRELOAD=libsocket_wrapper.so:libuid_wrapper.so UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $OCSERV $* &
}

launch_simple_pppd() {
       CERT="$1"
       KEY="$2"
       shift 2
       LD_PRELOAD=libsocket_wrapper.so socat \
		 PTY,rawer,b9600,link="$SOCKDIR/pppd.$$.pty" \
		 OPENSSL-LISTEN:443,verify=0,cert="$CERT",key="$KEY" 2>&1 &
       PID=$!

       sleep 3 # Wait for socat to create the PTY link

       # It would be preferable to invoke `pppd notty` directly using socat, but it seemingly cannot handle
       # being wrapped by libsocket_wrapper.so.
       # pppd's option parsing is notably brittle: it must have the actual PTY device node, not a symlink
       $SUDO $PPPD $(readlink "$SOCKDIR/pppd.$$.pty") noauth local debug nodetach nodefaultroute logfile "$LOGFILE" $* 2>&1 &
       PID="$PID $!"

       # XX: Caller needs to use PID, rather than $!
}

wait_server() {
	trap "kill $1" 1 15 2
	sleep 5
}

cleanup() {
	ret=0
	kill $PID 2>/dev/null
	if test $? != 0;then
		ret=1
	fi
	wait
	test -n "$SOCKDIR" && rm -rf $SOCKDIR && mkdir -p $SOCKDIR
	return $ret
}

fail() {
	PID="$1"
	shift;
	echo "Failure: $1" >&2
	kill $PID
	test -n "$SOCKDIR" && rm -rf $SOCKDIR
	exit 1
}

trap "fail \"Failed to launch the server, aborting test... \"" 10
