/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <config.h>

#include "openconnect-internal.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <arpa/inet.h>
#if defined(__APPLE__) && defined(HAVE_NET_UTUN_H)
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#endif
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * If an if_tun.h include file was found anywhere (by the Makefile), it's
 * included. Else, we end up assuming that we have BSD-style devices such
 * as /dev/tun0 etc.
 */
#ifdef IF_TUN_HDR
#include IF_TUN_HDR
#endif

/*
 * The OS X tun/tap driver doesn't provide a header file; you're expected
 * to define this for yourself.
 */
#ifdef __APPLE__
#define TUNSIFHEAD  _IOW('t', 96, int)
#endif

/*
 * OpenBSD always puts the protocol family prefix onto packets. Other
 * systems let us enable that with the TUNSIFHEAD ioctl, and some of them
 * (e.g. FreeBSD) _need_ it otherwise they'll interpret IPv6 packets as IPv4.
 */
#if defined(__OpenBSD__) || defined(TUNSIFHEAD)
#define TUN_HAS_AF_PREFIX 1
#endif

#ifdef __sun__
#include <stropts.h>
#include <sys/sockio.h>

#ifndef TUNNEWPPA
#error "Install TAP driver from http://www.whiteboard.ne.jp/~admin2/tuntap/"
#endif

static int link_proto(struct openconnect_info *vpninfo, int unit_nr,
		      const char *devname, uint64_t flags)
{
	int ip_fd, mux_id, tun2_fd;
	struct lifreq ifr;

	tun2_fd = open("/dev/tun", O_RDWR);
	if (tun2_fd < 0) {
		vpn_perror(vpninfo, _("Could not open /dev/tun for plumbing"));
		return -EIO;
	}
	if (ioctl(tun2_fd, I_PUSH, "ip") < 0) {
		vpn_perror(vpninfo, _("Can't push IP"));
		close(tun2_fd);
		return -EIO;
	}

	sprintf(ifr.lifr_name, "tun%d", unit_nr);
	ifr.lifr_ppa = unit_nr;
	ifr.lifr_flags = flags;

	if (ioctl(tun2_fd, SIOCSLIFNAME, &ifr) < 0) {
		vpn_perror(vpninfo, _("Can't set ifname"));
		close(tun2_fd);
		return -1;
	}

	ip_fd = open(devname, O_RDWR);
	if (ip_fd < 0) {
		vpn_progress(vpninfo, PRG_ERR, _("Can't open %s: %s\n"),
			     devname, strerror(errno));
		close(tun2_fd);
		return -1;
	}

	mux_id = ioctl(ip_fd, I_LINK, tun2_fd);
	if (mux_id < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Can't plumb %s for IPv%d: %s\n"),
			     ifr.lifr_name, (flags == IFF_IPV4) ? 4 : 6,
			     strerror(errno));
		close(tun2_fd);
		close(ip_fd);
		return -1;
	}

	close(tun2_fd);

	return ip_fd;
}

intptr_t os_setup_tun(struct openconnect_info *vpninfo)
{
	int tun_fd = -1;
	static char tun_name[80];
	int unit_nr;

	tun_fd = open("/dev/tun", O_RDWR);
	if (tun_fd < 0) {
		vpn_perror(vpninfo, _("open /dev/tun"));
		return -EIO;
	}

	unit_nr = ioctl(tun_fd, TUNNEWPPA, -1);
	if (unit_nr < 0) {
		vpn_perror(vpninfo, _("Failed to create new tun"));
		close(tun_fd);
		return -EIO;
	}

	if (ioctl(tun_fd, I_SRDOPT, RMSGD) < 0) {
		vpn_perror(vpninfo, _("Failed to put tun file descriptor into message-discard mode"));
		close(tun_fd);
		return -EIO;
	}

	sprintf(tun_name, "tun%d", unit_nr);
	vpninfo->ifname = strdup(tun_name);

	vpninfo->ip_fd = link_proto(vpninfo, unit_nr, "/dev/udp", IFF_IPV4);
	if (vpninfo->ip_fd < 0) {
		close(tun_fd);
		return -EIO;
	}

	if (vpninfo->ip_info.addr6 || vpninfo->ip_info.netmask6) {
		vpninfo->ip6_fd = link_proto(vpninfo, unit_nr, "/dev/udp6", IFF_IPV6);
		if (vpninfo->ip6_fd < 0) {
			close(tun_fd);
			close(vpninfo->ip_fd);
			vpninfo->ip_fd = -1;
			return -EIO;
		}
	} else
		vpninfo->ip6_fd = -1;

	return tun_fd;
}
#elif defined(__native_client__)

intptr_t os_setup_tun(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR,
		     _("tun device is unsupported on this platform\n"));
	return -EOPNOTSUPP;
}

#else /* !__sun__ && !__native_client__ */

static int ifreq_set_ifname(struct openconnect_info *vpninfo, struct ifreq *ifr,
			    char *ifname_utf8)
{
	char *ifname = openconnect_utf8_to_legacy(vpninfo, ifname_utf8);
	int ret = 0;

	if (strlen(ifname) >= sizeof(ifr->ifr_name)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Requested tun device name '%s' is too long\n"),
			     vpninfo->ifname);
		ret = -ENAMETOOLONG;
	} else {
		memcpy(ifr->ifr_name, ifname, strlen(ifname));
	}

	if (ifname != ifname_utf8)
		free(ifname);

	return ret;
}


#ifdef IFF_TUN /* Linux */
intptr_t os_setup_tun(struct openconnect_info *vpninfo)
{
	int tun_fd = -1;
	struct ifreq ifr;
	int tunerr;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (vpninfo->ifname && ifreq_set_ifname(vpninfo, &ifr, vpninfo->ifname))
		return -EINVAL;

	tun_fd = open("/dev/net/tun", O_RDWR);
	if (tun_fd < 0) {
		/* Android has /dev/tun instead of /dev/net/tun
		   Since other systems might have too, just try it
		   as a fallback instead of using ifdef __ANDROID__ */
		tunerr = errno;
		tun_fd = open("/dev/tun", O_RDWR);
	}
	if (tun_fd < 0) {
		/* If the error on /dev/tun is ENOENT, that's boring.
		   Use the error we got on /dev/net/tun instead */
		if (errno != ENOENT)
			tunerr = errno;

		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open tun device: %s\n"),
			     strerror(tunerr));
		return -EIO;
	}

	if (ioctl(tun_fd, TUNSETIFF, (void *) &ifr) < 0) {
		int err = errno;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to bind local tun device (TUNSETIFF): %s\n"),
			     strerror(err));
		if (err == EPERM) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("To configure local networking, openconnect must be running as root\n"
				       "See %s for more information\n"),
				     "https://www.infradead.org/openconnect/nonroot.html");
		}
		close(tun_fd);
		return -EIO;
	}
	if (!vpninfo->ifname)
		vpninfo->ifname = strdup(ifr.ifr_name);

	return tun_fd;
}
#else /* BSD et al, including OS X */

#ifdef SIOCIFCREATE
static int bsd_open_tun(struct openconnect_info *vpninfo, char *tun_name)
{
	int fd;
	int s;
	struct ifreq ifr;

	fd = open(tun_name, O_RDWR);
	if (fd == -1) {
		memset(&ifr, 0, sizeof(ifr));
		if (ifreq_set_ifname(vpninfo, &ifr, tun_name))
			return -1;

		s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s < 0)
			return -1;

		if (!ioctl(s, SIOCIFCREATE, &ifr))
			fd = open(tun_name, O_RDWR);

		close(s);
	}
	return fd;
}
#else
#define bsd_open_tun(vpninfo, tun_name) open(tun_name, O_RDWR)
#endif

intptr_t os_setup_tun(struct openconnect_info *vpninfo)
{
	static char tun_name[80];
	int unit_nr = 0;
	int tun_fd = -1;

#if defined(__APPLE__) && defined (HAVE_NET_UTUN_H)
	/* OS X (since 10.6) can do this as well as the traditional
	   BSD devices supported via tuntaposx. */
	struct sockaddr_ctl sc;
	struct ctl_info ci;

	if (vpninfo->ifname) {
		char *endp = NULL;

		if (!strncmp(vpninfo->ifname, "tun", 3))
			goto do_bsdtun;

		if (strncmp(vpninfo->ifname, "utun", 4) ||
		    (unit_nr = strtol(vpninfo->ifname + 4, &endp, 10), !endp) ||
		    (unit_nr && vpninfo->ifname[4] == '0') ||
		    *endp) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Invalid interface name '%s'; must match 'utun%%d' or 'tun%%d'\n"),
				     vpninfo->ifname);
			return -EINVAL;
		}
	}

	tun_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (tun_fd < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open SYSPROTO_CONTROL socket: %s\n"),
			     strerror(errno));
		goto utun_fail;
	}

	snprintf(ci.ctl_name, sizeof(ci.ctl_name), UTUN_CONTROL_NAME);

	if (ioctl(tun_fd, CTLIOCGINFO, &ci) == -1) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to query utun control id: %s\n"),
			       strerror(errno));
		close(tun_fd);
		goto utun_fail;
	}

	sc.sc_id = ci.ctl_id;
	sc.sc_len = sizeof(sc);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = AF_SYS_CONTROL;

	do {
		sc.sc_unit = unit_nr + 1;

		if (!connect(tun_fd, (struct sockaddr *)&sc, sizeof(sc))) {
			if (!vpninfo->ifname &&
			    asprintf(&vpninfo->ifname, "utun%d", unit_nr) == -1) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to allocate utun device name\n"));
				close(tun_fd);
				goto utun_fail;
			}
			return tun_fd;
		}
		unit_nr++;

	} while (sc.sc_unit < 255 && !vpninfo->ifname);

	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to connect utun unit: %s\n"),
		     strerror(errno));
	close(tun_fd);

 utun_fail:
	/* If we were explicitly asked for a utun device, fail. Else try tuntaposx */
	if (vpninfo->ifname)
		return -EIO;

	tun_fd = -1;
 do_bsdtun:
#endif /* __APPLE__ && HAVE_NET_UTUN_H */

	if (vpninfo->ifname) {
		char *endp = NULL;
		if (strncmp(vpninfo->ifname, "tun", 3) ||
		    ((void)strtol(vpninfo->ifname + 3, &endp, 10), !endp) ||
		    *endp) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Invalid interface name '%s'; must match 'tun%%d'\n"),
				     vpninfo->ifname);
			return -EINVAL;
		}
		snprintf(tun_name, sizeof(tun_name),
			 "/dev/%s", vpninfo->ifname);
		tun_fd = bsd_open_tun(vpninfo, tun_name);
		if (tun_fd < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Cannot open '%s': %s\n"),
				     tun_name, strerror(errno));
			return -EINVAL;
		}
	}
#ifdef HAVE_FDEVNAME_R
	/* We don't have to iterate over the possible devices; on FreeBSD
	   at least, opening /dev/tun will give us the next available
	   device. */
	if (tun_fd < 0) {
		tun_fd = open("/dev/tun", O_RDWR);
		if (tun_fd >= 0) {
			if (!fdevname_r(tun_fd, tun_name, sizeof(tun_name)) ||
			    strncmp(tun_name, "tun", 3)) {
				close(tun_fd);
				tun_fd = -1;
			} else
				vpninfo->ifname = strdup(tun_name);
		}
	}
#endif
	if (tun_fd < 0) {
		for (unit_nr = 0; unit_nr < 255; unit_nr++) {
			sprintf(tun_name, "/dev/tun%d", unit_nr);
			tun_fd = bsd_open_tun(vpninfo, tun_name);
			if (tun_fd >= 0)
				break;
		}
		if (tun_fd < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to open tun device: %s\n"),
				     strerror(errno));
			return -EIO;
		}
		vpninfo->ifname = strdup(tun_name + 5);
	}
#ifdef TUNSIFHEAD
	unit_nr = 1;
	if (ioctl(tun_fd, TUNSIFHEAD, &unit_nr) < 0) {
		vpn_perror(vpninfo, _("TUNSIFHEAD"));
		close(tun_fd);
		return -EIO;
	}
#endif

	return tun_fd;
}
#endif /* !IFF_TUN (i.e. BSD) */
#endif /* !__sun__ */

int openconnect_setup_tun_fd(struct openconnect_info *vpninfo, int tun_fd)
{
	set_fd_cloexec(tun_fd);

	if (vpninfo->tun_fd != -1)
		unmonitor_fd(vpninfo, tun);

	vpninfo->tun_fd = tun_fd;

	if (set_sock_nonblock(tun_fd)) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to make tun socket nonblocking: %s\n"),
			     strerror(errno));
		return -EIO;
	}

#ifdef HAVE_VHOST
	if (!setup_vhost(vpninfo, tun_fd))
		return 0;
#endif

	monitor_fd_new(vpninfo, tun);
	monitor_read_fd(vpninfo, tun);

	return 0;
}

int openconnect_setup_tun_script(struct openconnect_info *vpninfo,
				 const char *tun_script)
{
	pid_t pid;
	int fds[2];

	STRDUP(vpninfo->vpnc_script, tun_script);
	vpninfo->script_tun = 1;

	prepare_script_env(vpninfo);
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds)) {
		vpn_progress(vpninfo, PRG_ERR, _("socketpair failed: %s\n"), strerror(errno));
		return -EIO;
	}
	pid = fork();
	if (pid < 0) {
		vpn_progress(vpninfo, PRG_ERR, _("fork failed: %s\n"), strerror(errno));
		return -EIO;
	} else if (pid == 0) {
		/* Child */
		if (setpgid(0, 0) < 0)
			perror(_("setpgid"));
		close(fds[0]);
		script_setenv_int(vpninfo, "VPNFD", fds[1]);
		apply_script_env(vpninfo->script_env);
		execl("/bin/sh", "/bin/sh", "-c", vpninfo->vpnc_script, NULL);
		perror(_("execl"));
		exit(1);
	}
	close(fds[1]);
	vpninfo->script_tun = pid;
	vpninfo->ifname = strdup(_("(script)"));

	return openconnect_setup_tun_fd(vpninfo, fds[0]);
}

int os_read_tun(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	int prefix_size = 0;
	int len;

#ifdef TUN_HAS_AF_PREFIX
	if (!vpninfo->script_tun)
		prefix_size = sizeof(int);
#endif

	/* Sanity. Just non-blocking reads on a select()able file descriptor... */
	len = read(vpninfo->tun_fd, pkt->data - prefix_size, pkt->len + prefix_size);
	if (len <= prefix_size)
		return -1;

	pkt->len = len - prefix_size;
	return 0;
}

int os_write_tun(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	unsigned char *data = pkt->data;
	int len = pkt->len;

#ifdef TUN_HAS_AF_PREFIX
	if (!vpninfo->script_tun) {
		struct ip *iph = (void *)data;
		int type;

		if (iph->ip_v == 6)
			type = AF_INET6;
		else if (iph->ip_v == 4)
			type = AF_INET;
		else {
			static int complained; /* static variable initialised to 0 */
			if (!complained) {
				complained = 1;
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unknown packet (len %d) received: %02x %02x %02x %02x...\n"),
					     len, data[0], data[1], data[2], data[3]);
			}
			return 0;
		}
		data -= sizeof(int);
		len += sizeof(int);
		*(int *)data = htonl(type);
	}
#endif
	if (write(vpninfo->tun_fd, data, len) < 0) {
		/* Handle death of "script" socket */
		if (vpninfo->script_tun && errno == ENOTCONN) {
			vpninfo->quit_reason = "Client connection terminated";
			return -1;
		}
		/* The tun device in the Linux kernel returns -ENOMEM when
		 * the queue is full, so theoretically we could check for
		 * that and retry too.  But it doesn't let us poll() for
		 * the no-longer-full situation, so let's not bother. */
		if (errno == ENOBUFS || errno == EAGAIN || errno == EWOULDBLOCK) {
			monitor_write_fd(vpninfo, tun);
			return -1;
		}
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to write incoming packet: %s\n"),
			     strerror(errno));
	}
	return 0;

}

void os_shutdown_tun(struct openconnect_info *vpninfo)
{
	if (vpninfo->script_tun) {
		/* nuke the whole process group */
		kill(-vpninfo->script_tun, SIGHUP);
	} else {
		script_config_tun(vpninfo, "disconnect");
#ifdef __sun__
		close(vpninfo->ip_fd);
		vpninfo->ip_fd = -1;
		if (vpninfo->ip6_fd != -1) {
			close(vpninfo->ip6_fd);
			vpninfo->ip6_fd = -1;
		}
#endif
	}

#ifdef HAVE_VHOST
	shutdown_vhost(vpninfo);
#endif

	if (vpninfo->vpnc_script)
		close(vpninfo->tun_fd);
	vpninfo->tun_fd = -1;
}
