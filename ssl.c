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
#include <inttypes.h>
#include <fcntl.h>
#if defined(__linux__) || defined(__ANDROID__)
#include <sys/vfs.h>
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__OpenBSD__) || defined(__APPLE__)
#include <sys/param.h>
#include <sys/mount.h>
#elif defined(__sun__) || defined(__NetBSD__) || defined(__DragonFly__)
#include <sys/statvfs.h>
#elif defined(__GNU__)
#include <sys/statfs.h>
#endif

/* setsockopt and TCP_NODELAY */
#ifndef _WIN32
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

#ifdef ANDROID_KEYSTORE
#include <sys/un.h>
#endif

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

/* OSX < 1.6 doesn't have AI_NUMERICSERV */
#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif

/* GNU Hurd doesn't yet declare IPV6_TCLASS */
#ifndef IPV6_TCLASS
#if defined(__GNU__)
#define IPV6_TCLASS 61
#elif defined(__APPLE__)
#define IPV6_TCLASS 36
#endif
#endif

static inline int connect_pending(void)
{
#ifdef _WIN32
	return WSAGetLastError() == WSAEWOULDBLOCK;
#else
	return errno == EINPROGRESS;
#endif
}

/* Windows is interminably horrid, and has disjoint errno spaces.
 * So if we return a positive value, that's a WSA Error and should
 * be handled with openconnect__win32_strerror(). But if we return a
 * negative value, that's a normal errno and should be handled with
 * strerror(). No, you can't just pass the latter value (negated) to
 * openconnect__win32_strerror() because it gives nonsense results. */
static int cancellable_connect(struct openconnect_info *vpninfo, int sockfd,
			       const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_storage peer;
	socklen_t peerlen = sizeof(peer);
	fd_set wr_set, rd_set, ex_set;
	int maxfd = sockfd;
	int err;

	if (set_sock_nonblock(sockfd))
		goto sockerr;

	if (vpninfo->protect_socket)
		vpninfo->protect_socket(vpninfo->cbdata, sockfd);

	if (connect(sockfd, addr, addrlen) < 0 && !connect_pending()) {
	sockerr:
#ifdef _WIN32
		return WSAGetLastError();
#else
		return -errno;
#endif
	}

	do {
		FD_ZERO(&wr_set);
		FD_ZERO(&rd_set);
		FD_ZERO(&ex_set);
		FD_SET(sockfd, &wr_set);
#ifdef _WIN32 /* Windows indicates failure this way, not in wr_set */
		FD_SET(sockfd, &ex_set);
#endif
		cmd_fd_set(vpninfo, &rd_set, &maxfd);
		while (select(maxfd + 1, &rd_set, &wr_set, &ex_set, NULL) < 0) {
			if (errno != EINTR) {
				vpn_perror(vpninfo, _("Failed select() for socket connect"));
				return -EIO;
			}
		}

		if (is_cancel_pending(vpninfo, &rd_set)) {
			vpn_progress(vpninfo, PRG_ERR, _("Socket connect cancelled\n"));
			return -EINTR;
		}
	} while (!FD_ISSET(sockfd, &wr_set) && !FD_ISSET(sockfd, &ex_set) &&
		 !vpninfo->got_pause_cmd);

	/* Check whether connect() succeeded or failed by using
	   getpeername(). See https://cr.yp.to/docs/connect.html */
	if (!getpeername(sockfd, (void *)&peer, &peerlen))
		return 0;

#ifdef _WIN32 /* On Windows, use getsockopt() to determine the error.
	       * We don't ddo this on Windows because it just reports
	       * -ENOTCONN, which we already knew. */

	err = WSAGetLastError();
	if (err == WSAENOTCONN) {
		socklen_t errlen = sizeof(err);

		getsockopt(sockfd, SOL_SOCKET, SO_ERROR,
			   (void *)&err, &errlen);
	}
#else
	err = -errno;
	if (err == -ENOTCONN) {
		char ch;

		if (read(sockfd, &ch, 1) < 0)
			err = -errno;
		/* It should *always* fail! */
	}
#endif
	return err;
}


static inline int accept_pending(void)
{
#ifdef _WIN32
	return WSAGetLastError() == WSAEWOULDBLOCK;
#else
	return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

int cancellable_accept(struct openconnect_info *vpninfo, int sockfd)
{
	fd_set wr_set, rd_set, ex_set;
	int accept_fd, maxfd = sockfd;
	char *errstr;

	do {
		accept_fd = accept(sockfd, NULL, NULL);
		if (accept_fd >= 0)
			return accept_fd;

		if (!accept_pending())
			break;

		FD_ZERO(&wr_set);
		FD_ZERO(&rd_set);
		FD_ZERO(&ex_set);
		FD_SET(sockfd, &rd_set);

		cmd_fd_set(vpninfo, &rd_set, &maxfd);
		while (select(maxfd + 1, &rd_set, &wr_set, &ex_set, NULL) < 0) {
			if (errno != EINTR) {
				vpn_perror(vpninfo, _("Failed select() for socket accept"));
				return -EIO;
			}
		}

		if (is_cancel_pending(vpninfo, &rd_set)) {
			vpn_progress(vpninfo, PRG_ERR, _("Socket accept cancelled\n"));
			return -EINTR;
		}
	} while (!FD_ISSET(sockfd, &ex_set) && !vpninfo->got_pause_cmd);

#ifdef _WIN32
	errstr = openconnect__win32_strerror(WSAGetLastError());
#else
	errstr = strerror(errno);
#endif
	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to accept local connection: %s\n"),
		     errstr);
#ifdef _WIN32
	free(errstr);
#endif
	return -1;
}

/* checks whether the provided string is an IP or a hostname.
 */
unsigned string_is_hostname(const char *str)
{
	struct in_addr buf;

	/* We don't use inet_pton() because an IPv6 literal is likely to
	   be encased in []. So just check for a colon, which shouldn't
	   occur in hostnames anyway. */
	if (!str || inet_aton(str, &buf) || strchr(str, ':'))
		return 0;

	return 1;
}

static int match_sockaddr(struct sockaddr *a, struct sockaddr *b)
{
	if (a->sa_family == AF_INET) {
		struct sockaddr_in *a4 = (void *)a;
		struct sockaddr_in *b4 = (void *)b;

		return (a4->sin_addr.s_addr == b4->sin_addr.s_addr) &&
			(a4->sin_port == b4->sin_port);
	} else if (a->sa_family == AF_INET6) {
		struct sockaddr_in6 *a6 = (void *)a;
		struct sockaddr_in6 *b6 = (void *)b;
		return !memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) &&
		       a6->sin6_port == b6->sin6_port;
	} else
		return 0;
}

static int set_tcp_nodelay(struct openconnect_info *vpninfo, int ssl_sock)
{
	int flag = 1;
	if (setsockopt(ssl_sock, IPPROTO_TCP, TCP_NODELAY, (void *)(&flag), sizeof(flag)) < 0) {;
		vpn_perror(vpninfo,
			   _("Failed setsockopt(TCP_NODELAY) on TLS socket:"));
#ifdef _WIN32
		return WSAGetLastError();
#else
		return -errno;
#endif
	}
	return 0;
}


int connect_https_socket(struct openconnect_info *vpninfo)
{
	int ssl_sock = -1;
	int err;

	/* If we're talking to a server which told us it has dynamic DNS, don't
	   just reuse its previous IP address. If we're talking to a proxy, we
	   can use *its* previous IP address. We expect it'll redo the DNS
	   lookup for the server anyway. */
	if (vpninfo->peer_addr && (!vpninfo->is_dyndns || vpninfo->proxy)) {
	reconnect:
#ifdef SOCK_CLOEXEC
		ssl_sock = socket(vpninfo->peer_addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_IP);
		if (ssl_sock < 0)
#endif
		{
			ssl_sock = socket(vpninfo->peer_addr->sa_family, SOCK_STREAM, IPPROTO_IP);
			if (ssl_sock < 0) {
#ifdef _WIN32
				err = WSAGetLastError();
#else
				err = -errno;
#endif
				goto reconn_err;
			}
			set_fd_cloexec(ssl_sock);
		}
		set_tcp_nodelay(vpninfo, ssl_sock);
		err = cancellable_connect(vpninfo, ssl_sock, vpninfo->peer_addr, vpninfo->peer_addrlen);
		if (err) {
			char *errstr;
		reconn_err:
#ifdef _WIN32
			if (err > 0)
				errstr = openconnect__win32_strerror(err);
			else
#endif
				errstr = strerror(-err);
			if (vpninfo->proxy) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to reconnect to proxy %s: %s\n"),
					     vpninfo->proxy, errstr);
			} else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to reconnect to host %s: %s\n"),
					     vpninfo->hostname, errstr);
			}
#ifdef _WIN32
			if (err > 0)
				free(errstr);
#endif
			if (ssl_sock >= 0)
				closesocket(ssl_sock);
			ssl_sock = -EINVAL;
			goto out;
		}
	} else {
		struct addrinfo hints, *result, *rp;
		char *hostname;
		char port[6];

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
		hints.ai_protocol = 0;
		hints.ai_canonname = NULL;
		hints.ai_addr = NULL;
		hints.ai_next = NULL;

		/* The 'port' variable is a string because it's easier
		   this way than if we pass NULL to getaddrinfo() and
		   then try to fill in the numeric value into
		   different types of returned sockaddr_in{6,}. */
#ifdef LIBPROXY_HDR
		if (vpninfo->proxy_factory) {
			struct oc_text_buf *url_buf = buf_alloc();
			char **proxies;
			int i = 0;

			free(vpninfo->proxy_type);
			vpninfo->proxy_type = NULL;
			free(vpninfo->proxy);
			vpninfo->proxy = NULL;

			buf_append(url_buf, "https://%s", vpninfo->hostname);
			if (vpninfo->port != 443)
				buf_append(url_buf, ":%d", vpninfo->port);
			buf_append(url_buf, "/%s", vpninfo->urlpath?:"");
			if (buf_error(url_buf)) {
				buf_free(url_buf);
				ssl_sock = -ENOMEM;
				goto out;
			}

			proxies = px_proxy_factory_get_proxies(vpninfo->proxy_factory,
							       url_buf->data);
			i = 0;
			while (proxies && proxies[i]) {
				if (!vpninfo->proxy &&
				    (!strncmp(proxies[i], "http://", 7) ||
				     !strncmp(proxies[i], "socks://", 8) ||
				     !strncmp(proxies[i], "socks5://", 9)))
					internal_parse_url(proxies[i], &vpninfo->proxy_type,
						  &vpninfo->proxy, &vpninfo->proxy_port,
						  NULL, 0);
				i++;
			}
			buf_free(url_buf);
			free(proxies);
			if (vpninfo->proxy)
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Proxy from libproxy: %s://%s:%d/\n"),
					     vpninfo->proxy_type, vpninfo->proxy, vpninfo->port);
		}
#endif
		if (vpninfo->proxy) {
			hostname = vpninfo->proxy;
			snprintf(port, 6, "%d", vpninfo->proxy_port);
		} else {
			hostname = vpninfo->hostname;
			snprintf(port, 6, "%d", vpninfo->port);
		}

		if (hostname[0] == '[' && hostname[strlen(hostname)-1] == ']') {
			hostname = strndup(hostname + 1, strlen(hostname) - 2);
			if (!hostname) {
				ssl_sock = -ENOMEM;
				goto out;
			}
			hints.ai_flags |= AI_NUMERICHOST;
		}

		if (vpninfo->getaddrinfo_override)
			err = vpninfo->getaddrinfo_override(vpninfo->cbdata, hostname, port, &hints, &result);
		else
			err = getaddrinfo(hostname, port, &hints, &result);

		if (err) {
#ifdef _WIN32
			char *errstr = openconnect__win32_strerror(WSAGetLastError());
#else
			const char *errstr = gai_strerror(err);
#endif
			vpn_progress(vpninfo, PRG_ERR,
				     _("getaddrinfo failed for host '%s': %s\n"),
				     hostname, errstr);
#ifdef _WIN32
			free(errstr);
#endif
			if (hints.ai_flags & AI_NUMERICHOST)
				free(hostname);
			ssl_sock = -EINVAL;
			/* If we were just retrying for dynamic DNS, reconnect using
			   the previously-known IP address */
			if (vpninfo->peer_addr) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Reconnecting to DynDNS server using previously cached IP address\n"));
				goto reconnect;
			}
			goto out;
		}
		if (hints.ai_flags & AI_NUMERICHOST)
			free(hostname);

		for (rp = result; rp ; rp = rp->ai_next) {
			char host[80];

			host[0] = 0;
			if (!getnameinfo(rp->ai_addr, rp->ai_addrlen, host,
					 sizeof(host), NULL, 0, NI_NUMERICHOST))
				vpn_progress(vpninfo, PRG_DEBUG, vpninfo->proxy_type ?
						     _("Attempting to connect to proxy %s%s%s:%s\n") :
						     _("Attempting to connect to server %s%s%s:%s\n"),
					     rp->ai_family == AF_INET6 ? "[" : "",
					     host,
					     rp->ai_family == AF_INET6 ? "]" : "",
					     port);

			ssl_sock = socket(rp->ai_family, rp->ai_socktype,
					  rp->ai_protocol);
			if (ssl_sock < 0)
				continue;
			set_fd_cloexec(ssl_sock);
			set_tcp_nodelay(vpninfo, ssl_sock);
			err = cancellable_connect(vpninfo, ssl_sock, rp->ai_addr, rp->ai_addrlen);
			if (!err) {
				/* Store the peer address we actually used, so that DTLS can
				   use it again later */
				free(vpninfo->ip_info.gateway_addr);
				vpninfo->ip_info.gateway_addr = NULL;

				if (host[0]) {
					vpninfo->ip_info.gateway_addr = strdup(host);
					vpn_progress(vpninfo, PRG_INFO, _("Connected to %s%s%s:%s\n"),
						     rp->ai_family == AF_INET6 ? "[" : "",
						     host,
						     rp->ai_family == AF_INET6 ? "]" : "",
						     port);
				}

				free(vpninfo->peer_addr);
				vpninfo->peer_addrlen = 0;
				vpninfo->peer_addr = malloc(rp->ai_addrlen);
				if (!vpninfo->peer_addr) {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Failed to allocate sockaddr storage\n"));
					closesocket(ssl_sock);
					ssl_sock = -ENOMEM;
					freeaddrinfo(result);
					goto out;
				}
				vpninfo->peer_addrlen = rp->ai_addrlen;
				memcpy(vpninfo->peer_addr, rp->ai_addr, rp->ai_addrlen);
				/* If no proxy, ensure that we output *this* IP address in
				 * authentication results because we're going to need to
				 * reconnect to the *same* server from the rotation. And with
				 * some trick DNS setups, it might possibly be a "rotation"
				 * even if we only got one result from getaddrinfo() this
				 * time.
				 *
				 * If there's a proxy, we're kind of screwed; we can't know
				 * which IP address we connected to. Perhaps we ought to do
				 * the DNS lookup locally and connect to a specific IP? */
				if (!vpninfo->proxy && host[0]) {
					char *p = malloc(strlen(host) + 3);
					if (p) {
						free(vpninfo->unique_hostname);
						vpninfo->unique_hostname = p;
						if (rp->ai_family == AF_INET6)
							*p++ = '[';
						memcpy(p, host, strlen(host));
						p += strlen(host);
						if (rp->ai_family == AF_INET6)
							*p++ = ']';
						*p = 0;
					}
				}
				break;
			}
			if (host[0]) {
				char *errstr;
#ifdef _WIN32
				if (err > 0)
					errstr = openconnect__win32_strerror(err);
				else
#endif
					errstr = strerror(-err);

				vpn_progress(vpninfo, PRG_INFO, _("Failed to connect to %s%s%s:%s: %s\n"),
					     rp->ai_family == AF_INET6 ? "[" : "",
					     host,
					     rp->ai_family == AF_INET6 ? "]" : "",
					     port, errstr);
#ifdef _WIN32
				if (err > 0)
					free(errstr);
#endif
			}
			closesocket(ssl_sock);
			ssl_sock = -1;

			/* If we're in DynDNS mode but this *was* the cached IP address,
			 * don't bother falling back to it if it didn't work. */
			if (vpninfo->peer_addr && vpninfo->peer_addrlen == rp->ai_addrlen &&
			    match_sockaddr(vpninfo->peer_addr, rp->ai_addr)) {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Forgetting non-functional previous peer address\n"));
				free(vpninfo->peer_addr);
				vpninfo->peer_addr = NULL;
				vpninfo->peer_addrlen = 0;
				free(vpninfo->ip_info.gateway_addr);
				vpninfo->ip_info.gateway_addr = NULL;
			}
		}
		freeaddrinfo(result);

		if (ssl_sock < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to connect to host %s\n"),
				     vpninfo->proxy?:vpninfo->hostname);
			ssl_sock = -EINVAL;
			if (vpninfo->peer_addr) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Reconnecting to DynDNS server using previously cached IP address\n"));
				goto reconnect;
			}
			goto out;
		}
	}

	if (vpninfo->proxy) {
		err = process_proxy(vpninfo, ssl_sock);
		if (err) {
			closesocket(ssl_sock);
			if (err == -EAGAIN) {
				/* Proxy authentication failed and we need to retry */
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Reconnecting to proxy %s\n"), vpninfo->proxy);
				goto reconnect;
			}
			ssl_sock = err;
		}
	}
 out:
	/* If proxy processing returned -EAGAIN to reconnect before attempting
	   further auth, and we failed to reconnect, we have to clean up here. */
	clear_auth_states(vpninfo, vpninfo->proxy_auth, 1);
	return ssl_sock;
}

int  __attribute__ ((format (printf, 2, 3)))
    openconnect_SSL_printf(struct openconnect_info *vpninfo, const char *fmt, ...)
{
	char buf[1024];
	va_list args;

	buf[1023] = 0;

	va_start(args, fmt);
	vsnprintf(buf, 1023, fmt, args);
	va_end(args);
	return vpninfo->ssl_write(vpninfo, buf, strlen(buf));

}

int __attribute__ ((format(printf, 4, 5)))
    request_passphrase(struct openconnect_info *vpninfo, const char *label,
		       char **response, const char *fmt, ...)
{
	struct oc_auth_form f;
	struct oc_form_opt o;
	char buf[1024];
	va_list args;
	int ret;

	buf[1023] = 0;
	memset(&f, 0, sizeof(f));
	va_start(args, fmt);
	vsnprintf(buf, 1023, fmt, args);
	va_end(args);

	f.auth_id = (char *)label;
	f.opts = &o;

	o.next = NULL;
	o.type = OC_FORM_OPT_PASSWORD;
	o.name = (char *)label;
	o.label = buf;
	o._value = NULL;

	ret = process_auth_form(vpninfo, &f);
	if (!ret) {
		*response = o._value;
		return 0;
	}

	return -EIO;
}

#if defined(__sun__) || defined(__NetBSD__) || defined(__DragonFly__)
int openconnect_passphrase_from_fsid(struct openconnect_info *vpninfo)
{
	struct statvfs buf;
	char *sslkey = openconnect_utf8_to_legacy(vpninfo, vpninfo->certinfo[0].key);
	int err = 0;

	if (statvfs(sslkey, &buf)) {
		err = -errno;
		vpn_progress(vpninfo, PRG_ERR, _("statvfs: %s\n"),
			     strerror(errno));
	} else if (asprintf(&vpninfo->certinfo[0].password, "%lx", buf.f_fsid) == -1)
		err = -ENOMEM;

	if (sslkey != vpninfo->certinfo[0].key)
		free(sslkey);
	return err;
}
#elif defined(_WIN32)
#include <fileapi.h>
typedef BOOL WINAPI (*GVIBH)(HANDLE, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD);

int openconnect_passphrase_from_fsid(struct openconnect_info *vpninfo)
{
	HANDLE h;
	DWORD serial;
	HINSTANCE kernlib;
	GVIBH func = NULL;
	int success;
	int fd;

	/* Some versions of Windows don't have this so don't use standard
	   load-time linking or it'll cause failures. */
	kernlib = LoadLibraryA("Kernel32.dll");
	if (!kernlib) {
	notsupp:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Could not obtain file system ID for passphrase\n"));
		return -EOPNOTSUPP;
	}
	func = (void *)GetProcAddress(kernlib, "GetVolumeInformationByHandleW");
	FreeLibrary(kernlib);
	if (!func)
		goto notsupp;

	fd = openconnect_open_utf8(vpninfo, vpninfo->certinfo[0].key, O_RDONLY);
	if (fd == -1) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open private key file '%s': %s\n"),
			     vpninfo->certinfo[0].key, strerror(errno));
		return -ENOENT;
	}

	h = (HANDLE)_get_osfhandle(fd);
	success = func(h, NULL, 0, &serial, NULL, NULL, NULL, 0);
	close(fd);

	if (!success)
		return -EIO;

	if (asprintf(&vpninfo->certinfo[0].password, "%lx", serial) == -1)
		return -ENOMEM;

	return 0;
}
#elif defined(HAVE_STATFS)
int openconnect_passphrase_from_fsid(struct openconnect_info *vpninfo)
{
	char *sslkey = openconnect_utf8_to_legacy(vpninfo, vpninfo->certinfo[0].key);
	struct statfs buf;
	unsigned *fsid = (unsigned *)&buf.f_fsid;
	unsigned long long fsid64;
	int err = 0;

	if (statfs(sslkey, &buf)) {
		err = -errno;
		vpn_progress(vpninfo, PRG_ERR, _("statfs: %s\n"),
			     strerror(errno));
		return -err;
	} else {
		fsid64 = ((unsigned long long)fsid[0] << 32) | fsid[1];

		if (asprintf(&vpninfo->certinfo[0].password, "%llx", fsid64) == -1)
			err = -ENOMEM;
	}

	if (sslkey != vpninfo->certinfo[0].key)
		free(sslkey);

	return err;
}
#else
int openconnect_passphrase_from_fsid(struct openconnect_info *vpninfo)
{
	return -EOPNOTSUPP;
}
#endif

#if defined(OPENCONNECT_OPENSSL)
/* We put this here rather than in openssl.c because it might be needed
   for OpenSSL DTLS support even when GnuTLS is being used for HTTPS */
int openconnect_print_err_cb(const char *str, size_t len, void *ptr)
{
	struct openconnect_info *vpninfo = ptr;

	vpn_progress(vpninfo, PRG_ERR, "%s", str);
	return 0;
}
#endif

#ifdef FAKE_ANDROID_KEYSTORE
char *keystore_strerror(int err)
{
	return (char *)strerror(-err);
}

int keystore_fetch(const char *key, unsigned char **result)
{
	unsigned char *data;
	struct stat st;
	int fd;
	int ret;

	fd = open(key, O_RDONLY);
	if (fd < 0)
		return -errno;

	if (fstat(fd, &st)) {
		ret = -errno;
		goto out_fd;
	}

	data = malloc(st.st_size + 1);
	if (!data) {
		ret = -ENOMEM;
		goto out_fd;
	}

	if (read(fd, data, st.st_size) != st.st_size) {
		ret = -EIO;
		free(data);
		goto out_fd;
	}

	data[st.st_size] = 0;
	*result = data;
	ret = st.st_size;
 out_fd:
	close(fd);
	return ret;
}
#elif defined(ANDROID_KEYSTORE)
/* keystore.h isn't in the NDK so we need to define these */
#define NO_ERROR		1
#define LOCKED			2
#define UNINITIALIZED		3
#define SYSTEM_ERROR		4
#define PROTOCOL_ERROR		5
#define PERMISSION_DENIED	6
#define KEY_NOT_FOUND		7
#define VALUE_CORRUPTED		8
#define UNDEFINED_ACTION	9
#define WRONG_PASSWORD		10

const char *keystore_strerror(int err)
{
	switch (-err) {
	case NO_ERROR:		return _("No error");
	case LOCKED:		return _("Keystore locked");
	case UNINITIALIZED:	return _("Keystore uninitialized");
	case SYSTEM_ERROR:	return _("System error");
	case PROTOCOL_ERROR:	return _("Protocol error");
	case PERMISSION_DENIED:	return _("Permission denied");
	case KEY_NOT_FOUND:	return _("Key not found");
	case VALUE_CORRUPTED:	return _("Value corrupted");
	case UNDEFINED_ACTION:	return _("Undefined action");
	case WRONG_PASSWORD:
	case WRONG_PASSWORD+1:
	case WRONG_PASSWORD+2:
	case WRONG_PASSWORD+3:	return _("Wrong password");
	default:		return _("Unknown error");
	}
}

/* Returns length, or a negative errno in its own namespace (handled by its
   own strerror function above). The numbers are from Android's keystore.h */
int keystore_fetch(const char *key, unsigned char **result)
{
	struct sockaddr_un sa = { AF_UNIX, "/dev/socket/keystore" };
	socklen_t sl = offsetof(struct sockaddr_un, sun_path) + strlen(sa.sun_path) + 1;
	unsigned char *data, *p;
	unsigned char buf[3];
	int len, fd;
	int ret = -SYSTEM_ERROR;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -SYSTEM_ERROR;

	if (connect(fd, (void *)&sa, sl)) {
		close(fd);
		return -SYSTEM_ERROR;
	}
	len = strlen(key);
	buf[0] = 'g';
	store_be16(buf + 1, len);

	if (send(fd, buf, 3, 0) != 3 || send(fd, key, len, 0) != len ||
	    shutdown(fd, SHUT_WR) || recv(fd, buf, 1, 0) != 1)
		goto out;

	if (buf[0] != NO_ERROR) {
		/* Should never be zero */
		ret = buf[0] ? -buf[0] : -PROTOCOL_ERROR;
		goto out;
	}
	if (recv(fd, buf, 2, 0) != 2)
		goto out;
	len = load_be16(buf);
	data = malloc(len);
	if (!data)
		goto out;
	p  = data;
	ret = len;
	while (len) {
		int got = recv(fd, p, len, 0);
		if (got <= 0) {
			free(data);
			ret = -PROTOCOL_ERROR;
			goto out;
		}
		len -= got;
		p += got;
	}

	*result = data;

 out:
	close(fd);
	return ret;
}
#endif

void cmd_fd_set(struct openconnect_info *vpninfo, fd_set *fds, int *maxfd)
{
	if (vpninfo->cmd_fd != -1) {
		FD_SET(vpninfo->cmd_fd, fds);
		if (vpninfo->cmd_fd > *maxfd)
			*maxfd = vpninfo->cmd_fd;
	}
}

void check_cmd_fd(struct openconnect_info *vpninfo, fd_set *fds)
{
	char cmd;

	if (vpninfo->cmd_fd == -1 || !FD_ISSET(vpninfo->cmd_fd, fds))
		return;
	if (vpninfo->cmd_fd_write == -1) {
		/* legacy openconnect_set_cancel_fd() users */
		vpn_progress(vpninfo, PRG_TRACE, _("Got cancel on legacy fd\n"));
		vpninfo->got_cancel_cmd = 1;
		return;
	}

#ifdef _WIN32
	if (recv(vpninfo->cmd_fd, &cmd, 1, 0) != 1)
		return;
#else
	if (read(vpninfo->cmd_fd, &cmd, 1) != 1)
		return;
#endif
	switch (cmd) {
	case OC_CMD_CANCEL:
	case OC_CMD_DETACH:
		vpn_progress(vpninfo, PRG_TRACE, _("Got cancel command\n"));
		vpninfo->got_cancel_cmd = 1;
		vpninfo->cancel_type = cmd;
		break;
	case OC_CMD_PAUSE:
		vpn_progress(vpninfo, PRG_TRACE, _("Got pause command\n"));
		vpninfo->got_pause_cmd = 1;
		break;
	case OC_CMD_STATS:
		if (vpninfo->stats_handler)
			vpninfo->stats_handler(vpninfo->cbdata, &vpninfo->stats);
	}
}

int is_cancel_pending(struct openconnect_info *vpninfo, fd_set *fds)
{
	check_cmd_fd(vpninfo, fds);
	return vpninfo->got_cancel_cmd || vpninfo->got_pause_cmd;
}

void poll_cmd_fd(struct openconnect_info *vpninfo, int timeout)
{
	fd_set rd_set;
	int maxfd = 0;
	time_t expiration = time(NULL) + timeout, now = 0;

	while (now < expiration && !vpninfo->got_cancel_cmd && !vpninfo->got_pause_cmd) {
		struct timeval tv;

		now = time(NULL);
		tv.tv_sec = now >= expiration ? 0 : expiration - now;
		tv.tv_usec = 0;

		/* If the cmd_fd is internal and we've been told to poll it,
		 * don't *keep* doing so afterwards. */
		vpninfo->need_poll_cmd_fd = !vpninfo->cmd_fd_internal;

		FD_ZERO(&rd_set);
		cmd_fd_set(vpninfo, &rd_set, &maxfd);
		if (select(maxfd + 1, &rd_set, NULL, NULL, &tv) < 0) {
			if (errno == EINTR)
				continue;

			vpn_perror(vpninfo, _("Failed select() for command socket"));
			return;
		}
		if (FD_ISSET(vpninfo->cmd_fd, &rd_set)) {
			vpninfo->need_poll_cmd_fd = 1; /* Until it's *empty */
			check_cmd_fd(vpninfo, &rd_set);
		}
	}
}

#ifdef _WIN32
#include <io.h>
#include <sys/stat.h>
int openconnect_open_utf8(struct openconnect_info *vpninfo, const char *fname, int mode)
{
	wchar_t *fname_w;
	int nr_chars = MultiByteToWideChar(CP_UTF8, 0, fname, -1, NULL, 0);
	int fd;

	if (!nr_chars) {
		errno = EINVAL;
		return -1;
	}
	fname_w = malloc(nr_chars * sizeof(wchar_t));
	if (!fname_w) {
		errno = ENOMEM;
		return -1;
	}
	MultiByteToWideChar(CP_UTF8, 0, fname, -1, fname_w, nr_chars);

	fd = _wopen(fname_w, mode, _S_IREAD | _S_IWRITE);
	free(fname_w);

	return fd;
}
#else
int openconnect_open_utf8(struct openconnect_info *vpninfo, const char *fname, int mode)
{
	char *legacy_fname = openconnect_utf8_to_legacy(vpninfo, fname);
	int fd;

	fd = open(legacy_fname, mode, 0644);
	if (legacy_fname != fname)
		free(legacy_fname);

	return fd;
}
#endif

FILE *openconnect_fopen_utf8(struct openconnect_info *vpninfo, const char *fname,
			     const char *mode)
{
	int fd;
	int flags;

	if (!strcmp(mode, "r"))
		flags = O_RDONLY|O_CLOEXEC;
	else if (!strcmp(mode, "rb"))
		flags = O_RDONLY|O_CLOEXEC|O_BINARY;
	else if (!strcmp(mode, "w"))
		flags = O_WRONLY|O_CLOEXEC|O_CREAT|O_TRUNC;
	else if (!strcmp(mode, "wb"))
		flags = O_WRONLY|O_CLOEXEC|O_CREAT|O_TRUNC|O_BINARY;
	else {
		/* This should never happen, but if we forget and start using other
		   modes without implementing proper mode->flags conversion, complain! */
		vpn_progress(vpninfo, PRG_ERR,
			     _("%s() used with unsupported mode '%s'\n"),
			     __func__, mode);
		return NULL;
	}

	fd = openconnect_open_utf8(vpninfo, fname, flags);
	if (fd == -1)
		return NULL;

	return fdopen(fd, mode);
}

ssize_t openconnect_read_file(struct openconnect_info *vpninfo, const char *fname,
			      char **ptr)
{
	int fd, len;
	struct stat st;
	char *buf;

	fd = openconnect_open_utf8(vpninfo, fname, O_RDONLY|O_BINARY);
	if (fd < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open %s: %s\n"),
			     fname, strerror(errno));
		return -ENOENT;
	}

	if (fstat(fd, &st)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to fstat() %s: %s\n"),
			     fname, strerror(errno));
		close(fd);
		return -EIO;
	}

	if (st.st_size == 0) {
		vpn_progress(vpninfo, PRG_INFO, _("File %s is empty\n"),
			     vpninfo->xmlconfig);
		close(fd);
		return -ENOENT;
	}
	if (st.st_size >= INT_MAX || st.st_size < 0) {
		vpn_progress(vpninfo, PRG_INFO, _("File %s has suspicious size %" PRId64 "\n"),
			     vpninfo->xmlconfig, (int64_t)st.st_size);
		close(fd);
		return -EIO;
	}
	len = st.st_size;
	buf = malloc(len + 1);
	if (!buf) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to allocate %d bytes for %s\n"),
			     len + 1, fname);
		close(fd);
		return -ENOMEM;
	}

	if (read(fd, buf, len) != len) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to read %s: %s\n"),
			     fname, strerror(errno));
		free(buf);
		close(fd);
		return -EIO;
	}

	buf[len] = 0;
	close(fd);
	*ptr = buf;
	return len;
}

int udp_sockaddr(struct openconnect_info *vpninfo, int port)
{
	free(vpninfo->dtls_addr);
	vpninfo->dtls_addr = malloc(vpninfo->peer_addrlen);
	if (!vpninfo->dtls_addr)
		return -ENOMEM;

	memcpy(vpninfo->dtls_addr, vpninfo->peer_addr, vpninfo->peer_addrlen);

	if (vpninfo->peer_addr->sa_family == AF_INET) {
		struct sockaddr_in *sin = (void *)vpninfo->dtls_addr;
		sin->sin_port = htons(port);
		vpninfo->dtls_tos_proto = IPPROTO_IP;
		vpninfo->dtls_tos_optname = IP_TOS;
	} else if (vpninfo->peer_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin = (void *)vpninfo->dtls_addr;
		sin->sin6_port = htons(port);
#if defined(IPV6_TCLASS)
		vpninfo->dtls_tos_proto = IPPROTO_IPV6;
		vpninfo->dtls_tos_optname = IPV6_TCLASS;
#endif
	} else {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown protocol family %d. Cannot create UDP server address\n"),
			     vpninfo->peer_addr->sa_family);
		return -EINVAL;
	}

	/* in case DTLS TOS copy is disabled, reset the optname value */
	/* so that the copy won't be applied in dtls.c / dtls_mainloop() */
	if (!vpninfo->dtls_pass_tos)
		vpninfo->dtls_tos_optname = 0;

	return 0;
}

int udp_connect(struct openconnect_info *vpninfo)
{
	int fd, sndbuf;

	fd = socket(vpninfo->peer_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		vpn_perror(vpninfo, _("Open UDP socket"));
		return -EINVAL;
	}
	if (vpninfo->protect_socket)
		vpninfo->protect_socket(vpninfo->cbdata, fd);

	sndbuf = vpninfo->ip_info.mtu;
	if (!sndbuf)
		sndbuf = 1500;
	sndbuf *= vpninfo->max_qlen;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *)&sndbuf, sizeof(sndbuf)) < 0) {
		vpn_perror(vpninfo, "Set UDP socket send buffer");
	}

	socklen_t l = sizeof(sndbuf);
	if (!getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *)&sndbuf, &l))
		vpn_progress(vpninfo, PRG_DEBUG, "UDP SO_SNDBUF: %d\n", sndbuf);

	if (vpninfo->dtls_local_port) {
		union {
			struct sockaddr_in in;
			struct sockaddr_in6 in6;
		} dtls_bind_addr;
		int dtls_bind_addrlen;
		memset(&dtls_bind_addr, 0, sizeof(dtls_bind_addr));

		if (vpninfo->peer_addr->sa_family == AF_INET) {
			struct sockaddr_in *addr = &dtls_bind_addr.in;
			dtls_bind_addrlen = sizeof(*addr);
			addr->sin_family = AF_INET;
			addr->sin_addr.s_addr = INADDR_ANY;
			addr->sin_port = htons(vpninfo->dtls_local_port);
		} else if (vpninfo->peer_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *addr = &dtls_bind_addr.in6;
			dtls_bind_addrlen = sizeof(*addr);
			addr->sin6_family = AF_INET6;
			addr->sin6_addr = in6addr_any;
			addr->sin6_port = htons(vpninfo->dtls_local_port);
		} else {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown protocol family %d. Cannot use UDP transport\n"),
				     vpninfo->peer_addr->sa_family);
			vpninfo->dtls_attempt_period = 0;
			closesocket(fd);
			return -EINVAL;
		}

		if (bind(fd, (struct sockaddr *)&dtls_bind_addr, dtls_bind_addrlen)) {
			vpn_perror(vpninfo, _("Bind UDP socket"));
			closesocket(fd);
			return -EINVAL;
		}
	}

	if (connect(fd, vpninfo->dtls_addr, vpninfo->peer_addrlen)) {
		vpn_perror(vpninfo, _("Connect UDP socket"));
		closesocket(fd);
		return -EINVAL;
	}

	set_fd_cloexec(fd);
	if (set_sock_nonblock(fd)) {
		vpn_perror(vpninfo, _("Make UDP socket non-blocking"));
		closesocket(fd);
		return -EIO;
	}

	return fd;
}

int ssl_reconnect(struct openconnect_info *vpninfo)
{
	int ret;
	int timeout;
	int interval;
	int tun_up = tun_is_up(vpninfo);

	openconnect_close_https(vpninfo, 0);


	timeout = vpninfo->reconnect_timeout;
	interval = vpninfo->reconnect_interval;

	free_pkt(vpninfo, vpninfo->dtls_pkt);
	vpninfo->dtls_pkt = NULL;
	free_pkt(vpninfo, vpninfo->tun_pkt);
	vpninfo->tun_pkt = NULL;

	while (1) {
		if (tun_up)
			script_config_tun(vpninfo, "attempt-reconnect");
		ret = vpninfo->proto->tcp_connect(vpninfo);
		if (!ret)
			break;

		if (timeout <= 0)
			return ret;
		if (ret == -EPERM) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Cookie is no longer valid, ending session\n"));
			return ret;
		}
		vpn_progress(vpninfo, PRG_INFO,
			     _("sleep %ds, remaining timeout %ds\n"),
			     interval, timeout);
		poll_cmd_fd(vpninfo, interval);
		if (vpninfo->got_cancel_cmd)
			return -EINTR;
		if (vpninfo->got_pause_cmd)
			return 0;
		timeout -= interval;
		interval += vpninfo->reconnect_interval;
		if (interval > RECONNECT_INTERVAL_MAX)
			interval = RECONNECT_INTERVAL_MAX;
	}

	if (tun_up) {
		script_config_tun(vpninfo, "reconnect");
		if (vpninfo->reconnected)
			vpninfo->reconnected(vpninfo->cbdata);
	}

	return 0;
}

int cancellable_gets(struct openconnect_info *vpninfo, int fd,
		     char *buf, size_t len)
{
	int i = 0;
	int ret;

	if (len < 2)
		return -EINVAL;

	while ((ret = cancellable_recv(vpninfo, fd, (void *)(buf + i), 1)) == 1) {
		if (buf[i] == '\n') {
			buf[i] = 0;
			if (i && buf[i-1] == '\r') {
				buf[i-1] = 0;
				i--;
			}
			return i;
		}
		i++;

		if (i >= len - 1) {
			buf[i] = 0;
			return i;
		}
	}
	buf[i] = 0;
	return i ?: ret;
}

int cancellable_send(struct openconnect_info *vpninfo, int fd,
		     const char *buf, size_t len)
{
	size_t count;

	if (fd == -1)
		return -EINVAL;

	for (count = 0; count < len; ) {
		fd_set rd_set, wr_set;
		int maxfd = fd;
		int i;

		FD_ZERO(&wr_set);
		FD_ZERO(&rd_set);
		FD_SET(fd, &wr_set);
		cmd_fd_set(vpninfo, &rd_set, &maxfd);

		while (select(maxfd + 1, &rd_set, &wr_set, NULL, NULL) < 0) {
			if (errno != EINTR) {
				vpn_perror(vpninfo, _("Failed select() for socket send"));
				return -EIO;
			}
		}

		if (is_cancel_pending(vpninfo, &rd_set))
			return -EINTR;

		/* Not that this should ever be able to happen... */
		if (!FD_ISSET(fd, &wr_set))
			continue;

		i = send(fd, (void *)&buf[count], len - count, 0);
		if (i < 0)
			return -errno;

		count += i;
	}
	return count;
}


int cancellable_recv(struct openconnect_info *vpninfo, int fd,
		     char *buf, size_t len)
{
	size_t count;

	if (fd == -1)
		return -EINVAL;

	for (count = 0; count < len; ) {
		fd_set rd_set;
		int maxfd = fd;
		int i;

		FD_ZERO(&rd_set);
		FD_SET(fd, &rd_set);
		cmd_fd_set(vpninfo, &rd_set, &maxfd);

		if (select(maxfd + 1, &rd_set, NULL, NULL, NULL) < 0) {
			if (errno != EINTR) {
				vpn_perror(vpninfo, _("Failed select() for socket recv"));
				return -EIO;
			}
		}

		if (is_cancel_pending(vpninfo, &rd_set))
			return -EINTR;

		/* Not that this should ever be able to happen... */
		if (!FD_ISSET(fd, &rd_set))
			continue;

		i = recv(fd, (void *)&buf[count], len - count, 0);
		if (i < 0)
			return -errno;
		else if (i == 0)
			return -ECONNRESET;

		count += i;
	}
	return count;
}
