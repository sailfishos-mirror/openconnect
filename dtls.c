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
#include <fcntl.h>
#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * The master-secret is generated randomly by the client. The server
 * responds with a DTLS Session-ID. These, done over the HTTPS
 * connection, are enough to 'resume' a DTLS session, bypassing all
 * the normal setup of a normal DTLS connection.
 *
 * Cisco use a version of the protocol which predates RFC4347, but
 * isn't quite the same as the pre-RFC version of the protocol which
 * was in OpenSSL 0.9.8e -- it includes backports of some later
 * OpenSSL patches.
 *
 * The openssl/ directory of this source tree should contain both a
 * small patch against OpenSSL 0.9.8e to make it support Cisco's
 * snapshot of the protocol, and a larger patch against newer OpenSSL
 * which gives us an option to use the old protocol again.
 *
 * Cisco's server also seems to respond to the official version of the
 * protocol, with a change in the ChangeCipherSpec packet which implies
 * that it does know the difference and isn't just repeating the version
 * number seen in the ClientHello. But although I can make the handshake
 * complete by hacking tls1_mac() to use the _old_ protocol version
 * number when calculating the MAC, the server still seems to be ignoring
 * my subsequent data packets. So we use the old protocol, which is what
 * their clients use anyway.
 */

char *openconnect_bin2hex(const char *prefix, const uint8_t *data, unsigned len)
{
	struct oc_text_buf *buf;
	char *p = NULL;

	buf = buf_alloc();
	if (prefix)
		buf_append(buf, "%s", prefix);
	buf_append_hex(buf, data, len);

	if (!buf_error(buf)) {
		p = buf->data;
		buf->data = NULL;
	}
	buf_free(buf);

	return p;
}

char *openconnect_bin2base64(const char *prefix, const uint8_t *data, unsigned len)
{
	struct oc_text_buf *buf;
	char *p = NULL;

	buf = buf_alloc();
	if (prefix)
		buf_append(buf, "%s", prefix);
	buf_append_base64(buf, data, len, 0);

	if (!buf_error(buf)) {
		p = buf->data;
		buf->data = NULL;
	}
	buf_free(buf);

	return p;
}

static int connect_dtls_socket(struct openconnect_info *vpninfo, int *timeout)
{
	int dtls_fd, ret;

	/* Sanity check for the removal of new_dtls_{fd,ssl} */
	if (vpninfo->dtls_fd != -1) {
		vpn_progress(vpninfo, PRG_ERR, _("DTLS connection attempted with an existing fd\n"));
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	if (!vpninfo->dtls_addr) {
		vpn_progress(vpninfo, PRG_ERR, _("No DTLS address\n"));
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	if (vpninfo->proto->proto == PROTO_ANYCONNECT && !vpninfo->dtls_cipher) {
		/* We probably didn't offer it any ciphers it liked */
		vpn_progress(vpninfo, PRG_ERR, _("Server offered no DTLS cipher option\n"));
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	if (vpninfo->proxy) {
		/* XXX: Theoretically, SOCKS5 proxies can do UDP too */
		vpn_progress(vpninfo, PRG_ERR, _("No DTLS when connected via proxy\n"));
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	dtls_fd = udp_connect(vpninfo);
	if (dtls_fd < 0)
		return -EINVAL;


	ret = start_dtls_handshake(vpninfo, dtls_fd);
	if (ret) {
		closesocket(dtls_fd);
		return ret;
	}

	vpninfo->dtls_state = DTLS_CONNECTING;

	vpninfo->dtls_fd = dtls_fd;
	monitor_fd_new(vpninfo, dtls);
	monitor_read_fd(vpninfo, dtls);
	monitor_except_fd(vpninfo, dtls);

	time(&vpninfo->new_dtls_started);

	return dtls_try_handshake(vpninfo, timeout);
}

void dtls_close(struct openconnect_info *vpninfo)
{
	if (vpninfo->dtls_ssl) {
		dtls_ssl_free(vpninfo);
		unmonitor_fd(vpninfo, dtls);
		closesocket(vpninfo->dtls_fd);
		vpninfo->dtls_ssl = NULL;
		vpninfo->dtls_fd = -1;
	}
	vpninfo->dtls_state = DTLS_SLEEPING;
}

int dtls_reconnect(struct openconnect_info *vpninfo, int *timeout)
{
	dtls_close(vpninfo);

	if (vpninfo->dtls_state == DTLS_DISABLED)
		return -EINVAL;

	vpninfo->dtls_state = DTLS_SLEEPING;
	return connect_dtls_socket(vpninfo, timeout);
}

int dtls_setup(struct openconnect_info *vpninfo)
{
	if (vpninfo->dtls_state == DTLS_DISABLED ||
	    vpninfo->dtls_state == DTLS_NOSECRET)
		return -EINVAL;

	if (!vpninfo->dtls_attempt_period)
		return 0;

	if (!vpninfo->dtls_addr) {
		vpn_progress(vpninfo, PRG_ERR, _("No DTLS address\n"));
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}
	if (vpninfo->dtls_times.rekey <= 0)
		vpninfo->dtls_times.rekey_method = REKEY_NONE;

	if (connect_dtls_socket(vpninfo, NULL))
		return -EINVAL;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("DTLS initialised. DPD %d, Keepalive %d\n"),
		     vpninfo->dtls_times.dpd, vpninfo->dtls_times.keepalive);

	return 0;
}

int udp_tos_update(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	int tos;

	/* Extract TOS field from IP header (IPv4 and IPv6 differ) */
	switch (pkt->data[0] >> 4) {
	case 4:
		tos = pkt->data[1];
		break;
	case 6:
		tos = (load_be16(pkt->data) >> 4) & 0xff;
		break;
	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown packet (len %d) received: %02x %02x %02x %02x...\n"),
			     pkt->len, pkt->data[0], pkt->data[1], pkt->data[2], pkt->data[3]);
		return -EINVAL;
	}

	/* set the actual value */
	if (tos != vpninfo->dtls_tos_current) {
		vpn_progress(vpninfo, PRG_DEBUG, _("TOS this: %d, TOS last: %d\n"),
			     tos, vpninfo->dtls_tos_current);
		if (setsockopt(vpninfo->dtls_fd, vpninfo->dtls_tos_proto,
			       vpninfo->dtls_tos_optname, (void *)&tos, sizeof(tos)))
			vpn_perror(vpninfo, _("UDP setsockopt"));
		else
			vpninfo->dtls_tos_current = tos;
	}
	return 0;
}

int dtls_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int work_done = 0;
	char magic_pkt;

	if (vpninfo->dtls_need_reconnect) {
		vpninfo->dtls_need_reconnect = 0;
		dtls_reconnect(vpninfo, timeout);
		return 1;
	}

	if (vpninfo->dtls_state == DTLS_CONNECTING) {
		dtls_try_handshake(vpninfo, timeout);
		if (vpninfo->dtls_state != DTLS_CONNECTED) {
			vpninfo->delay_tunnel_reason = "DTLS MTU detection";
			return 0;
		}
		return 1;
	}

	if (vpninfo->dtls_state == DTLS_SLEEPING) {
		int when = vpninfo->new_dtls_started + vpninfo->dtls_attempt_period - time(NULL);

		if (when <= 0) {
			vpn_progress(vpninfo, PRG_DEBUG, _("Attempt new DTLS connection\n"));
			if (connect_dtls_socket(vpninfo, timeout) < 0)
				*timeout = 1000;
		} else if ((when * 1000) < *timeout) {
			*timeout = when * 1000;
		}
		return 0;
	}

	/* Nothing to do here for Cisco DTLS as it is preauthenticated */
	if (vpninfo->dtls_state == DTLS_CONNECTED)
		vpninfo->dtls_state = DTLS_ESTABLISHED;

	while (readable) {
		int len = MAX(16384, vpninfo->ip_info.mtu);
		unsigned char *buf;

		if (vpninfo->incoming_queue.count >= vpninfo->max_qlen) {
			work_done = 1;
			break;
		}
		if (!vpninfo->dtls_pkt) {
			vpninfo->dtls_pkt = alloc_pkt(vpninfo, len);
			if (!vpninfo->dtls_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		buf = vpninfo->dtls_pkt->data - 1;
		len = ssl_nonblock_read(vpninfo, 1, buf, len + 1);
		if (len <= 0)
			break;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Received DTLS packet 0x%02x of %d bytes\n"),
			     buf[0], len);

		vpninfo->dtls_times.last_rx = time(NULL);

		switch (buf[0]) {
		case AC_PKT_DATA:
			vpninfo->dtls_pkt->len = len - 1;
			queue_packet(&vpninfo->incoming_queue, vpninfo->dtls_pkt);
			vpninfo->dtls_pkt = NULL;
			work_done = 1;
			break;

		case AC_PKT_DPD_OUT:
			vpn_progress(vpninfo, PRG_DEBUG, _("Got DTLS DPD request\n"));

			/* FIXME: What if the packet doesn't get through? */
			magic_pkt = AC_PKT_DPD_RESP;
			if (ssl_nonblock_write(vpninfo, 1, &magic_pkt, 1) != 1)
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to send DPD response. Expect disconnect\n"));
			continue;

		case AC_PKT_DPD_RESP:
			vpn_progress(vpninfo, PRG_DEBUG, _("Got DTLS DPD response\n"));
			break;

		case AC_PKT_KEEPALIVE:
			vpn_progress(vpninfo, PRG_DEBUG, _("Got DTLS Keepalive\n"));
			break;

		case AC_PKT_COMPRESSED:
			if (!vpninfo->dtls_compr) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Compressed DTLS packet received when compression not enabled\n"));
				goto unknown_pkt;
			}
			decompress_and_queue_packet(vpninfo, vpninfo->dtls_compr,
						    vpninfo->dtls_pkt->data, len - 1);
			break;
		default:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown DTLS packet type %02x, len %d\n"),
				     buf[0], len);
			if (1) {
				/* Some versions of OpenSSL have bugs with receiving out-of-order
				 * packets. Not only do they wrongly decide to drop packets if
				 * two packets get swapped in transit, but they also _fail_ to
				 * drop the packet in non-blocking mode; instead they return
				 * the appropriate length of garbage. So don't abort... for now. */
				break;
			} else {
			unknown_pkt:
				vpninfo->quit_reason = "Unknown packet received";
				return 1;
			}

		}
	}

	switch (keepalive_action(&vpninfo->dtls_times, timeout)) {
	case KA_REKEY: {
		int ret;

		vpn_progress(vpninfo, PRG_INFO, _("DTLS rekey due\n"));

		if (vpninfo->dtls_times.rekey_method == REKEY_SSL) {
			time(&vpninfo->new_dtls_started);
			vpninfo->dtls_state = DTLS_CONNECTING;
			ret = dtls_try_handshake(vpninfo, timeout);
			if (ret) {
				vpn_progress(vpninfo, PRG_ERR, _("DTLS Rehandshake failed; reconnecting.\n"));
				return connect_dtls_socket(vpninfo, timeout);
			}
		}

		return 1;
	}

	case KA_DPD_DEAD:
		vpn_progress(vpninfo, PRG_ERR, _("DTLS Dead Peer Detection detected dead peer!\n"));
		/* Fall back to SSL, and start a new DTLS connection */
		dtls_reconnect(vpninfo, timeout);
		return 1;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send DTLS DPD\n"));

		magic_pkt = AC_PKT_DPD_OUT;
		if (ssl_nonblock_write(vpninfo, 1, &magic_pkt, 1) != 1)
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send DPD request. Expect disconnect\n"));

		/* last_dpd will just have been set */
		vpninfo->dtls_times.last_tx = vpninfo->dtls_times.last_dpd;
		work_done = 1;
		break;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->outgoing_queue.head)
			break;

		vpn_progress(vpninfo, PRG_DEBUG, _("Send DTLS Keepalive\n"));

		magic_pkt = AC_PKT_KEEPALIVE;
		if (ssl_nonblock_write(vpninfo, 1, &magic_pkt, 1) != 1)
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send keepalive request. Expect disconnect\n"));
		time(&vpninfo->dtls_times.last_tx);
		work_done = 1;
		break;

	case KA_NONE:
		;
	}

	/* Service outgoing packet queue */
	unmonitor_write_fd(vpninfo, dtls);
	while (vpninfo->outgoing_queue.head) {
		struct pkt *this = dequeue_packet(&vpninfo->outgoing_queue);
		struct pkt *send_pkt = this;
		int ret;

		/* If TOS optname is set, we want to copy the TOS/TCLASS header
		   to the outer UDP packet */
		if (vpninfo->dtls_tos_optname)
			udp_tos_update(vpninfo, this);

		/* One byte of header */
		this->cstp.hdr[7] = AC_PKT_DATA;

		/* We can compress into vpninfo->deflate_pkt unless CSTP
		 * currently has a compressed packet pending — which it
		 * shouldn't if DTLS is active. */
		if (vpninfo->dtls_compr &&
		    vpninfo->current_ssl_pkt != vpninfo->deflate_pkt &&
		    !compress_packet(vpninfo, vpninfo->dtls_compr, this)) {
				send_pkt = vpninfo->deflate_pkt;
				send_pkt->cstp.hdr[7] = AC_PKT_COMPRESSED;
		}

		ret = ssl_nonblock_write(vpninfo, 1, &send_pkt->cstp.hdr[7], send_pkt->len + 1);
		if (ret <= 0) {
			/* Zero is -EAGAIN; just requeue. dtls_nonblock_write()
			 * will have added the socket to the poll wfd list. */
			requeue_packet(&vpninfo->outgoing_queue, this);
			if (ret < 0) {
				/* If it's a real error, kill the DTLS connection so
				   the requeued packet will be sent over SSL */
				dtls_reconnect(vpninfo, timeout);
				work_done = 1;
			}
			return work_done;
		}
		time(&vpninfo->dtls_times.last_tx);
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sent DTLS packet of %d bytes; DTLS send returned %d\n"),
			     this->len, ret);
		free_pkt(vpninfo, this);
	}

	return work_done;
}

/* This symbol is missing in glibc < 2.22 (bug 18643). */
#if defined(__linux__) && !defined(HAVE_IPV6_PATHMTU)
# define HAVE_IPV6_PATHMTU 1
# define IPV6_PATHMTU 61
#endif

#define PKT_INTERVAL_MS 50

/* Performs a binary search to detect MTU.
 * @buf: is preallocated with MTU size
 *
 * Returns: new MTU or 0
 */
static int probe_mtu(struct openconnect_info *vpninfo, unsigned char *buf)
{
	int max, min, cur, ret, absolute_min, last;
	int tries = 0; /* Number of loops in bin search - includes resends */
	uint32_t id, id_len;
	struct timeval start_tv, now_tv, last_tv;

	absolute_min = 576;
	if (vpninfo->ip_info.addr6)
		absolute_min = 1280;

	/* We'll assume that it is at least functional, and permits the bare
	 * minimum MTU for the protocol(s) it transports. All else is mad. */
	min = absolute_min;

	/* First send a probe at the configured maximum. Most of the time, this
	   one will probably work. */
	last = cur = max = vpninfo->ip_info.mtu;

	if (max <= min)
		goto fail;

	/* Generate unique ID */
	if (openconnect_random(&id, sizeof(id)) < 0)
		goto fail;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Initiating MTU detection (min=%d, max=%d)\n"), min, max);

	gettimeofday(&start_tv, NULL);
	last_tv = start_tv;

	while (1) {
		int wait_ms;

#ifdef HAVE_IPV6_PATHMTU
		if (vpninfo->peer_addr->sa_family == AF_INET6) {
			struct ip6_mtuinfo mtuinfo;
			socklen_t len = sizeof(mtuinfo);
			int newmax;

			if (getsockopt(vpninfo->dtls_fd, IPPROTO_IPV6, IPV6_PATHMTU, &mtuinfo, &len) >= 0) {
				newmax = mtuinfo.ip6m_mtu;
				if (newmax > 0) {
					newmax = dtls_set_mtu(vpninfo, newmax) - /*ipv6*/40 - /*udp*/20 - /*oc dtls*/1;
					if (absolute_min > newmax)
						goto fail;
					if (max > newmax)
						max = newmax;
					if (cur > newmax)
						cur = newmax;
				}
			}
		}
#endif

		buf[0] = AC_PKT_DPD_OUT;
		id_len = id + cur;
		memcpy(&buf[1], &id_len, sizeof(id_len));

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending MTU DPD probe (%u bytes)\n"), cur);
		ret = openconnect_dtls_write(vpninfo, buf, cur + 1);
		if (ret != cur + 1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send DPD request (%d %d)\n"), cur, ret);
			if (cur == max) {
				max = --cur;
				if (cur >= absolute_min)
					continue;
			}
			goto fail;
		}
		if (last == cur)
			tries++;
		else {
			tries = 0;
			last = cur;
		}

		memset(buf, 0, sizeof(id)+1);
	keep_waiting:
		gettimeofday(&now_tv, NULL);

		if (now_tv.tv_sec > start_tv.tv_sec + 10) {
			if (absolute_min == min) {
				/* Hm, we never got *anything* back successfully? */
				vpn_progress(vpninfo, PRG_ERR,
				             _("Too long time in MTU detect loop; assuming negotiated MTU.\n"));
				goto fail;
			} else {
				vpn_progress(vpninfo, PRG_ERR,
				             _("Too long time in MTU detect loop; MTU set to %d.\n"), min);
				ret = min;
				goto out;
			}
		}


		wait_ms = PKT_INTERVAL_MS -
			((now_tv.tv_sec - last_tv.tv_sec) * 1000) -
			((now_tv.tv_usec - last_tv.tv_usec) / 1000);
		if (wait_ms <= 0 || wait_ms > PKT_INTERVAL_MS)
			wait_ms = PKT_INTERVAL_MS;

		ret = openconnect_dtls_read(vpninfo, buf, max+1, wait_ms);
		if (ret > 0 && (buf[0] != AC_PKT_DPD_RESP || !memcpy(&id_len, &buf[1], sizeof(id_len)) ||
				id_len != id + ret - 1)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received unexpected packet (%.2x) in MTU detection; skipping.\n"), (unsigned)buf[0]);
			goto keep_waiting;
		}

		if (ret == -ETIMEDOUT) {
			if (tries >= 6) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("No response to size %u after %d tries; declare MTU is %u\n"),
					     last, tries, min);
				ret = min;
				goto out;
			}
		} else if (ret < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to recv DPD request (%d)\n"), ret);
			goto fail;
		} else if (ret > 0) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received MTU DPD probe (%u bytes)\n"), ret - 1);
			ret--;
			tries = 0;
		}

		if (ret == max)
			goto out;

		if (ret > min) {
			min = ret;
			if (min >= last) {
				cur = (min + max + 1) / 2;
			} else {
				cur = (min + last + 1) / 2;
			}
		} else {
			cur = (min + last + 1) / 2;
		}
	}
 fail:
	ret = 0;
 out:
	return ret;
}



void dtls_detect_mtu(struct openconnect_info *vpninfo)
{
	int mtu;
	int prev_mtu = vpninfo->ip_info.mtu;
	unsigned char *buf;

	if (vpninfo->proto->proto != PROTO_ANYCONNECT)
		return;

	if (vpninfo->ip_info.mtu < 1 + sizeof(uint32_t))
		return;

	/* detect MTU */
	buf = calloc(1, 1 + vpninfo->ip_info.mtu);
	if (!buf) {
		vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
		return;
	}

	mtu = probe_mtu(vpninfo, buf);
	if (mtu == 0)
		goto skip_mtu;

	vpninfo->ip_info.mtu = mtu;
	if (prev_mtu != vpninfo->ip_info.mtu) {
		vpn_progress(vpninfo, PRG_INFO,
		     _("Detected MTU of %d bytes (was %d)\n"), vpninfo->ip_info.mtu, prev_mtu);
	} else {
		vpn_progress(vpninfo, PRG_DEBUG,
		     _("No change in MTU after detection (was %d)\n"), prev_mtu);
	}

 skip_mtu:
	free(buf);
}
