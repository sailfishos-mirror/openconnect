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
#ifndef _WIN32
/* for setgroups() */
# include <sys/types.h>
# include <grp.h>
#endif

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

int queue_new_packet(struct openconnect_info *vpninfo,
		     struct pkt_q *q, void *buf, int len)
{
	struct pkt *new = alloc_pkt(vpninfo, len);
	if (!new)
		return -ENOMEM;

	new->len = len;
	new->next = NULL;
	memcpy(new->data, buf, len);
	queue_packet(q, new);
	return 0;
}

/* This is here because it's generic and hence can't live in either of the
   tun*.c files for specific platforms */
int tun_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable, int did_work)
{
	struct pkt *this;
	int work_done = 0;

	if (readable && read_fd_monitored(vpninfo, tun)) {
		struct pkt *out_pkt = vpninfo->tun_pkt;
		while (1) {
			int len = vpninfo->ip_info.mtu;

			if (!out_pkt) {
				out_pkt = alloc_pkt(vpninfo, len + vpninfo->pkt_trailer);
				if (!out_pkt) {
					vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
					break;
				}
				out_pkt->len = len;
			}

			if (os_read_tun(vpninfo, out_pkt))
				break;

			vpninfo->stats.tx_pkts++;
			vpninfo->stats.tx_bytes += out_pkt->len;
			work_done = 1;

			if (queue_packet(&vpninfo->outgoing_queue, out_pkt) +
			    vpninfo->tcp_control_queue.count >= vpninfo->max_qlen) {
				out_pkt = NULL;
				unmonitor_read_fd(vpninfo, tun);
				break;
			}
			out_pkt = NULL;
		}
		vpninfo->tun_pkt = out_pkt;
	} else if (vpninfo->outgoing_queue.count + vpninfo->tcp_control_queue.count < vpninfo->max_qlen) {
		monitor_read_fd(vpninfo, tun);
	}

	while ((this = dequeue_packet(&vpninfo->incoming_queue))) {

		unmonitor_write_fd(vpninfo, tun);

		if (os_write_tun(vpninfo, this)) {
			requeue_packet(&vpninfo->incoming_queue, this);
			break;
		}

		vpninfo->stats.rx_pkts++;
		vpninfo->stats.rx_bytes += this->len;

		free_pkt(vpninfo, this);
	}
	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

static int setup_tun_device(struct openconnect_info *vpninfo)
{
	int ret;

	if (vpninfo->setup_tun) {
		vpninfo->setup_tun(vpninfo->cbdata);
		if (tun_is_up(vpninfo))
			return 0;
	}

#ifndef _WIN32
	if (vpninfo->use_tun_script) {
		ret = openconnect_setup_tun_script(vpninfo, vpninfo->vpnc_script);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Set up tun script failed\n"));
			return ret;
		}
	} else
#endif
	ret = openconnect_setup_tun_device(vpninfo, vpninfo->vpnc_script, vpninfo->ifname);
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR, _("Set up tun device failed\n"));
		if (!vpninfo->quit_reason)
			vpninfo->quit_reason = "Set up tun device failed";
		return ret;
	}

#if !defined(_WIN32) && !defined(__native_client__)
	if (vpninfo->uid != getuid()) {
		if (setgid(vpninfo->gid)) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to set gid %ld: %s\n"),
				     (long)vpninfo->gid, strerror(errno));
			return -EPERM;
		}

		if (setgroups(1, &vpninfo->gid)) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to set groups to %ld: %s\n"),
				     (long)vpninfo->gid, strerror(errno));
			return -EPERM;
		}

		if (setuid(vpninfo->uid)) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to set uid %ld: %s\n"),
				     (long)vpninfo->uid, strerror(errno));
			return -EPERM;
		}
	}
#endif
	return 0;
}

/* Return value:
 *  = 0, when successfully paused (may call again)
 *  = -EINTR, if aborted locally via OC_CMD_CANCEL
 *  = -ECONNABORTED, if aborted locally via OC_CMD_DETACH
 *  = -EPIPE, if the remote end explicitly terminated the session
 *  = -EPERM, if the gateway sent 401 Unauthorized (cookie expired)
 *  < 0, for any other error
 */
int openconnect_mainloop(struct openconnect_info *vpninfo,
			 int reconnect_timeout,
			 int reconnect_interval)
{
	int ret = 0;
	int tun_r = 1, udp_r = 1, tcp_r = 1;
#ifdef HAVE_VHOST
	int vhost_r = 0;
#endif

	vpninfo->reconnect_timeout = reconnect_timeout;
	vpninfo->reconnect_interval = reconnect_interval;

	if (vpninfo->cmd_fd >= 0) {
		monitor_fd_new(vpninfo, cmd);
		monitor_read_fd(vpninfo, cmd);
	}

	while (!vpninfo->quit_reason) {
		int did_work = 0;
		int timeout;
#ifdef _WIN32
		HANDLE events[4];
		int nr_events = 0;
#else
		struct timeval tv;
		fd_set rfds, wfds, efds;
#endif

		/* If tun is not up, loop more often to detect
		 * a DTLS timeout (due to a firewall block) as soon. */
		if (tun_is_up(vpninfo))
			timeout = INT_MAX;
		else
			timeout = 1000;

		if (!tun_is_up(vpninfo)) {
			if (vpninfo->delay_tunnel_reason) {
				vpn_progress(vpninfo, PRG_TRACE, _("Delaying tunnel with reason: %s\n"),
					     vpninfo->delay_tunnel_reason);
				/* XX: don't let this spin forever */
				vpninfo->delay_tunnel_reason = NULL;
			} else {
				/* No DTLS, or DTLS failed; setup TUN device unconditionally */
				ret = setup_tun_device(vpninfo);
				if (ret)
					break;
			}
		}

		if (vpninfo->dtls_state > DTLS_DISABLED) {
			ret = vpninfo->proto->udp_mainloop(vpninfo, &timeout, udp_r);
			if (vpninfo->quit_reason)
				break;
			did_work += ret;
		}

		ret = vpninfo->proto->tcp_mainloop(vpninfo, &timeout, tcp_r);
		if (vpninfo->quit_reason)
			break;
		did_work += ret;


		/* Tun must be last because it will set/clear its bit
		   in the select_rfds according to the queue length */
		if (!tun_is_up(vpninfo)) {
			struct pkt *this;
			/* no tun yet; clear any queued packets */
			while ((this = dequeue_packet(&vpninfo->incoming_queue)))
				free_pkt(vpninfo, this);
#ifdef HAVE_VHOST
		} else if (vpninfo->vhost_fd >= 0) {
			did_work += vhost_tun_mainloop(vpninfo, &timeout, vhost_r, did_work);
			/* If it returns zero *then* it will have read the eventfd
			 * and there's no need to do so again until we poll again. */
			if (!did_work)
				vhost_r = 0;
#endif
		} else {
			did_work += tun_mainloop(vpninfo, &timeout, tun_r, did_work);
		}
		if (vpninfo->quit_reason)
			break;

		if (vpninfo->need_poll_cmd_fd)
			poll_cmd_fd(vpninfo, 0);

		if (vpninfo->got_cancel_cmd) {
			if (vpninfo->delay_close != NO_DELAY_CLOSE) {
				if (vpninfo->delay_close == DELAY_CLOSE_IMMEDIATE_CALLBACK) {
					vpn_progress(vpninfo, PRG_TRACE, _("Delaying cancel (immediate callback).\n"));
					did_work++;
				} else
					vpn_progress(vpninfo, PRG_TRACE, _("Delaying cancel.\n"));
				/* XX: don't let this spin forever */
				vpninfo->delay_close = NO_DELAY_CLOSE;
			} else if (vpninfo->cancel_type == OC_CMD_CANCEL) {
				vpninfo->quit_reason = "Aborted by caller";
				vpninfo->got_cancel_cmd = 0;
				ret = -EINTR;
				break;
			} else {
				vpninfo->got_cancel_cmd = 0;
				ret = -ECONNABORTED;
				break;
			}
		}

		if (vpninfo->got_pause_cmd) {
			if (vpninfo->delay_close != NO_DELAY_CLOSE) {
				 /* XX: don't let this spin forever */
				if (vpninfo->delay_close == DELAY_CLOSE_IMMEDIATE_CALLBACK) {
					vpn_progress(vpninfo, PRG_TRACE, _("Delaying pause (immediate callback).\n"));
					did_work++;
				} else
					vpn_progress(vpninfo, PRG_TRACE, _("Delaying pause.\n"));
				/* XX: don't let this spin forever */
				vpninfo->delay_close = NO_DELAY_CLOSE;
			} else {
				/* close all connections and wait for the user to call
				   openconnect_mainloop() again */
				openconnect_close_https(vpninfo, 0);
				if (vpninfo->dtls_state > DTLS_DISABLED) {
					vpninfo->proto->udp_close(vpninfo);
					vpninfo->new_dtls_started = 0;
				}

				vpninfo->got_pause_cmd = 0;
				vpn_progress(vpninfo, PRG_INFO, _("Caller paused the connection\n"));

				if (vpninfo->cmd_fd >= 0)
					unmonitor_fd(vpninfo, cmd);

				return 0;
			}
		}

		if (did_work)
			continue;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("No work to do; sleeping for %d ms...\n"), timeout);

#ifdef _WIN32
		if (vpninfo->dtls_monitored) {
			WSAEventSelect(vpninfo->dtls_fd, vpninfo->dtls_event, vpninfo->dtls_monitored);
			events[nr_events++] = vpninfo->dtls_event;
		}
		if (vpninfo->ssl_monitored) {
			WSAEventSelect(vpninfo->ssl_fd, vpninfo->ssl_event, vpninfo->ssl_monitored);
			events[nr_events++] = vpninfo->ssl_event;
		}
		if (vpninfo->cmd_monitored) {
			WSAEventSelect(vpninfo->cmd_fd, vpninfo->cmd_event, vpninfo->cmd_monitored);
			events[nr_events++] = vpninfo->cmd_event;
		}
		if (vpninfo->tun_monitored) {
			events[nr_events++] = vpninfo->tun_rd_overlap.hEvent;
		}
		if (WaitForMultipleObjects(nr_events, events, FALSE, timeout) == WAIT_FAILED) {
			char *errstr = openconnect__win32_strerror(GetLastError());
			vpn_progress(vpninfo, PRG_ERR,
				     _("WaitForMultipleObjects failed: %s\n"),
				     errstr);
			free(errstr);
		}
#else
#ifdef HAVE_EPOLL
		if (vpninfo->epoll_fd >= 0) {
			struct epoll_event evs[5];

			/* During busy periods, monitor_read_fd() and unmonitor_read_fd()
			 * may get called multiple times as we go round and round the
			 * loop and queues get full then have space again. In the past
			 * with the select() loop, that was only a bitflip in the fd_set
			 * and didn't cost much. With epoll() it's actually a system
			 * call, so don't do it every time. Wait until we're about to
			 * sleep, and *then* ensure that we call epoll_ctl() to sync the
			 * set of events that we care about, if it's changed. */
			if (vpninfo->epoll_update) {
				update_epoll_fd(vpninfo, tun);
				update_epoll_fd(vpninfo, ssl);
				update_epoll_fd(vpninfo, cmd);
				update_epoll_fd(vpninfo, dtls);
#ifdef HAVE_VHOST
				update_epoll_fd(vpninfo, vhost_call);
#endif
			}

			tun_r = udp_r = tcp_r = 0;
#ifdef HAVE_VHOST
			vhost_r = 0;
#endif

			int nfds = epoll_wait(vpninfo->epoll_fd, evs, 5, timeout);
			if (nfds < 0) {
				if (errno != EINTR) {
					ret = -errno;
					vpn_perror(vpninfo, _("Failed epoll_wait() in mainloop"));
					break;
				}
				nfds = 0;
			}
			while (nfds--) {
				if (evs[nfds].events & (EPOLLIN|EPOLLERR)) {
					if (evs[nfds].data.fd == vpninfo->tun_fd)
						tun_r = 1;
					else if (evs[nfds].data.fd == vpninfo->ssl_fd)
						tcp_r = 1;
					else if (evs[nfds].data.fd == vpninfo->dtls_fd)
						udp_r = 1;
#ifdef HAVE_VHOST
					else if (evs[nfds].data.fd == vpninfo->vhost_call_fd)
						vhost_r = 1;
#endif
				}
			}
			continue;
		}
#endif
		memcpy(&rfds, &vpninfo->_select_rfds, sizeof(rfds));
		memcpy(&wfds, &vpninfo->_select_wfds, sizeof(wfds));
		memcpy(&efds, &vpninfo->_select_efds, sizeof(efds));

		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;

		if (select(vpninfo->_select_nfds, &rfds, &wfds, &efds, &tv) < 0 &&
		    errno != EINTR) {
			ret = -errno;
			vpn_perror(vpninfo, _("Failed select() in mainloop"));
			break;
		}
#ifdef HAVE_VHOST
		if (vpninfo->vhost_call_fd >= 0)
			vhost_r = FD_ISSET(vpninfo->vhost_call_fd, &rfds);
#endif
		if (vpninfo->tun_fd >= 0)
			tun_r = FD_ISSET(vpninfo->tun_fd, &rfds);
		if (vpninfo->dtls_fd >= 0)
			udp_r = FD_ISSET(vpninfo->dtls_fd, &rfds);
		if (vpninfo->ssl_fd >= 0)
			tcp_r = FD_ISSET(vpninfo->ssl_fd, &rfds);
#endif
	}

	if (vpninfo->quit_reason && vpninfo->proto->vpn_close_session)
		vpninfo->proto->vpn_close_session(vpninfo, vpninfo->quit_reason);

	if (tun_is_up(vpninfo))
		os_shutdown_tun(vpninfo);

	if (vpninfo->cmd_fd >= 0)
		unmonitor_fd(vpninfo, cmd);

	return ret < 0 ? ret : -EIO;
}

int ka_check_deadline(int *timeout, time_t now, time_t due)
{
	if (now >= due)
		return 1;
	if (*timeout > (due - now) * 1000)
		*timeout = (due - now) * 1000;
	return 0;
}

/* Called when the socket is unwritable, to get the deadline for DPD.
   Returns 1 if DPD deadline has already arrived. */
int ka_stalled_action(struct keepalive_info *ka, int *timeout)
{
	time_t now = time(NULL);

	/* We only support the new-tunnel rekey method for now. */
	if (ka->rekey_method != REKEY_NONE &&
	    ka_check_deadline(timeout, now, ka->last_rekey + ka->rekey)) {
		ka->last_rekey = now;
		return KA_REKEY;
	}

	if (ka->dpd &&
	    ka_check_deadline(timeout, now, ka->last_rx + (2 * ka->dpd)))
		return KA_DPD_DEAD;

	return KA_NONE;
}


int keepalive_action(struct keepalive_info *ka, int *timeout)
{
	time_t now = time(NULL);

	if (ka->rekey_method != REKEY_NONE &&
	    ka_check_deadline(timeout, now, ka->last_rekey + ka->rekey)) {
		ka->last_rekey = now;
		return KA_REKEY;
	}

	/* DPD is bidirectional -- PKT 3 out, PKT 4 back */
	if (ka->dpd) {
		time_t due = ka->last_rx + ka->dpd;
		time_t overdue = ka->last_rx + (2 * ka->dpd);

		/* Peer didn't respond */
		if (now > overdue)
			return KA_DPD_DEAD;

		/* If we already have DPD outstanding, don't flood. Repeat by
		   all means, but only after half the DPD period. */
		if (ka->last_dpd > ka->last_rx)
			due = ka->last_dpd + ka->dpd / 2;

		/* We haven't seen a packet from this host for $DPD seconds.
		   Prod it to see if it's still alive */
		if (ka_check_deadline(timeout, now, due)) {
			ka->last_dpd = now;
			return KA_DPD;
		}
	}

	/* Keepalive is just client -> server.
	   If we haven't sent anything for $KEEPALIVE seconds, send a
	   dummy packet (which the server will discard) */
	if (ka->keepalive &&
	    ka_check_deadline(timeout, now, ka->last_tx + ka->keepalive))
		return KA_KEEPALIVE;

	return KA_NONE;
}

int trojan_check_deadline(struct openconnect_info *vpninfo, int *timeout)
{
	time_t now = time(NULL);

	if (vpninfo->trojan_interval &&
	    ka_check_deadline(timeout, now,
			      vpninfo->last_trojan + vpninfo->trojan_interval)) {
		vpninfo->last_trojan = now;
		return 1;
	} else {
		return 0;
	}
}
