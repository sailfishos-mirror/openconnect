/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020 Daniel Lenski
 *
 * Authors: Daniel Lenski <dlenski@gmail.com>
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

#if defined(__linux__)
/* For TCP_INFO */
# include <linux/tcp.h>
/* For IP_MTU */
# include <linux/in.h>
#endif

#define ESP_HEADER_SIZE (4 /* SPI */ + 4 /* sequence number */)
#define ESP_FOOTER_SIZE (1 /* pad length */ + 1 /* next header */)
#define UDP_HEADER_SIZE 8
#define TCP_HEADER_SIZE 20 /* with no options */
#define IPV4_HEADER_SIZE 20
#define IPV6_HEADER_SIZE 40

/* Attempt to measure base MTU to peer, using TCP PMTU or TCP MAXSEG
 */
int measure_base_mtu(struct openconnect_info *vpninfo, int is_udp) {
#if defined(__linux__) && defined(TCP_INFO)
	/* Try to figure out base_mtu (from TCP PMTU), and save TCP MSS for later */
	struct tcp_info ti;
	socklen_t ti_size = sizeof(ti);
	if (!is_udp && !getsockopt(vpninfo->ssl_fd, IPPROTO_TCP, TCP_INFO, &ti, &ti_size)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("TCP_INFO rcv mss %d, snd mss %d, adv mss %d, pmtu %d\n"),
			     ti.tcpi_rcv_mss, ti.tcpi_snd_mss, ti.tcpi_advmss, ti.tcpi_pmtu);

		if (ti.tcpi_pmtu)
			return ti.tcpi_pmtu;
	}
#endif
#ifdef TCP_MAXSEG
	int mss;
	socklen_t mss_size = sizeof(mss);
	if (!is_udp && !getsockopt(vpninfo->ssl_fd, IPPROTO_TCP, TCP_MAXSEG, &mss, &mss_size)) {
		vpn_progress(vpninfo, PRG_DEBUG, _("TCP_MAXSEG %d\n"), mss);

		int base_mtu = mss + TCP_HEADER_SIZE;
		base_mtu += (vpninfo->peer_addr->sa_family == AF_INET6) ? IPV6_HEADER_SIZE : IPV4_HEADER_SIZE;
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("TCP_MAXSEG + TCP_HEADER_SIZE + IPV%d_HEADER_SIZE %d\n"),
			     vpninfo->peer_addr->sa_family == AF_INET6 ? 6 : 4, base_mtu);
		return base_mtu;
	}
#endif
#if defined(__linux__) && defined(IP_MTU)
	int mtu;
	socklen_t mtu_size = sizeof(mtu);
	if (!getsockopt(is_udp ? vpninfo->dtls_fd : vpninfo->ssl_fd, IPPROTO_IP, IP_MTU, &mtu, &mtu_size)) {
		vpn_progress(vpninfo, PRG_DEBUG, _("IP_MTU %d\n"), mtu);
		return mtu;
	}
#endif

	/* XX: Default to existing vpninfo->basemtu value (possibly set via --base-mtu)
	 */
	int default_mtu = vpninfo->basemtu ? : 1280;
	vpn_progress(vpninfo, PRG_DEBUG, _("Can't measure base_mtu for %s socket. Defaulting to %d\n"),
		is_udp ? (vpninfo->proto->udp_protocol ? : "UDP") : "SSL", default_mtu);
	return default_mtu;
}


/* Calculate MTU of a tunnel.
 *
 * is_udp: 1 if outer packet is UDP, 0 if TCP
 * unpadded_overhead: overhead that does not get padded (headers or footers)
 * padded_overhead:   overhead that gets before padding the payload (typically footers)
 * block_size:        block size that payload will be padded to AFTER adding padded overhead
 */

int calculate_mtu(struct openconnect_info *vpninfo, int is_udp,
		  int unpadded_overhead, int padded_overhead, int block_size)
{
	int mtu = vpninfo->reqmtu, base_mtu = vpninfo->basemtu;
	int mss = 0;

	/* Try to figure out base_mtu (from TCP PMTU), and save TCP MSS for later */
#if defined(__linux__) && defined(TCP_INFO)
	if (!mtu) {
		struct tcp_info ti;
		socklen_t ti_size = sizeof(ti);

		if (!getsockopt(vpninfo->ssl_fd, IPPROTO_TCP, TCP_INFO,
				&ti, &ti_size)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("TCP_INFO rcv mss %d, snd mss %d, adv mss %d, pmtu %d\n"),
				     ti.tcpi_rcv_mss, ti.tcpi_snd_mss, ti.tcpi_advmss, ti.tcpi_pmtu);

			/* If base_mtu unknown, use TCP PMTU */
			if (!base_mtu) {
				base_mtu = ti.tcpi_pmtu;
			}

			/* Use largest MSS */
			mss = MAX(ti.tcpi_rcv_mss, ti.tcpi_snd_mss);
			mss = MAX(mss, ti.tcpi_advmss);
		}
	}
#endif
#ifdef TCP_MAXSEG
	if (!mtu && !mss) {
		socklen_t mss_size = sizeof(mss);
		if (!getsockopt(vpninfo->ssl_fd, IPPROTO_TCP, TCP_MAXSEG,
				&mss, &mss_size)) {
			vpn_progress(vpninfo, PRG_DEBUG, _("TCP_MAXSEG %d\n"), mss);
		}
	}
#endif

	/* Default base_mtu needs to be big enough for IPv6 (1280 minimum) */
	if (!base_mtu) {
		/* Default */
		base_mtu = 1406;
	}

	if (base_mtu < 1280)
		base_mtu = 1280;

	vpn_progress(vpninfo, PRG_TRACE, _("Using base_mtu of %d\n"), base_mtu);

        /* base_mtu is now (we hope) the PMTU between our external network interface
	 * and the VPN gateway */

	if (!mtu) {
		if (!is_udp && mss)
			/* MSS already has IP, TCP header size removed */
			mtu = mss;
		else {
			/* remove TCP/UDP, IP headers from base (wire) MTU */
			mtu = base_mtu - (is_udp ? UDP_HEADER_SIZE : TCP_HEADER_SIZE);
			mtu -= (vpninfo->peer_addr->sa_family == AF_INET6) ? IPV6_HEADER_SIZE : IPV4_HEADER_SIZE;
		}
	}

	vpn_progress(vpninfo, PRG_TRACE, _("After removing %s/IPv%d headers, MTU of %d\n"),
		     (is_udp ? "UDP" : "TCP"), vpninfo->peer_addr->sa_family == AF_INET6 ? 6 : 4, mtu);

        /* MTU is now (we hope) the number of payload bytes that can fit in a UDP or
	 * TCP packet exchanged with the VPN gateway. */

	mtu -= unpadded_overhead; /* remove protocol-specific overhead that isn't affected by padding */
	mtu -= mtu % block_size;  /* round down to a multiple of blocksize */
	mtu -= padded_overhead;	  /* remove protocol-specific overhead that contributes to payload padding */

	vpn_progress(vpninfo, PRG_TRACE, _("After removing protocol specific overhead (%d unpadded, %d padded, %d blocksize), MTU of %d\n"),
		     unpadded_overhead, padded_overhead, block_size, mtu);

	return mtu;
}
