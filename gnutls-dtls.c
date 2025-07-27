
/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2016 Intel Corporation.
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

#include "gnutls.h"

#include <gnutls/dtls.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if GNUTLS_VERSION_NUMBER < 0x030400
# define GNUTLS_CIPHER_CHACHA20_POLY1305 23
#endif

#if GNUTLS_VERSION_NUMBER >= 0x030801 && !defined(GNUTLS_NO_EXTENSIONS)
/* XX: GNUTLS_NO_EXTENSIONS was renamed in GnuTLS v3.8.1. A
 * backwards-compatibility shim was added in a subsequent commit, but
 * not yet released.
 */
# define GNUTLS_NO_EXTENSIONS GNUTLS_NO_DEFAULT_EXTENSIONS
#endif

/* sets the DTLS MTU and returns the actual tunnel MTU */
unsigned dtls_set_mtu(struct openconnect_info *vpninfo, unsigned mtu)
{
	gnutls_dtls_set_mtu(vpninfo->dtls_ssl, mtu);
	return gnutls_dtls_get_data_mtu(vpninfo->dtls_ssl);
}

struct {
	const char *name;
	gnutls_protocol_t version;
	gnutls_cipher_algorithm_t cipher;
	gnutls_kx_algorithm_t kx;
	gnutls_mac_algorithm_t mac;
	const char *prio;
	const char *min_gnutls_version;
	int cisco_dtls12;
} gnutls_dtls_ciphers[] = {
	{ "DHE-RSA-AES128-SHA", GNUTLS_DTLS0_9, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_DHE_RSA, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-128-CBC:+SHA1:+DHE-RSA:+SIGN-ALL:%COMPAT", "3.0.0" },
	{ "DHE-RSA-AES256-SHA", GNUTLS_DTLS0_9, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_DHE_RSA, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-256-CBC:+SHA1:+DHE-RSA:+SIGN-ALL:%COMPAT", "3.0.0" },
	{ "AES128-SHA", GNUTLS_DTLS0_9, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_RSA, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-128-CBC:+SHA1:+RSA:+SIGN-ALL:%COMPAT", "3.0.0" },
	{ "AES256-SHA", GNUTLS_DTLS0_9, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_RSA, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-256-CBC:+SHA1:+RSA:+SIGN-ALL:%COMPAT", "3.0.0" },
	{ "DES-CBC3-SHA", GNUTLS_DTLS0_9, GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_RSA, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+3DES-CBC:+SHA1:+RSA:+SIGN-ALL:%COMPAT", "3.0.0" },
	{ "OC-DTLS1_2-AES128-GCM", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_128_GCM, GNUTLS_KX_RSA, GNUTLS_MAC_AEAD,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-128-GCM:+AEAD:+RSA:%COMPAT:+SIGN-ALL", "3.2.7" },
	{ "OC-DTLS1_2-AES256-GCM", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_256_GCM, GNUTLS_KX_RSA, GNUTLS_MAC_AEAD,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-256-GCM:+AEAD:+RSA:%COMPAT:+SIGN-ALL", "3.2.7" },
	{ "OC2-DTLS1_2-CHACHA20-POLY1305", GNUTLS_DTLS1_2, GNUTLS_CIPHER_CHACHA20_POLY1305, GNUTLS_KX_PSK, GNUTLS_MAC_AEAD,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+CHACHA20-POLY1305:+AEAD:+PSK:%COMPAT:+SIGN-ALL", "3.4.8" },
	/* Cisco X-DTLS12-CipherSuite: values */
	{ "DHE-RSA-AES128-SHA", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_DHE_RSA, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-128-CBC:+SHA1:+DHE-RSA:+SIGN-ALL:%COMPAT", "3.0.0", 1 },
	{ "DHE-RSA-AES256-SHA", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_DHE_RSA, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-256-CBC:+SHA1:+DHE-RSA:+SIGN-ALL:%COMPAT", "3.0.0", 1 },
	{ "AES128-SHA", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_RSA, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-128-CBC:+SHA1:+RSA:+SIGN-ALL:%COMPAT", "3.0.0", 1 },
	{ "AES256-SHA", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_RSA, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-256-CBC:+SHA1:+RSA:+SIGN-ALL:%COMPAT", "3.0.0", 1 },
	{ "ECDHE-RSA-AES256-GCM-SHA384", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_256_GCM, GNUTLS_KX_ECDHE_RSA, GNUTLS_MAC_AEAD,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-256-GCM:+AEAD:+ECDHE-RSA:+SIGN-ALL:%COMPAT", "3.2.7", 1 },
	{ "ECDHE-RSA-AES128-GCM-SHA256", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_128_GCM, GNUTLS_KX_ECDHE_RSA, GNUTLS_MAC_AEAD,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-128-GCM:+AEAD:+ECDHE-RSA:+SIGN-ALL:%COMPAT", "3.2.7", 1 },
	{ "AES128-GCM-SHA256", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_128_GCM, GNUTLS_KX_RSA, GNUTLS_MAC_AEAD,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-128-GCM:+AEAD:+RSA:+SIGN-ALL:%COMPAT", "3.2.7", 1 },
	{ "AES256-GCM-SHA384", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_256_GCM, GNUTLS_KX_RSA, GNUTLS_MAC_AEAD,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-256-GCM:+AEAD:+RSA:+SIGN-ALL:%COMPAT", "3.2.7", 1 },
	/* NB. We agreed that any new cipher suites probably shouldn't use
	 * Cisco's session resume hack (which ties us to a specific version
	 * of DTLS). Instead, we'll use GNUTLS_KX_PSK and let it negotiate
	 * the session properly. We might want to wait for
	 * draft-jay-tls-psk-identity-extension before we do that. */
};

#if GNUTLS_VERSION_NUMBER < 0x030009
void gather_dtls_ciphers(struct openconnect_info *vpninfo, struct oc_text_buf *buf,
			 struct oc_text_buf *buf12)
{
	int i, first = 1;

	for (i = 0; i < ARRAY_SIZE(gnutls_dtls_ciphers); i++) {
		if (!gnutls_dtls_ciphers[i].cisco_dtls12 &&
		    gnutls_check_version(gnutls_dtls_ciphers[i].min_gnutls_version)) {
			buf_append(buf, "%s%s", first ? "" : ":",
				   gnutls_dtls_ciphers[i].name);
			first = 0;
		}
	}
}
#else
void gather_dtls_ciphers(struct openconnect_info *vpninfo, struct oc_text_buf *buf,
			 struct oc_text_buf *buf12)
{
	/* only enable the ciphers that would have been negotiated in the TLS channel */
	unsigned i, j;
	int ret;
	unsigned idx;
	gnutls_cipher_algorithm_t cipher;
	gnutls_mac_algorithm_t mac;
	gnutls_priority_t cache;
	uint32_t used = 0;

	buf_append(buf, "PSK-NEGOTIATE");

	ret = gnutls_priority_init(&cache, vpninfo->ciphersuite_config, NULL);
	if (ret < 0) {
		buf->error = -EIO;
		return;
	}

	for (j=0; ; j++) {
		ret = gnutls_priority_get_cipher_suite_index(cache, j, &idx);
		if (ret == GNUTLS_E_UNKNOWN_CIPHER_SUITE)
			continue;
		else if (ret < 0)
			break;

		if (gnutls_cipher_suite_info(idx, NULL, NULL, &cipher, &mac, NULL) != NULL) {
			for (i = 0; i < ARRAY_SIZE(gnutls_dtls_ciphers); i++) {
				if (used & (1 << i))
					continue;
				if (gnutls_dtls_ciphers[i].mac == mac && gnutls_dtls_ciphers[i].cipher == cipher) {
					/* This cipher can be supported. Decide whether which list it lives
					 * in. Cisco's DTLSv1.2 options need to go into a separate
					 * into a separate X-DTLS12-CipherSuite header for some reason... */
					struct oc_text_buf *list;

					if (gnutls_dtls_ciphers[i].cisco_dtls12)
						list = buf12;
					else
						list = buf;

					if (list && list->pos)
						buf_append(list, ":%s", gnutls_dtls_ciphers[i].name);
					else
						buf_append(list, "%s", gnutls_dtls_ciphers[i].name);

					used |= (1 << i);
					break;
				}
			}
		}
	}
	gnutls_priority_deinit(cache);
}
#endif

/* This enables a DTLS protocol negotiation. The new negotiation is as follows:
 *
 * If the client's X-DTLS-CipherSuite contains the "PSK-NEGOTIATE" keyword,
 * the server will reply with "X-DTLS-CipherSuite: PSK-NEGOTIATE" and will
 * enable DTLS-PSK negotiation on the DTLS channel. This allows the protocol
 * to use new DTLS versions, as well as new DTLS ciphersuites, as long as
 * they are also permitted by the system crypto policy in use.
 *
 * That change still requires to client to pretend it is resuming by setting
 * in the TLS ClientHello the session ID provided by the X-DTLS-Session-ID
 * header. That is, because there is no TLS extension we can use to set an
 * identifier in the client hello (draft-jay-tls-psk-identity-extension
 * could be used in the future). The session is not actually resumed.
 */
static int start_dtls_psk_handshake(struct openconnect_info *vpninfo, gnutls_session_t dtls_ssl)
{
	gnutls_datum_t key;
	struct oc_text_buf *prio;
	int err;

	if (!vpninfo->https_sess) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("Deferring DTLS resumption until CSTP generates a PSK\n"));
		return -EAGAIN;
	}

	prio = buf_alloc();
	buf_append(prio, "%s:-VERS-TLS-ALL:+VERS-DTLS-ALL:-KX-ALL:+PSK", vpninfo->ciphersuite_config);
	if (buf_error(prio)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to generate DTLS priority string\n"));
		return buf_free(prio);
	}


	err = gnutls_priority_set_direct(dtls_ssl, prio->data, NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set DTLS priority: '%s': %s\n"),
			     prio->data, gnutls_strerror(err));
		goto fail;
	}

	/* set our session identifier match the application ID; we do that in addition
	 * to the extension which contains the same information in order to deprecate
	 * the latter. The reason is that the session ID field is a field not used
	 * with TLS1.3 (and DTLS1.3), and as such we can rely on it being available to
	 * us, while avoiding a custom extension which requires standardization.
	 */
	if (vpninfo->dtls_app_id_size > 0) {
		gnutls_datum_t id = {vpninfo->dtls_app_id, vpninfo->dtls_app_id_size};

		gnutls_session_set_id(dtls_ssl, &id);
	}

	/* set PSK credentials */
	err = gnutls_psk_allocate_client_credentials(&vpninfo->psk_cred);
	if (err < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to allocate credentials: %s\n"),
			     gnutls_strerror(err));
		goto fail;
	}

	/* generate key */
	/* we should have used gnutls_prf_rfc5705() but since we don't use
	 * the RFC5705 context, the output is identical with gnutls_prf(). The
	 * latter is available in much earlier versions of gnutls. */
	err = gnutls_prf(vpninfo->https_sess, PSK_LABEL_SIZE, PSK_LABEL,
			 0, 0, 0, PSK_KEY_SIZE, (char *)vpninfo->dtls_secret);
	if (err < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to generate DTLS key: %s\n"),
			     gnutls_strerror(err));
		goto fail;
	}

	key.data = vpninfo->dtls_secret;
	key.size = PSK_KEY_SIZE;

	/* we set an arbitrary username here. We cannot take advantage of the
	 * username field to send our ID to the server, since the username in TLS-PSK
	 * is sent after the server-hello. */
	err = gnutls_psk_set_client_credentials(vpninfo->psk_cred, "psk", &key, 0);
	if (err < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set DTLS key: %s\n"),
			     gnutls_strerror(err));
		goto fail;
	}

	err = gnutls_credentials_set(dtls_ssl, GNUTLS_CRD_PSK, vpninfo->psk_cred);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set DTLS PSK credentials: %s\n"),
			     gnutls_strerror(err));
		goto fail;
	}

	buf_free(prio);
	return 0;

 fail:
	buf_free(prio);
	gnutls_psk_free_client_credentials(vpninfo->psk_cred);
	vpninfo->psk_cred = NULL;
	return -EINVAL;
}

static int start_dtls_resume_handshake(struct openconnect_info *vpninfo, gnutls_session_t dtls_ssl)
{
	gnutls_datum_t master_secret, session_id;
	int err;
	int cipher;

	for (cipher = 0; cipher < ARRAY_SIZE(gnutls_dtls_ciphers); cipher++) {
		if (gnutls_dtls_ciphers[cipher].cisco_dtls12 != vpninfo->dtls12 ||
		    gnutls_check_version(gnutls_dtls_ciphers[cipher].min_gnutls_version) == NULL)
			continue;
		if (!strcmp(vpninfo->dtls_cipher, gnutls_dtls_ciphers[cipher].name))
			goto found_cipher;
	}
	vpn_progress(vpninfo, PRG_ERR, _("Unknown DTLS parameters for requested CipherSuite '%s'\n"),
		     vpninfo->dtls_cipher);
	return -EINVAL;

 found_cipher:
	err = gnutls_priority_set_direct(dtls_ssl,
					 gnutls_dtls_ciphers[cipher].prio,
					 NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set DTLS priority: '%s': %s\n"),
			     gnutls_dtls_ciphers[cipher].prio, gnutls_strerror(err));
		return -EINVAL;
	}

	gnutls_record_disable_padding(dtls_ssl);
	master_secret.data = vpninfo->dtls_secret;
	master_secret.size = sizeof(vpninfo->dtls_secret);
	session_id.data = vpninfo->dtls_session_id;
	session_id.size = sizeof(vpninfo->dtls_session_id);
	err = gnutls_session_set_premaster(dtls_ssl, GNUTLS_CLIENT, gnutls_dtls_ciphers[cipher].version,
					   gnutls_dtls_ciphers[cipher].kx, gnutls_dtls_ciphers[cipher].cipher,
					   gnutls_dtls_ciphers[cipher].mac, GNUTLS_COMP_NULL,
					   &master_secret, &session_id);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set DTLS session parameters: %s\n"),
			     gnutls_strerror(err));
		return -EINVAL;
	}

	return 0;
}

static int start_dtls_anon_handshake(struct openconnect_info *vpninfo, gnutls_session_t dtls_ssl)
{
	char *prio = vpninfo->ciphersuite_config;
	int ret;

	/*
	 * Use the same cred store as for the HTTPS session. That has
	 * our own verify_peer() callback installed, and will validate
	 * just like we do for the HTTPS service.
	 *
	 * There is also perhaps a case to be made for *only* accepting
	 * precisely the same cert that we get from the HTTPS service,
	 * but we tried that for EAP-TTLS in the Pulse protocol and the
	 * theory was disproven, so we ended up doing this there too.
	 */
	gnutls_credentials_set(dtls_ssl, GNUTLS_CRD_CERTIFICATE, vpninfo->https_cred);

	/* The F5 BIG-IP server before v16, will crap itself if we
	 * even *try* to do DTLSv1.2 */
	if (!vpninfo->dtls12 &&
	    asprintf(&prio, "%s:-VERS-DTLS1.2:+VERS-DTLS1.0",
		     vpninfo->ciphersuite_config) < 0)
		return -ENOMEM;

	ret = gnutls_priority_set_direct(dtls_ssl, prio ? : vpninfo->ciphersuite_config,
					 NULL);
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set DTLS priority: '%s': %s\n"),
			     prio, gnutls_strerror(ret));
	}

	if (prio != vpninfo->ciphersuite_config)
		free(prio);

	return ret;
}

/*
 * GnuTLS version between 3.6.3 and 3.6.12 send zero'ed ClientHello. Make sure
 * we are not hitting that bug. Adapted from:
 * https://gitlab.com/gnutls/gnutls/-/blob/3.6.13/tests/tls_hello_random_value.c
 */
static int check_client_hello_random(gnutls_session_t ttls_sess, unsigned int type,
				     unsigned hook, unsigned int incoming, const gnutls_datum_t *msg)
{
	unsigned non_zero = 0, i;
	struct openconnect_info *vpninfo = (struct openconnect_info *)gnutls_session_get_ptr(ttls_sess);

	if (type == GNUTLS_HANDSHAKE_CLIENT_HELLO && hook == GNUTLS_HOOK_POST) {
		gnutls_datum_t buf;
		gnutls_session_get_random(ttls_sess, &buf, NULL);
		if (buf.size != 32) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("GnuTLS used %d ClientHello random bytes; this should never happen\n"),
				     buf.size);
			return GNUTLS_E_INVALID_REQUEST;
		}

		for (i = 0; i < buf.size; ++i) {
			if (buf.data[i] != 0) {
				non_zero++;
			}
		}

		/* The GnuTLS bug was that *all* bytes were zero, but as part of the unit test
		 * they also slipped in a coincidental check on how well the random number
		 * generator is behaving. Eight or more zeroes is a bad thing whatever the
		 * reason for it. So we have the same check. */
		if (non_zero <= 8) {
			/* TODO: mention CVE number in log message once it's assigned */
			vpn_progress(vpninfo, PRG_ERR,
			     _("GnuTLS sent insecure ClientHello random. Upgrade to 3.6.13 or newer.\n"));
			return GNUTLS_E_INVALID_REQUEST;
		}
	}

	return 0;
}

int start_dtls_handshake(struct openconnect_info *vpninfo, int dtls_fd)
{
	gnutls_session_t dtls_ssl;
	int err, ret;

	err = gnutls_init(&dtls_ssl, GNUTLS_CLIENT|GNUTLS_DATAGRAM|GNUTLS_NONBLOCK|GNUTLS_NO_EXTENSIONS);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialize DTLS: %s\n"),
			     gnutls_strerror(err));
		return -EINVAL;
	}
	gnutls_session_set_ptr(dtls_ssl, (void *) vpninfo);
	gnutls_transport_set_ptr(dtls_ssl,
				 (gnutls_transport_ptr_t)(intptr_t)dtls_fd);

	if (!vpninfo->dtls_cipher) {
		/* Anonymous DTLS (PPP protocols) */
		ret = start_dtls_anon_handshake(vpninfo, dtls_ssl);
	} else if (!strcmp(vpninfo->dtls_cipher, "PSK-NEGOTIATE")) {
		/* For OpenConnect/ocserv protocol */
		ret = start_dtls_psk_handshake(vpninfo, dtls_ssl);
	} else {
		/* Nonexistent session resume hack (Cisco AnyConnect) */
		ret = start_dtls_resume_handshake(vpninfo, dtls_ssl);
	}

	if (ret) {
		if (ret != -EAGAIN)
			vpninfo->dtls_attempt_period = 0;
		gnutls_deinit(dtls_ssl);
		return ret;
	}

	if (gnutls_check_version_numeric(3,6,3) && !gnutls_check_version_numeric(3,6,13)) {
		gnutls_handshake_set_hook_function(dtls_ssl, GNUTLS_HANDSHAKE_CLIENT_HELLO,
						   GNUTLS_HOOK_POST, check_client_hello_random);
	}


	vpninfo->dtls_ssl = dtls_ssl;
	return 0;
}

int dtls_try_handshake(struct openconnect_info *vpninfo, int *timeout)
{
	int err = gnutls_handshake(vpninfo->dtls_ssl);
	char *str;

	if (!err) {
		if (!vpninfo->dtls_cipher) {
			/* Anonymous DTLS (PPP protocols) will set vpninfo->ip_info.mtu
			 * in PPP negotiation.
			 *
			 * XX: Needs forthcoming overhaul to detect MTU correctly and offer
			 * reasonable MRU values during PPP negotiation.
			 */
			int data_mtu = vpninfo->cstp_basemtu = 1500;
			if (vpninfo->peer_addr->sa_family == IPPROTO_IPV6)
				data_mtu -= 40; /* IPv6 header */
			else
				data_mtu -= 20; /* Legacy IP header */
			data_mtu -= 8; /* UDP header */
			dtls_set_mtu(vpninfo, data_mtu);
		} else if (!strcmp(vpninfo->dtls_cipher, "PSK-NEGOTIATE")) {
			/* For PSK-NEGOTIATE (OpenConnect/ocserv protocol)
			 * we have to determine the tunnel MTU
			 * for ourselves based on the base MTU */
			int data_mtu = vpninfo->cstp_basemtu;
			if (vpninfo->peer_addr->sa_family == IPPROTO_IPV6)
				data_mtu -= 40; /* IPv6 header */
			else
				data_mtu -= 20; /* Legacy IP header */
			data_mtu -= 8; /* UDP header */
			if (data_mtu < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Peer MTU %d too small to allow DTLS\n"),
					     vpninfo->cstp_basemtu);
				goto nodtls;
			}
			/* Reduce it by one because that's the payload header *inside*
			 * the encryption */
			data_mtu = dtls_set_mtu(vpninfo, data_mtu) - 1;
			if (data_mtu < vpninfo->ip_info.mtu) {
				vpn_progress(vpninfo, PRG_INFO,
					     _("DTLS MTU reduced to %d\n"),
					     data_mtu);
				vpninfo->ip_info.mtu = data_mtu;
			}
		} else {
			/* Nonexistent session resume hack (Cisco AnyConnect) */
			if (!gnutls_session_is_resumed(vpninfo->dtls_ssl)) {
				/* Someone attempting to hijack the DTLS session?
				 * A real server would never allow a full session
				 * establishment instead of the agreed resume. */
				vpn_progress(vpninfo, PRG_ERR,
					     _("DTLS session resume failed; possible MITM attack. Disabling DTLS.\n"));
			nodtls:
				dtls_close(vpninfo);
				vpninfo->dtls_attempt_period = 0;
				vpninfo->dtls_state = DTLS_DISABLED;
				return -EIO;
			}

			/* Make sure GnuTLS's idea of the MTU is sufficient to take
			   a full VPN MTU (with 1-byte header) in a data record. */
			err = gnutls_dtls_set_data_mtu(vpninfo->dtls_ssl, vpninfo->ip_info.mtu + 1);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to set DTLS MTU: %s\n"),
					     gnutls_strerror(err));
				goto error;
			}
		}

		vpninfo->dtls_state = DTLS_CONNECTED;
		str = get_gnutls_cipher(vpninfo->dtls_ssl);
		if (str) {
			const char *c;
			vpn_progress(vpninfo, PRG_INFO,
				     _("Established DTLS connection (using GnuTLS). Ciphersuite %s.\n"),
				     str);
			gnutls_free(str);
			c = openconnect_get_dtls_compression(vpninfo);
			if (c) {
				vpn_progress(vpninfo, PRG_INFO,
					     _("DTLS connection compression using %s.\n"), c);
			}
		}

		vpninfo->dtls_times.last_rekey = vpninfo->dtls_times.last_rx =
			vpninfo->dtls_times.last_tx = time(NULL);

		dtls_detect_mtu(vpninfo);
		/* XXX: For OpenSSL we explicitly prevent retransmits here. */
		return 0;
	}

	if (err == GNUTLS_E_AGAIN || err == GNUTLS_E_INTERRUPTED) {
		int quit_time = vpninfo->new_dtls_started + 12 - time(NULL);
		if (quit_time > 0) {
			if (timeout) {
				unsigned next_resend = gnutls_dtls_get_timeout(vpninfo->dtls_ssl);
				if (next_resend && *timeout > next_resend)
					*timeout = next_resend;

				if (*timeout > quit_time * 1000)
					*timeout = quit_time * 1000;
			}
			return 0;
		}
		vpn_progress(vpninfo, PRG_DEBUG, _("DTLS handshake timed out\n"));
	}

	vpn_progress(vpninfo, PRG_ERR, _("DTLS handshake failed: %s\n"),
		     gnutls_strerror(err));
	if (err == GNUTLS_E_PUSH_ERROR)
		vpn_progress(vpninfo, PRG_ERR,
			     _("(Is a firewall preventing you from sending UDP packets?)\n"));
 error:
	dtls_close(vpninfo);

	vpninfo->dtls_state = DTLS_SLEEPING;
	time(&vpninfo->new_dtls_started);
	if (timeout && *timeout > vpninfo->dtls_attempt_period * 1000)
		*timeout = vpninfo->dtls_attempt_period * 1000;
	return -EINVAL;
}

void dtls_shutdown(struct openconnect_info *vpninfo)
{
	dtls_close(vpninfo);
}

void dtls_ssl_free(struct openconnect_info *vpninfo)
{
	gnutls_deinit(vpninfo->dtls_ssl);

	if (vpninfo->psk_cred) {
		gnutls_psk_free_client_credentials(vpninfo->psk_cred);
		vpninfo->psk_cred = NULL;
	}
}
