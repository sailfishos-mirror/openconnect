/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 * Copyright © 2013 John Morrissey <jwm@horde.net>
 *
 * Authors: David Woodhouse <dwmw2@infradead.org>
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

#if defined(OPENCONNECT_GNUTLS)
#include "gnutls.h"
#endif

#ifdef HAVE_LIBSTOKEN
#include <stoken.h>
#endif

#include <libxml/tree.h>
#include <zlib.h>

#if defined(OPENCONNECT_OPENSSL)
#include <openssl/bio.h>
#endif

#include <unistd.h>
#include <fcntl.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>

struct openconnect_info *openconnect_vpninfo_new(const char *useragent,
						 openconnect_validate_peer_cert_vfn validate_peer_cert,
						 openconnect_write_new_config_vfn write_new_config,
						 openconnect_process_auth_form_vfn process_auth_form,
						 openconnect_progress_vfn progress,
						 void *privdata)
{
	struct openconnect_info *vpninfo = calloc(1, sizeof(*vpninfo));
#ifdef HAVE_ICONV
	char *charset = nl_langinfo(CODESET);
#endif

	if (!vpninfo)
		return NULL;

#ifdef HAVE_ICONV
	if (charset && strcmp(charset, "UTF-8")) {
		vpninfo->ic_utf8_to_legacy = iconv_open(charset, "UTF-8");
		vpninfo->ic_legacy_to_utf8 = iconv_open("UTF-8", charset);
	} else {
		vpninfo->ic_utf8_to_legacy = (iconv_t)-1;
		vpninfo->ic_legacy_to_utf8 = (iconv_t)-1;
	}
#endif
#ifdef HAVE_VHOST
	vpninfo->vhost_fd = vpninfo->vhost_call_fd = vpninfo->vhost_kick_fd = -1;
#endif
#ifndef _WIN32
	vpninfo->tun_fd = -1;
#endif
#if defined(DEFAULT_EXTERNAL_BROWSER)
	vpninfo->external_browser = DEFAULT_EXTERNAL_BROWSER;
#endif
	init_pkt_queue(&vpninfo->free_queue);
	init_pkt_queue(&vpninfo->incoming_queue);
	init_pkt_queue(&vpninfo->outgoing_queue);
	init_pkt_queue(&vpninfo->tcp_control_queue);
	vpninfo->dtls_tos_current = 0;
	vpninfo->dtls_pass_tos = 0;
	vpninfo->ssl_fd = vpninfo->dtls_fd = -1;
	vpninfo->cmd_fd = vpninfo->cmd_fd_write = -1;
	vpninfo->tncc_fd = -1;
	vpninfo->cert_expire_warning = 60 * 86400;
	vpninfo->req_compr = COMPR_STATELESS;
	vpninfo->max_qlen = 32;	  /* >=16 will enable vhost-net on Linux */
	vpninfo->localname = strdup("localhost");
	vpninfo->port = 443;
	vpninfo->useragent = openconnect_create_useragent(useragent);
	vpninfo->validate_peer_cert = validate_peer_cert;
	vpninfo->write_new_config = write_new_config;
	vpninfo->process_auth_form = process_auth_form;
	vpninfo->progress = progress;
	vpninfo->cbdata = privdata ? : vpninfo;
	vpninfo->xmlpost = 1;
	vpninfo->verbose = PRG_TRACE;
	vpninfo->try_http_auth = 1;
	vpninfo->proxy_auth[AUTH_TYPE_BASIC].state = AUTH_DEFAULT_DISABLED;
	vpninfo->http_auth[AUTH_TYPE_BASIC].state = AUTH_DEFAULT_DISABLED;
	openconnect_set_reported_os(vpninfo, NULL);
#ifdef HAVE_EPOLL
	vpninfo->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
#endif
	if (!vpninfo->localname || !vpninfo->useragent)
		goto err;

#ifdef ENABLE_NLS
	bindtextdomain("openconnect", LOCALEDIR);
#endif
	openconnect_set_protocol(vpninfo, "anyconnect");
	return vpninfo;

err:
	free(vpninfo->localname);
	free(vpninfo->useragent);
	free(vpninfo);
	return NULL;
}

static const struct vpn_proto openconnect_protos[] = {
	{
		.name = "anyconnect",
		.pretty_name = N_("Cisco AnyConnect or OpenConnect"),
		.description = N_("Compatible with Cisco AnyConnect SSL VPN, as well as ocserv"),
		.proto = PROTO_ANYCONNECT,
		.flags = OC_PROTO_PROXY | OC_PROTO_CSD | OC_PROTO_AUTH_CERT | OC_PROTO_AUTH_OTP | OC_PROTO_AUTH_STOKEN | OC_PROTO_AUTH_MCA,
		.vpn_close_session = cstp_bye,
		.tcp_connect = cstp_connect,
		.tcp_mainloop = cstp_mainloop,
		.add_http_headers = cstp_common_headers,
		.obtain_cookie = cstp_obtain_cookie,
		.sso_detect_done = cstp_sso_detect_done,
		.secure_cookie = "webvpn",
		.udp_protocol = "DTLS",
#ifdef HAVE_DTLS
		.udp_setup = dtls_setup,
		.udp_mainloop = dtls_mainloop,
		.udp_close = dtls_close,
		.udp_shutdown = dtls_shutdown,
#endif
	}, {
		.name = "nc",
		.pretty_name = N_("Juniper Network Connect"),
		.description = N_("Compatible with Juniper Network Connect"),
		.proto = PROTO_NC,
		.flags = OC_PROTO_PROXY | OC_PROTO_CSD | OC_PROTO_AUTH_CERT | OC_PROTO_AUTH_OTP | OC_PROTO_AUTH_STOKEN | OC_PROTO_PERIODIC_TROJAN,
		.vpn_close_session = oncp_bye,
		.tcp_connect = oncp_connect,
		.tcp_mainloop = oncp_mainloop,
		.add_http_headers = oncp_common_headers,
		.obtain_cookie = oncp_obtain_cookie,
		.secure_cookie = "DSID",
		.udp_protocol = "ESP",
#ifdef HAVE_ESP
		.udp_setup = esp_setup,
		.udp_mainloop = esp_mainloop,
		.udp_close = oncp_esp_close,
		.udp_shutdown = esp_shutdown,
		.udp_send_probes = oncp_esp_send_probes,
		.udp_catch_probe = oncp_esp_catch_probe,
#endif
	}, {
		.name = "gp",
		.pretty_name = N_("Palo Alto Networks GlobalProtect"),
		.description = N_("Compatible with Palo Alto Networks (PAN) GlobalProtect SSL VPN"),
		.proto = PROTO_GPST,
		.flags = OC_PROTO_PROXY | OC_PROTO_CSD | OC_PROTO_AUTH_CERT | OC_PROTO_AUTH_OTP | OC_PROTO_AUTH_STOKEN | OC_PROTO_PERIODIC_TROJAN,
		.vpn_close_session = gpst_bye,
		.tcp_connect = gpst_setup,
		.tcp_mainloop = gpst_mainloop,
		.add_http_headers = gpst_common_headers,
		.obtain_cookie = gpst_obtain_cookie,
		.sso_detect_done = gpst_sso_detect_done,
		.udp_protocol = "ESP",
#ifdef HAVE_ESP
		.udp_setup = esp_setup,
		.udp_mainloop = esp_mainloop,
		.udp_close = esp_close,
		.udp_shutdown = esp_shutdown,
		.udp_send_probes = gpst_esp_send_probes,
		.udp_catch_probe = gpst_esp_catch_probe,
#endif
	}, {
		.name = "pulse",
		.pretty_name = N_("Pulse Connect Secure"),
		.description = N_("Compatible with Pulse Connect Secure SSL VPN"),
		.proto = PROTO_PULSE,
		.flags = OC_PROTO_PROXY | OC_PROTO_AUTH_CERT | OC_PROTO_AUTH_OTP | OC_PROTO_AUTH_STOKEN,
		.vpn_close_session = pulse_bye,
		.tcp_connect = pulse_connect,
		.tcp_mainloop = pulse_mainloop,
		.add_http_headers = http_common_headers,
		.obtain_cookie = pulse_obtain_cookie,
		.udp_protocol = "ESP",
#ifdef HAVE_ESP
		.udp_setup = esp_setup,
		.udp_mainloop = esp_mainloop,
		.udp_close = esp_close,
		.udp_shutdown = esp_shutdown,
		.udp_send_probes = oncp_esp_send_probes,
		.udp_catch_probe = oncp_esp_catch_probe,
#endif
	}, {
		.name = "f5",
		.pretty_name = N_("F5 BIG-IP SSL VPN"),
		.description = N_("Compatible with F5 BIG-IP SSL VPN"),
		.proto = PROTO_F5,
		.flags = OC_PROTO_PROXY | OC_PROTO_AUTH_CERT | OC_PROTO_AUTH_OTP | OC_PROTO_AUTH_STOKEN,
		.vpn_close_session = f5_bye,
		.tcp_connect = f5_connect,
		.tcp_mainloop = ppp_tcp_mainloop,
		.add_http_headers = http_common_headers,
		.obtain_cookie = f5_obtain_cookie,
		.secure_cookie = "MRHSession",
		.udp_protocol = "DTLS",
#ifdef HAVE_DTLS
		.udp_setup = dtls_setup,
		.udp_mainloop = ppp_udp_mainloop,
		.udp_close = dtls_close,
		.udp_shutdown = dtls_shutdown,
		.udp_catch_probe = f5_dtls_catch_probe,
#endif
	}, {
		.name = "fortinet",
		.pretty_name = N_("Fortinet SSL VPN"),
		.description = N_("Compatible with FortiGate SSL VPN"),
		.proto = PROTO_FORTINET,
		.flags = OC_PROTO_PROXY | OC_PROTO_AUTH_CERT | OC_PROTO_AUTH_OTP | OC_PROTO_AUTH_STOKEN,
		.vpn_close_session = fortinet_bye,
		.tcp_connect = fortinet_connect,
		.tcp_mainloop = ppp_tcp_mainloop,
		.add_http_headers = fortinet_common_headers,
		.obtain_cookie = fortinet_obtain_cookie,
		.secure_cookie = "SVPNCOOKIE",
		.udp_protocol = "DTLS",
#ifdef HAVE_DTLS
		.udp_setup = dtls_setup,
		.udp_mainloop = ppp_udp_mainloop,
		.udp_close = dtls_close,
		.udp_shutdown = dtls_shutdown,
		.udp_catch_probe = fortinet_dtls_catch_svrhello,
#endif
	}, {
		.name = "nullppp",
		.pretty_name = N_("PPP over TLS"),
		.description = N_("Unauthenticated RFC1661/RFC1662 PPP over TLS, for testing"),
		.proto = PROTO_NULLPPP,
		.flags = OC_PROTO_PROXY | OC_PROTO_HIDDEN,
		.tcp_connect = nullppp_connect,
		.tcp_mainloop = nullppp_mainloop,
		.add_http_headers = http_common_headers,
		.obtain_cookie = nullppp_obtain_cookie,
	}, {
		.name = "array",
		.pretty_name = N_("Array SSL VPN"),
		.description = N_("Compatible with Array Networks SSL VPN"),
		.proto = PROTO_ARRAY,
		.flags = OC_PROTO_PROXY,
		.vpn_close_session = array_bye,
		.tcp_connect = array_connect,
		.tcp_mainloop = array_mainloop,
		.add_http_headers = http_common_headers,
		.obtain_cookie = array_obtain_cookie,
		.udp_protocol = "DTLS",
#ifdef HAVE_DTLS
		.udp_setup = dtls_setup,
		.udp_mainloop = array_dtls_mainloop,
		.udp_close = dtls_close,
		.udp_shutdown = dtls_shutdown,
#endif
	},
};

#define NR_PROTOS ARRAY_SIZE(openconnect_protos)

int openconnect_get_supported_protocols(struct oc_vpn_proto **protos)
{
	struct oc_vpn_proto *pr;
	int i, j;

	/* The original version of this function included an all-zero
	 * sentinel value at the end of the array, so we must continue
	 * to do so for ABI compatibility even though it's
	 * functionally redundant as a marker of the array's length,
	 * along with the explicit length in the return value.
	 */
	*protos = pr = calloc(NR_PROTOS + 1, sizeof(*pr));
	if (!pr)
		return -ENOMEM;

	for (i = j = 0; i < NR_PROTOS; i++) {
		if (!(openconnect_protos[i].flags & OC_PROTO_HIDDEN)) {
			pr[j].name = openconnect_protos[i].name;
			pr[j].pretty_name = _(openconnect_protos[i].pretty_name);
			pr[j].description = _(openconnect_protos[i].description);
			pr[j].flags = openconnect_protos[i].flags;
			j++;
		}
	}
	return j;
}

void openconnect_free_supported_protocols(struct oc_vpn_proto *protos)
{
	free((void *)protos);
}

const char *openconnect_get_protocol(struct openconnect_info *vpninfo)
{
	return vpninfo->proto->name;
}

int openconnect_set_protocol(struct openconnect_info *vpninfo, const char *protocol)
{
	const struct vpn_proto *p;
	int i;

	for (i = 0; i < NR_PROTOS; i++) {
		p = &openconnect_protos[i];
		if (strcasecmp(p->name, protocol))
			continue;
		vpninfo->proto = p;
		if (!p->udp_setup)
			vpninfo->dtls_state = DTLS_DISABLED;

		return 0;
	}
	vpn_progress(vpninfo, PRG_ERR,
		     _("Unknown VPN protocol '%s'\n"), protocol);
	return -EINVAL;
}

void openconnect_set_pass_tos(struct openconnect_info *vpninfo, int enable)
{
	vpninfo->dtls_pass_tos = enable;
}

void openconnect_set_loglevel(struct openconnect_info *vpninfo, int level)
{
	vpninfo->verbose = level;
}

int openconnect_setup_dtls(struct openconnect_info *vpninfo,
			   int attempt_period)

{
	vpninfo->dtls_attempt_period = attempt_period;
	if (vpninfo->proto->udp_setup)
		return vpninfo->proto->udp_setup(vpninfo);

	vpn_progress(vpninfo, PRG_ERR,
		     _("Built against SSL library with no Cisco DTLS support\n"));
	return -EINVAL;
}

int openconnect_obtain_cookie(struct openconnect_info *vpninfo)
{
#ifdef HAVE_LIBSTOKEN
	int ret;
	if (vpninfo->token_mode == OC_TOKEN_MODE_STOKEN) {
		ret = prepare_stoken(vpninfo);
		if (ret)
			return ret;
	}
#endif
	return vpninfo->proto->obtain_cookie(vpninfo);
}

int openconnect_make_cstp_connection(struct openconnect_info *vpninfo)
{
	int result = vpninfo->proto->tcp_connect(vpninfo);

	/* ssl_times.last_tx should be set to show that a connection has been setup */
	if (result == 0 && vpninfo->ssl_times.last_tx == 0)
		vpninfo->ssl_times.last_tx = time(NULL);
	return result;
}

int openconnect_set_reported_os(struct openconnect_info *vpninfo,
				const char *os)
{
	static const char * const allowed[] = {"linux", "linux-64", "win", "mac-intel", "android", "apple-ios"};

	if (!os) {
#if defined(__APPLE__)
#  include <TargetConditionals.h>
#  if TARGET_OS_IOS
		/* We need to use Apple's boolean "target" defines to distinguish iOS from
		 * desktop MacOS. See  https://stackoverflow.com/a/5920028 and
		 * https://github.com/mstg/iOS-full-sdk/blob/master/iPhoneOS9.3.sdk/usr/include/TargetConditionals.h#L64-L71
		 */
		os = "apple-ios";
#  else
		os = "mac-intel";
#  endif
#elif defined(__ANDROID__)
		os = "android";
#elif defined(_WIN32)
		os = "win";
#else
		os = sizeof(long) > 4 ? "linux-64" : "linux";
#endif
	}

	for (int i = 0; i < ARRAY_SIZE(allowed); i++) {
		if (!strcmp(os, allowed[i])) {
			STRDUP(vpninfo->platname, os);
			return 0;
		}
	}
	return -EINVAL;
}

int openconnect_set_mobile_info(struct openconnect_info *vpninfo,
				const char *mobile_platform_version,
				const char *mobile_device_type,
				const char *mobile_device_uniqueid)
{
	STRDUP(vpninfo->mobile_platform_version, mobile_platform_version);
	STRDUP(vpninfo->mobile_device_type, mobile_device_type);
	STRDUP(vpninfo->mobile_device_uniqueid, mobile_device_uniqueid);

	return 0;
}

int openconnect_set_version_string(struct openconnect_info *vpninfo,
				   const char *version_string)
{
	STRDUP(vpninfo->version_string, version_string);

	return 0;
}

const char *add_option_dup(struct oc_vpn_option **list,
			   const char *opt,
			   const char *val, int val_len)
{
	const char *ret;
	char *new_val;

	if (val_len >= 0)
		new_val = strndup(val, val_len);
	else
		new_val = strdup(val);

	ret = add_option_steal(list, opt, &new_val);
	free(new_val);
	return ret;
}

const char *add_option_steal(struct oc_vpn_option **list,
			     const char *opt, char **val)
{
	struct oc_vpn_option *new = malloc(sizeof(*new));
	if (!new)
		return NULL;

	new->option = strdup(opt);
	if (!new->option) {
		free(new);
		return NULL;
	}
	new->value = *val;
	*val = NULL;
	new->next = *list;
	*list = new;

	return new->value;
}

const char *add_option_ipaddr(struct oc_vpn_option **list,
			      const char *opt, int af, void *addr)
{
	char buf[40];

	if (!inet_ntop(af, addr, buf, sizeof(buf)))
		return NULL;

	return add_option_dup(list, opt, buf, -1);
}


void free_optlist(struct oc_vpn_option *opt)
{
	struct oc_vpn_option *next;

	for (; opt; opt = next) {
		next = opt->next;
		free(opt->option);
		free(opt->value);
		free(opt);
	}
}

int install_vpn_opts(struct openconnect_info *vpninfo, struct oc_vpn_option *opt,
		     struct oc_ip_info *ip_info)
{
	/* XX: remove protocol-specific exceptions here, once we can test them
	 * with F5 reconnections in addition to Juniper reconnections. See:
	 * https://gitlab.com/openconnect/openconnect/-/merge_requests/293#note_702388182
	 */
	if (!ip_info->addr && !ip_info->addr6 && !ip_info->netmask6) {
		if (vpninfo->proto->proto == PROTO_F5) {
			/* F5 doesn't get its IP address until it actually establishes the
			 * PPP connection. */
		} else if (vpninfo->proto->proto == PROTO_NC && vpninfo->ip_info.addr) {
			/* Juniper doesn't necessarily resend the Legacy IP address in the
			 * event of a rekey/reconnection. */
			ip_info->addr = add_option_dup(&opt, "ipaddr", vpninfo->ip_info.addr, -1);
			if (!ip_info->netmask && vpninfo->ip_info.netmask)
				ip_info->netmask = add_option_dup(&opt, "netmask", vpninfo->ip_info.netmask, -1);
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("No IP address received with Juniper rekey/reconnection.\n"));
			goto after_ip_checks;
		} else {
			/* For all other protocols, not receiving any IP address is an error */
			vpn_progress(vpninfo, PRG_ERR,
				     _("No IP address received. Aborting\n"));
			return -EINVAL;
		}
	}

	if (vpninfo->ip_info.addr) {
		if (!ip_info->addr || strcmp(ip_info->addr, vpninfo->ip_info.addr)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different Legacy IP address (%s != %s)\n"),
				     ip_info->addr, vpninfo->ip_info.addr);
			/* EPERM means that the retry loop will abort and won't keep trying. */
			return -EPERM;
		}
	}
	if (vpninfo->ip_info.netmask) {
		if (!ip_info->netmask || strcmp(ip_info->netmask, vpninfo->ip_info.netmask)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different Legacy IP netmask (%s != %s)\n"),
				     ip_info->netmask, vpninfo->ip_info.netmask);
			return -EPERM;
		}
	}
	if (vpninfo->ip_info.addr6) {
		if (!ip_info->addr6 || strcmp(ip_info->addr6, vpninfo->ip_info.addr6)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different IPv6 address (%s != %s)\n"),
				     ip_info->addr6, vpninfo->ip_info.addr6);
			return -EPERM;
		}
	}
	if (vpninfo->ip_info.netmask6) {
		if (!ip_info->netmask6 || strcmp(ip_info->netmask6, vpninfo->ip_info.netmask6)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different IPv6 netmask (%s != %s)\n"),
				     ip_info->netmask6, vpninfo->ip_info.netmask6);
			return -EPERM;
		}
	}

 after_ip_checks:
	/* Preserve gateway_addr and MTU if they were set */
	ip_info->gateway_addr = vpninfo->ip_info.gateway_addr;
	if (!ip_info->mtu)
		ip_info->mtu = vpninfo->ip_info.mtu;

	if (ip_info->mtu && ip_info->mtu < 1280 &&
	    (ip_info->addr6 || ip_info->netmask6)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("IPv6 configuration received but MTU %d is too small.\n"),
			     ip_info->mtu);
	}

	/* XX: Supported protocols and servers are inconsistent in how they send us
	 * multiple search domains. Some provide domains via repeating fields which we
	 * glom into a single space-separated string, some provide domains in single
	 * fields which contain ',' or ';' as separators.
	 *
	 * Since neither ',' nor ';' is a legal character in a domain name, and since all
	 * known routing configuration scripts support space-separated domains, we can
	 * safely replace these characters with spaces, and thus support all known
	 * combinations.
	 */
	for (char *p = (char *)ip_info->domain; p && *p; p++) {
		if (*p == ';' || *p == ',')
			*p = ' ';
	}

	/* Free the original options */
	free_split_routes(&vpninfo->ip_info);
	free_optlist(vpninfo->cstp_options);

	/* Install the new options */
	vpninfo->cstp_options = opt;
	vpninfo->ip_info = *ip_info;

	return 0;
}

static void free_certinfo(struct cert_info *certinfo)
{
	/**
	 * Ensure resources are released
	 */

	unload_certificate(certinfo, 1);

	/* These are const in openconnect itself, but for consistency of
	   the library API we do take ownership of the strings we're given,
	   and thus we have to free them too. */
	if (certinfo->cert != certinfo->key)
		free((void *)certinfo->key);
	free((void *)certinfo->cert);

	free_pass(&certinfo->password);
}

void openconnect_vpninfo_free(struct openconnect_info *vpninfo)
{
	openconnect_close_https(vpninfo, 1);
	if (vpninfo->proto->udp_shutdown)
		vpninfo->proto->udp_shutdown(vpninfo);
	if (vpninfo->tncc_fd != -1)
		closesocket(vpninfo->tncc_fd);
	if (vpninfo->cmd_fd_write != -1) {
		closesocket(vpninfo->cmd_fd);
		closesocket(vpninfo->cmd_fd_write);
	}

#ifdef HAVE_HPKE_SUPPORT
	free_strap_keys(vpninfo);
	free(vpninfo->strap_pubkey);
	free(vpninfo->strap_dh_pubkey);
#endif /* HAVE_HPKE_SUPPORT */

	free(vpninfo->sso_username);
	free(vpninfo->sso_cookie_value);
	free(vpninfo->sso_browser_mode);
	free(vpninfo->sso_login);
	free(vpninfo->sso_login_final);
	free(vpninfo->sso_error_cookie);
	free(vpninfo->sso_token_cookie);

	free(vpninfo->ppp);
	buf_free(vpninfo->ppp_tls_connect_req);
	buf_free(vpninfo->ppp_dtls_connect_req);
#ifdef HAVE_ICONV
	if (vpninfo->ic_utf8_to_legacy != (iconv_t)-1)
		iconv_close(vpninfo->ic_utf8_to_legacy);

	if (vpninfo->ic_legacy_to_utf8 != (iconv_t)-1)
		iconv_close(vpninfo->ic_legacy_to_utf8);
#endif
#ifdef _WIN32
	if (vpninfo->cmd_event)
		CloseHandle(vpninfo->cmd_event);
	if (vpninfo->ssl_event)
		CloseHandle(vpninfo->ssl_event);
	if (vpninfo->dtls_event)
		CloseHandle(vpninfo->dtls_event);
	free(vpninfo->ifname_w);
#endif
	free(vpninfo->peer_addr);
	free(vpninfo->ip_info.gateway_addr);
	free_optlist(vpninfo->csd_env);
	free_optlist(vpninfo->script_env);
	free_optlist(vpninfo->cookies);
	free_optlist(vpninfo->cstp_options);
	free_optlist(vpninfo->dtls_options);
	free_split_routes(&vpninfo->ip_info);
	free(vpninfo->hostname);
	free(vpninfo->unique_hostname);
	free(vpninfo->sni);
	buf_free(vpninfo->connect_urlbuf);
	free(vpninfo->urlpath);
	free(vpninfo->redirect_url);
	free_pass(&vpninfo->cookie);
	free(vpninfo->proxy_type);
	free(vpninfo->proxy);
	free(vpninfo->proxy_user);
	free_pass(&vpninfo->proxy_pass);
	free(vpninfo->vpnc_script);
	free(vpninfo->cafile);
	free(vpninfo->ifname);
	free(vpninfo->dtls_cipher);
	free(vpninfo->peer_cert_hash);
	free(vpninfo->ciphersuite_config);
#if defined(OPENCONNECT_OPENSSL)
	free(vpninfo->cstp_cipher);
#if defined(HAVE_BIO_METH_FREE)
	if (vpninfo->ttls_bio_meth)
		BIO_meth_free(vpninfo->ttls_bio_meth);
#endif
#ifdef HAVE_DTLS
	free(vpninfo->dtls_cipher_desc);
#endif
#elif defined(OPENCONNECT_GNUTLS)
	gnutls_free(vpninfo->cstp_cipher);
#ifdef HAVE_DTLS
	gnutls_free(vpninfo->dtls_cipher_desc);
#endif
#endif
	free(vpninfo->dtls_addr);

	if (vpninfo->csd_scriptname) {
		unlink(vpninfo->csd_scriptname);
		free(vpninfo->csd_scriptname);
	}
	free(vpninfo->mobile_platform_version);
	free(vpninfo->mobile_device_type);
	free(vpninfo->mobile_device_uniqueid);
	free(vpninfo->csd_token);
	free(vpninfo->csd_ticket);
	free(vpninfo->csd_stuburl);
	free(vpninfo->csd_starturl);
	free(vpninfo->csd_waiturl);
	free(vpninfo->csd_preurl);
	free(vpninfo->platname);
	if (vpninfo->opaque_srvdata)
		xmlFreeNode(vpninfo->opaque_srvdata);
	free(vpninfo->profile_url);
	free(vpninfo->profile_sha1);

	free_certinfo(&vpninfo->certinfo[0]);
	free_certinfo(&vpninfo->certinfo[1]);

	if (vpninfo->peer_cert) {
#if defined(OPENCONNECT_OPENSSL)
		X509_free(vpninfo->peer_cert);
#elif defined(OPENCONNECT_GNUTLS)
		gnutls_x509_crt_deinit(vpninfo->peer_cert);
#endif
		vpninfo->peer_cert = NULL;
	}
	while (vpninfo->pin_cache) {
		struct pin_cache *cache = vpninfo->pin_cache;

		free(cache->token);
		memset(cache->pin, 0x5a, strlen(cache->pin));
		free(cache->pin);
		vpninfo->pin_cache = cache->next;
		free(cache);
	}

	free(vpninfo->localname);
	free(vpninfo->useragent);
	free(vpninfo->authgroup);
#ifdef HAVE_LIBSTOKEN
	if (vpninfo->stoken_pin)
		free_pass(&vpninfo->stoken_pin);
	if (vpninfo->stoken_ctx)
		stoken_destroy(vpninfo->stoken_ctx);
#endif
	if (vpninfo->oath_secret) {
#ifdef HAVE_LIBPSKC
		if (vpninfo->pskc)
			pskc_done(vpninfo->pskc);
		else
#endif /* HAVE_LIBPSKC */
		free_pass(&vpninfo->oath_secret);
	}
#ifdef HAVE_LIBPCSCLITE
	release_pcsc_ctx(vpninfo);
#endif
#ifdef HAVE_LIBP11
	if (vpninfo->pkcs11_ctx) {
		if (vpninfo->pkcs11_slot_list)
			PKCS11_release_all_slots(vpninfo->pkcs11_ctx,
						 vpninfo->pkcs11_slot_list,
						 vpninfo->pkcs11_slot_count);
		PKCS11_CTX_unload(vpninfo->pkcs11_ctx);
		PKCS11_CTX_free(vpninfo->pkcs11_ctx);
	}
	free(vpninfo->pkcs11_cert_id);
#endif
	/* These check strm->state so they are safe to call multiple times */
	inflateEnd(&vpninfo->inflate_strm);
	deflateEnd(&vpninfo->deflate_strm);

#ifdef HAVE_EPOLL
	if (vpninfo->epoll_fd >= 0)
		close(vpninfo->epoll_fd);
#endif

	free_pkt(vpninfo, vpninfo->deflate_pkt);
	free_pkt(vpninfo, vpninfo->tun_pkt);
	free_pkt(vpninfo, vpninfo->dtls_pkt);
	free_pkt(vpninfo, vpninfo->cstp_pkt);
	struct pkt *pkt;
	while ((pkt = dequeue_packet(&vpninfo->free_queue)))
		free(pkt);

	free(vpninfo->bearer_token);
	free(vpninfo);
}


const char *openconnect_get_connect_url(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *urlbuf = vpninfo->connect_urlbuf;

	if (!urlbuf)
		urlbuf = buf_alloc();

	buf_append(urlbuf, "https://%s", vpninfo->hostname);
	if (vpninfo->port != 443)
		buf_append(urlbuf, ":%d", vpninfo->port);
	buf_append(urlbuf, "/");

	/* Other protocols don't care and just leave noise from the
	 * authentication process in ->urlpath. Pulse does care, and
	 * you have to *connect* to a given usergroup at the correct
	 * path, not just authenticate.
	 *
	 * https://gitlab.gnome.org/GNOME/NetworkManager-openconnect/-/issues/53
	 * https://gitlab.gnome.org/GNOME/NetworkManager-openconnect/-/merge_requests/22
	 */
	if (vpninfo->proto->proto == PROTO_PULSE && vpninfo->urlpath)
		buf_append(urlbuf, "%s", vpninfo->urlpath);
	if (buf_error(urlbuf)) {
		buf_free(urlbuf);
		vpninfo->connect_urlbuf = NULL;
		return NULL;
	}

	vpninfo->connect_urlbuf = urlbuf;
	return urlbuf->data;
}

const char *openconnect_get_hostname(struct openconnect_info *vpninfo)
{
	return vpninfo->unique_hostname?:vpninfo->hostname;
}

const char *openconnect_get_dnsname(struct openconnect_info *vpninfo)
{
	return vpninfo->hostname;
}

int openconnect_set_hostname(struct openconnect_info *vpninfo,
			     const char *hostname)
{
	UTF8CHECK(hostname);

	STRDUP(vpninfo->hostname, hostname);
	free(vpninfo->unique_hostname);
	vpninfo->unique_hostname = NULL;
	free(vpninfo->peer_addr);
	vpninfo->peer_addr = NULL;
	free(vpninfo->ip_info.gateway_addr);
	vpninfo->ip_info.gateway_addr = NULL;

	return 0;
}

char *openconnect_get_urlpath(struct openconnect_info *vpninfo)
{
	return vpninfo->urlpath;
}

int openconnect_set_useragent(struct openconnect_info *vpninfo,
			      const char *useragent)
{
	UTF8CHECK(useragent);

	STRDUP(vpninfo->useragent, useragent);
	return 0;
}

int openconnect_set_urlpath(struct openconnect_info *vpninfo,
			    const char *urlpath)
{
	UTF8CHECK(urlpath);

	STRDUP(vpninfo->urlpath, urlpath);
	return 0;
}

int openconnect_set_localname(struct openconnect_info *vpninfo,
			      const char *localname)
{
	UTF8CHECK(localname);

	STRDUP(vpninfo->localname, localname);
	return 0;
}

int openconnect_set_sni(struct openconnect_info *vpninfo,
			      const char *sni)
{
	UTF8CHECK(sni);

	STRDUP(vpninfo->sni, sni);
	return 0;
}

void openconnect_set_xmlsha1(struct openconnect_info *vpninfo,
			     const char *xmlsha1, int size)
{
	if (size != sizeof(vpninfo->xmlsha1))
		return;

	memcpy(&vpninfo->xmlsha1, xmlsha1, size);
}

int openconnect_disable_ipv6(struct openconnect_info *vpninfo)
{
	/* This prevents disabling IPv6 when the connection is
	 * currently connected or has been connected previously.
	 *
	 * XX: It would be better to allow it when currently
	 * disconnected, but we currently have no way to indicate
	 * a state in which IP and routing configuration are
	 * unconfigured state. (Neither a closed TLS socket
	 * nor tunnel socket is a reliable indicator.)
	 */
	if (!vpninfo->disable_ipv6 &&
	    vpninfo->ssl_times.last_tx != 0)
		return -EINVAL;
	vpninfo->disable_ipv6 = 1;
	return 0;
}

int openconnect_disable_dtls(struct openconnect_info *vpninfo)
{
	/* This disables DTLS or ESP. It is prevented when the
	 * connection is currently connected or has been
	 * connected previously.
	 *
	 * We allow to disable DTLS if not yet connected to
	 * allow clients using the library disable DTLS if it
	 * fails to connect, similarly to what openconnect does.
	 */
	if (vpninfo->dtls_state == DTLS_ESTABLISHED
	    || vpninfo->dtls_state == DTLS_CONNECTED)
		return -EINVAL;
	vpninfo->dtls_state = DTLS_DISABLED;
	return 0;
}

int openconnect_set_cafile(struct openconnect_info *vpninfo, const char *cafile)
{
	UTF8CHECK(cafile);

	STRDUP(vpninfo->cafile, cafile);
	return 0;
}

void openconnect_set_system_trust(struct openconnect_info *vpninfo, unsigned val)
{
	vpninfo->no_system_trust = !val;
}

const char *openconnect_get_ifname(struct openconnect_info *vpninfo)
{
	return vpninfo->ifname;
}

void openconnect_set_reqmtu(struct openconnect_info *vpninfo, int reqmtu)
{
	vpninfo->reqmtu = reqmtu;
}

void openconnect_set_dpd(struct openconnect_info *vpninfo, int min_seconds)
{
	/* Make sure (ka->dpd / 2), our computed midway point, isn't 0 */
	if (!min_seconds || min_seconds >= 2)
		vpninfo->dtls_times.dpd = vpninfo->ssl_times.dpd = min_seconds;
	else if (min_seconds == 1)
		vpninfo->dtls_times.dpd = vpninfo->ssl_times.dpd = 2;
}

void openconnect_set_trojan_interval(struct openconnect_info *vpninfo, int seconds)
{
	vpninfo->trojan_interval = seconds;
}

int openconnect_get_idle_timeout(struct openconnect_info *vpninfo)
{
	return vpninfo->idle_timeout;
}

time_t openconnect_get_auth_expiration(struct openconnect_info *vpninfo)
{
	return vpninfo->auth_expiration;
}

int openconnect_get_ip_info(struct openconnect_info *vpninfo,
			    const struct oc_ip_info **info,
			    const struct oc_vpn_option **cstp_options,
			    const struct oc_vpn_option **dtls_options)
{
	if (info)
		*info = &vpninfo->ip_info;
	if (cstp_options)
		*cstp_options = vpninfo->cstp_options;
	if (dtls_options)
		*dtls_options = vpninfo->dtls_options;
	return 0;
}

int openconnect_setup_csd(struct openconnect_info *vpninfo, uid_t uid,
			  int silent, const char *wrapper)
{
#ifndef _WIN32
	vpninfo->uid_csd = uid;
	vpninfo->uid_csd_given = silent ? 2 : 1;
#endif
	STRDUP(vpninfo->csd_wrapper, wrapper);

	return 0;
}

void openconnect_set_xmlpost(struct openconnect_info *vpninfo, int enable)
{
	vpninfo->xmlpost = enable;
}

int openconnect_set_client_cert(struct openconnect_info *vpninfo,
				const char *cert, const char *sslkey)
{
	UTF8CHECK(cert);
	UTF8CHECK(sslkey);

	/* Avoid freeing it twice if it's the same */
	if (vpninfo->certinfo[0].key == vpninfo->certinfo[0].cert)
		vpninfo->certinfo[0].key = NULL;

	STRDUP(vpninfo->certinfo[0].cert, cert);

	if (sslkey) {
		STRDUP(vpninfo->certinfo[0].key, sslkey);
	} else {
		vpninfo->certinfo[0].key = vpninfo->certinfo[0].cert;
	}

	return 0;
}

int openconnect_set_mca_cert(struct openconnect_info *vpninfo,
			     const char *cert, const char *key)
{
	UTF8CHECK(cert);
	UTF8CHECK(key);

	/* Avoid freeing it twice if it's the same */
	if (vpninfo->certinfo[1].key == vpninfo->certinfo[1].cert)
		vpninfo->certinfo[1].key = NULL;

	STRDUP(vpninfo->certinfo[1].cert, cert);

	if (key) {
		STRDUP(vpninfo->certinfo[1].key, key);
	} else {
		vpninfo->certinfo[1].key = vpninfo->certinfo[1].cert;
	}

	return 0;
}

int openconnect_set_mca_key_password(struct openconnect_info *vpninfo, const char *pass)
{
	STRDUP(vpninfo->certinfo[1].password, pass);

	return 0;
}

int openconnect_get_port(struct openconnect_info *vpninfo)
{
	return vpninfo->port;
}

const char *openconnect_get_cookie(struct openconnect_info *vpninfo)
{
	return vpninfo->cookie;
}

void openconnect_clear_cookie(struct openconnect_info *vpninfo)
{
	if (vpninfo->cookie)
		memset(vpninfo->cookie, 0, strlen(vpninfo->cookie));
}

int openconnect_set_cookie(struct openconnect_info *vpninfo,
			    const char *cookie)
{
	UTF8CHECK(cookie);

	STRDUP(vpninfo->cookie, cookie);
	return 0;
}

void openconnect_reset_ssl(struct openconnect_info *vpninfo)
{
	vpninfo->got_cancel_cmd = 0;
	openconnect_close_https(vpninfo, 0);

	free(vpninfo->peer_addr);
	vpninfo->peer_addr = NULL;
	vpninfo->dtls_tos_optname = 0;
	free(vpninfo->ip_info.gateway_addr);
	vpninfo->ip_info.gateway_addr = NULL;

	openconnect_clear_cookies(vpninfo);
}

int openconnect_parse_url(struct openconnect_info *vpninfo, const char *url)
{
	char *scheme = NULL;
	int ret;

	UTF8CHECK(url);

	openconnect_set_hostname(vpninfo, NULL);
	free(vpninfo->urlpath);
	vpninfo->urlpath = NULL;

	ret = internal_parse_url(url, &scheme, &vpninfo->hostname,
				 &vpninfo->port, &vpninfo->urlpath, 443);

	if (ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse server URL '%s'\n"),
			     url);
		return ret;
	}
	if (scheme && strcmp(scheme, "https")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Only https:// permitted for server URL\n"));
		ret = -EINVAL;
	}
	free(scheme);
	return ret;
}

void openconnect_set_cert_expiry_warning(struct openconnect_info *vpninfo,
					 int seconds)
{
	vpninfo->cert_expire_warning = seconds;
}

int openconnect_set_key_password(struct openconnect_info *vpninfo, const char *pass)
{
	STRDUP(vpninfo->certinfo[0].password, pass);

	return 0;
}

void openconnect_set_pfs(struct openconnect_info *vpninfo, unsigned val)
{
	vpninfo->pfs = val;
}

int openconnect_set_allow_insecure_crypto(struct openconnect_info *vpninfo, unsigned val)
{
	int ret = can_enable_insecure_crypto();
	if (ret)
		return ret;
	vpninfo->allow_insecure_crypto = val;
	return 0;
}

void openconnect_set_cancel_fd(struct openconnect_info *vpninfo, int fd)
{
	vpninfo->cmd_fd = fd;
}

#ifdef _WIN32
# define CMD_PIPE_ERR INVALID_SOCKET
#else
# define CMD_PIPE_ERR -EIO
#endif

OPENCONNECT_CMD_SOCKET openconnect_setup_cmd_pipe(struct openconnect_info *vpninfo)
{
	OPENCONNECT_CMD_SOCKET pipefd[2];

#ifdef _WIN32
	if (dumb_socketpair(pipefd, 0))
		return CMD_PIPE_ERR;
#else
	if (pipe(pipefd) < 0)
		return CMD_PIPE_ERR;
#endif

	if (set_sock_nonblock(pipefd[0]) || set_sock_nonblock(pipefd[1])) {
		closesocket(pipefd[0]);
		closesocket(pipefd[1]);
		return CMD_PIPE_ERR;
	}
	vpninfo->cmd_fd = pipefd[0];
	vpninfo->cmd_fd_write = pipefd[1];
	vpninfo->need_poll_cmd_fd = 1;
	return vpninfo->cmd_fd_write;
}

const char *openconnect_get_version(void)
{
	return openconnect_version_str;
}

int openconnect_has_pkcs11_support(void)
{
#if defined(OPENCONNECT_GNUTLS) && defined(HAVE_P11KIT)
	return 1;
#elif defined(OPENCONNECT_OPENSSL) && defined(HAVE_LIBP11)
	return 1;
#else
	return 0;
#endif
}

#if defined(OPENCONNECT_OPENSSL) && defined(HAVE_ENGINE)
#include <openssl/engine.h>
#endif
int openconnect_has_tss_blob_support(void)
{
#if defined(OPENCONNECT_OPENSSL) && defined(HAVE_ENGINE)
	ENGINE *e;

	ENGINE_load_builtin_engines();

	e = ENGINE_by_id("tpm");
	if (e) {
		ENGINE_free(e);
		return 1;
	}
#elif defined(OPENCONNECT_GNUTLS) && defined(HAVE_TROUSERS)
	return 1;
#endif
	return 0;
}

int openconnect_has_tss2_blob_support(void)
{
#if defined(OPENCONNECT_OPENSSL) && defined(HAVE_ENGINE)
	ENGINE *e;

	ENGINE_load_builtin_engines();

	e = ENGINE_by_id("tpm2");
	if (e) {
		ENGINE_free(e);
		return 1;
	}
#elif defined(OPENCONNECT_GNUTLS) && defined(HAVE_TSS2)
	return 1;
#endif
	return 0;
}

int openconnect_has_stoken_support(void)
{
#ifdef HAVE_LIBSTOKEN
	return 1;
#else
	return 0;
#endif
}

int openconnect_has_oath_support(void)
{
	return 2;
}

int openconnect_has_yubioath_support(void)
{
#ifdef HAVE_LIBPCSCLITE
	return 1;
#else
	return 0;
#endif
}

int openconnect_has_system_key_support(void)
{
#ifdef HAVE_GNUTLS_SYSTEM_KEYS
	return 1;
#else
	return 0;
#endif
}

int openconnect_set_token_callbacks(struct openconnect_info *vpninfo,
				    void *tokdata,
				    openconnect_lock_token_vfn lock,
				    openconnect_unlock_token_vfn unlock)
{
	vpninfo->lock_token = lock;
	vpninfo->unlock_token = unlock;
	vpninfo->tok_cbdata = tokdata;

	return 0;
}

/*
 * Enable software token generation.
 *
 * If token_mode is OC_TOKEN_MODE_STOKEN and token_str is NULL,
 * read the token data from ~/.stokenrc.
 *
 * Return value:
 *  = -EILSEQ, if token_str is not valid UTF-8
 *  = -EOPNOTSUPP, if the underlying library (libstoken, liboath) is not
 *                 available or an invalid token_mode was provided
 *  = -EINVAL, if the token string is invalid (token_str was provided)
 *  = -ENOENT, if token_mode is OC_TOKEN_MODE_STOKEN and ~/.stokenrc is
 *             missing (token_str was NULL)
 *  = -EIO, for other failures in the underlying library (libstoken, liboath)
 *  = 0, on success
 */
int openconnect_set_token_mode(struct openconnect_info *vpninfo,
			       oc_token_mode_t token_mode,
			       const char *token_str)
{
	vpninfo->token_mode = OC_TOKEN_MODE_NONE;

	UTF8CHECK(token_str);

	switch (token_mode) {
	case OC_TOKEN_MODE_NONE:
		return 0;

	case OC_TOKEN_MODE_TOTP:
	case OC_TOKEN_MODE_HOTP:
		return set_oath_mode(vpninfo, token_str, token_mode);

#ifdef HAVE_LIBSTOKEN
	case OC_TOKEN_MODE_STOKEN:
		return set_libstoken_mode(vpninfo, token_str);
#endif
#ifdef HAVE_LIBPCSCLITE
	case OC_TOKEN_MODE_YUBIOATH:
		return set_yubikey_mode(vpninfo, token_str);
#endif
	case OC_TOKEN_MODE_OIDC:
		return set_oidc_token(vpninfo, token_str);
	default:
		return -EOPNOTSUPP;
	}
}

/*
 * Enable libstoken token generation if use_stoken == 1.
 *
 * If token_str is not NULL, try to parse the string.  Otherwise, try to read
 * the token data from ~/.stokenrc
 *
 * DEPRECATED: use openconnect_set_stoken_mode() instead.
 *
 * Return value:
 *  = -EILSEQ, if token_str is not valid UTF-8
 *  = -EOPNOTSUPP, if libstoken is not available
 *  = -EINVAL, if the token string is invalid (token_str was provided)
 *  = -ENOENT, if ~/.stokenrc is missing (token_str was NULL)
 *  = -EIO, for other libstoken failures
 *  = 0, on success
 */
int openconnect_set_stoken_mode(struct openconnect_info *vpninfo,
				int use_stoken, const char *token_str)
{
	oc_token_mode_t token_mode = OC_TOKEN_MODE_NONE;

	if (use_stoken)
		token_mode = OC_TOKEN_MODE_STOKEN;

	return openconnect_set_token_mode(vpninfo, token_mode, token_str);
}

void openconnect_set_protect_socket_handler(struct openconnect_info *vpninfo,
					    openconnect_protect_socket_vfn protect_socket)
{
	vpninfo->protect_socket = protect_socket;
}

void openconnect_override_getaddrinfo(struct openconnect_info *vpninfo, openconnect_getaddrinfo_vfn gai_fn)
{
	vpninfo->getaddrinfo_override = gai_fn;
}

void openconnect_set_setup_tun_handler(struct openconnect_info *vpninfo,
				       openconnect_setup_tun_vfn setup_tun)
{
	vpninfo->setup_tun = setup_tun;
}

void openconnect_set_reconnected_handler(struct openconnect_info *vpninfo,
				         openconnect_reconnected_vfn reconnected)
{
	vpninfo->reconnected = reconnected;
}

void openconnect_set_stats_handler(struct openconnect_info *vpninfo,
				   openconnect_stats_vfn stats_handler)
{
	vpninfo->stats_handler = stats_handler;
}

/* Set up a traditional OS-based tunnel device, optionally specified in 'ifname'. */
int openconnect_setup_tun_device(struct openconnect_info *vpninfo,
				 const char *vpnc_script, const char *ifname)
{
	intptr_t tun_fd;
	char *legacy_ifname;

	UTF8CHECK(vpnc_script);
	UTF8CHECK(ifname);

	STRDUP(vpninfo->vpnc_script, vpnc_script);
	STRDUP(vpninfo->ifname, ifname);

	prepare_script_env(vpninfo);

	/* XX: vpninfo->ifname will only be non-NULL here if set by the -i option,
	   which only works on some platforms (see os_setup_tun implementations) */
	legacy_ifname = vpninfo->ifname ? openconnect_utf8_to_legacy(vpninfo, vpninfo->ifname) : NULL;
	script_setenv(vpninfo, "TUNDEV", legacy_ifname, 0, 0);
	if (legacy_ifname != vpninfo->ifname)
		free(legacy_ifname);

	script_config_tun(vpninfo, "pre-init");

	tun_fd = os_setup_tun(vpninfo);
	if (tun_fd < 0)
		return tun_fd;

#ifdef _WIN32
	if (vpninfo->tun_idx != -1)
		script_setenv_int(vpninfo, "TUNIDX", vpninfo->tun_idx);
#endif

	/* XX: os_setup_tun has set (or even changed) ifname */
	legacy_ifname = openconnect_utf8_to_legacy(vpninfo, vpninfo->ifname);
	script_setenv(vpninfo, "TUNDEV", legacy_ifname, 0, 0);
	if (legacy_ifname != vpninfo->ifname)
		free(legacy_ifname);

	script_config_tun(vpninfo, "connect");

	return openconnect_setup_tun_fd(vpninfo, tun_fd);
}

static const char * const compr_name_map[] = {
	[COMPR_DEFLATE] = "Deflate",
	[COMPR_LZS] = "LZS",
	[COMPR_LZ4] = "LZ4",
	[COMPR_LZO] = "LZO",
};

const char *openconnect_get_cstp_compression(struct openconnect_info *vpninfo)
{
	if (vpninfo->cstp_compr <= 0 || vpninfo->cstp_compr > COMPR_MAX)
		return NULL;

	return compr_name_map[vpninfo->cstp_compr];
}

const char *openconnect_get_dtls_compression(struct openconnect_info *vpninfo)
{
	if (vpninfo->dtls_compr <= 0 || vpninfo->dtls_compr > COMPR_MAX)
		return NULL;

	return compr_name_map[vpninfo->dtls_compr];
}

const char *openconnect_get_dtls_cipher(struct openconnect_info *vpninfo)
{
	if (vpninfo->dtls_state < DTLS_CONNECTED || !vpninfo->dtls_ssl) {
#if defined(OPENCONNECT_GNUTLS)
		gnutls_free(vpninfo->dtls_cipher_desc);
#else
		free(vpninfo->dtls_cipher_desc);
#endif
		vpninfo->dtls_cipher_desc = NULL;
		return NULL;
	}
	/* in DTLS rehandshakes don't switch the ciphersuite as only
	 * one is enabled. */
	if (vpninfo->dtls_cipher_desc == NULL) {
#if defined(OPENCONNECT_GNUTLS)
		vpninfo->dtls_cipher_desc = get_gnutls_cipher(vpninfo->dtls_ssl);
#else
		if (asprintf(&vpninfo->dtls_cipher_desc, "%s-%s",
		             SSL_get_version(vpninfo->dtls_ssl), SSL_get_cipher_name(vpninfo->dtls_ssl)) < 0)
			return NULL;
#endif
	}
	return vpninfo->dtls_cipher_desc;
}

int openconnect_set_csd_environ(struct openconnect_info *vpninfo,
				const char *name, const char *value)
{
	struct oc_vpn_option *p;

	if (!name) {
		free_optlist(vpninfo->csd_env);
		vpninfo->csd_env = NULL;
		return 0;
	}
	for (p = vpninfo->csd_env; p; p = p->next) {
		if (!strcmp(name, p->option)) {
			char *valdup = strdup(value);
			if (!valdup)
				return -ENOMEM;
			free(p->value);
			p->value = valdup;
			return 0;
		}
	}
	p = malloc(sizeof(*p));
	if (!p)
		return -ENOMEM;
	p->option = strdup(name);
	if (!p->option) {
		free(p);
		return -ENOMEM;
	}
	p->value = strdup(value);
	if (!p->value) {
		free(p->option);
		free(p);
		return -ENOMEM;
	}
	p->next = vpninfo->csd_env;
	vpninfo->csd_env = p;
	return 0;
}

int openconnect_check_peer_cert_hash(struct openconnect_info *vpninfo,
				     const char *old_hash)
{
	char *fingerprint = NULL;
	const unsigned min_match_len = 4;
	unsigned old_len, fingerprint_len;
	int case_sensitive = 0;
	int ret = 0;

	if (strchr(old_hash, ':')) {
		/* These are hashes of the public key not the full cert. */
		if (strncmp(old_hash, "sha1:", 5) == 0) {
			old_hash += 5;
			fingerprint = openconnect_bin2hex(NULL, vpninfo->peer_cert_sha1_raw, sizeof(vpninfo->peer_cert_sha1_raw));
		} else if (strncmp(old_hash, "sha256:", 7) == 0) {
			old_hash += 7;
			fingerprint = openconnect_bin2hex(NULL, vpninfo->peer_cert_sha256_raw, sizeof(vpninfo->peer_cert_sha256_raw));
		} else if (strncmp(old_hash, "pin-sha256:", 11) == 0) {
			old_hash += 11;
			fingerprint = openconnect_bin2base64(NULL, vpninfo->peer_cert_sha256_raw, sizeof(vpninfo->peer_cert_sha256_raw));
			case_sensitive = 1;
		} else {
			vpn_progress(vpninfo, PRG_ERR, _("Unknown certificate hash: %s.\n"), old_hash);
			return -EIO;
		}
	} else {
		/* Not the same as the sha1: case above, because this hashes the full cert */
		unsigned char *cert;
		int len;
		unsigned char sha1_bin[SHA1_SIZE];

		len = openconnect_get_peer_cert_DER(vpninfo, &cert);
		if (len < 0)
			return len;

		if (openconnect_sha1(sha1_bin, cert, len)) {
			free(cert);
			return -EIO;
		}

		free(cert);
		fingerprint = openconnect_bin2hex(NULL, sha1_bin, sizeof(sha1_bin));
	}

	if (!fingerprint)
		return -EIO;

	old_len = strlen(old_hash);
	fingerprint_len = strlen(fingerprint);

	if (old_len > fingerprint_len)
		ret = 1;
	else if (case_sensitive ? strncmp(old_hash, fingerprint, old_len) :
		 strncasecmp(old_hash, fingerprint, old_len))
		ret = 1;
	else if (old_len < min_match_len) {
		vpn_progress(vpninfo, PRG_ERR, _("The size of the provided fingerprint is less than the minimum required (%u).\n"), min_match_len);
		ret = 1;
	}

	free(fingerprint);
	return ret;
}

const char *openconnect_get_cstp_cipher(struct openconnect_info *vpninfo)
{
	return vpninfo->cstp_cipher;
}

const char *openconnect_get_peer_cert_hash(struct openconnect_info *vpninfo)
{
	if (vpninfo->peer_cert_hash == NULL)
		vpninfo->peer_cert_hash = openconnect_bin2base64("pin-sha256:", vpninfo->peer_cert_sha256_raw, sizeof(vpninfo->peer_cert_sha256_raw));
	return vpninfo->peer_cert_hash;
}

int openconnect_set_compression_mode(struct openconnect_info *vpninfo,
				     oc_compression_mode_t mode)
{
	switch (mode) {
	case OC_COMPRESSION_MODE_NONE:
		vpninfo->req_compr = 0;
		return 0;
	case OC_COMPRESSION_MODE_STATELESS:
		vpninfo->req_compr = COMPR_STATELESS;
		return 0;
	case OC_COMPRESSION_MODE_ALL:
		vpninfo->req_compr = COMPR_ALL;
		return 0;
	default:
		return -EINVAL;
	}
}

void nuke_opt_values(struct oc_form_opt *opt)
{
	for (; opt; opt = opt->next) {
		if (opt->type == OC_FORM_OPT_TEXT ||
		    opt->type == OC_FORM_OPT_PASSWORD) {
			free(opt->_value);
			opt->_value = NULL;
		}
	}
}

int process_auth_form(struct openconnect_info *vpninfo, struct oc_auth_form *form)
{
	int ret, do_sso = 0;
	struct oc_form_opt_select *grp = form->authgroup_opt;
	struct oc_choice *auth_choice;
	struct oc_form_opt *opt;

	if (!vpninfo->process_auth_form) {
		vpn_progress(vpninfo, PRG_ERR, _("No form handler; cannot authenticate.\n"));
		return OC_FORM_RESULT_ERR;
	}
	if (!form->auth_id) {
		vpn_progress(vpninfo, PRG_ERR, _("No form ID. This is a bug in OpenConnect's authentication code.\n"));
		return OC_FORM_RESULT_ERR;
	}

retry:
	auth_choice = NULL;
	if (grp && grp->nr_choices) {
		/* Set group selection from authgroup */
		if (vpninfo->authgroup) {
			int i;
			for (i = 0; i < grp->nr_choices; i++)
				if (!strcmp(grp->choices[i]->name, vpninfo->authgroup))
					form->authgroup_selection = i;
		}
		auth_choice = grp->choices[form->authgroup_selection];
	}

	for (opt = form->opts; opt; opt = opt->next) {
		int second_auth = opt->flags & OC_FORM_OPT_SECOND_AUTH;
		opt->flags &= ~OC_FORM_OPT_IGNORE;

		if (opt->type == OC_FORM_OPT_SSO_TOKEN) {
			do_sso = 1;
			continue;
		}

		if (!auth_choice ||
		    (opt->type != OC_FORM_OPT_TEXT && opt->type != OC_FORM_OPT_PASSWORD))
			continue;

		if (auth_choice->noaaa ||
		    (!auth_choice->second_auth && second_auth))
			opt->flags |= OC_FORM_OPT_IGNORE;
		else if (!strcmp(opt->name, "secondary_username") && second_auth) {
			if (auth_choice->secondary_username) {
				free(opt->_value);
				opt->_value = strdup(auth_choice->secondary_username);
			}
			if (!auth_choice->secondary_username_editable)
				opt->flags |= OC_FORM_OPT_IGNORE;
		}
	}

	ret = vpninfo->process_auth_form(vpninfo->cbdata, form);

	if (ret == OC_FORM_RESULT_NEWGROUP &&
	    form->authgroup_opt &&
	    form->authgroup_opt->form._value) {
		free(vpninfo->authgroup);
		vpninfo->authgroup = strdup(form->authgroup_opt->form._value);

		if (!vpninfo->xmlpost)
			goto retry;
	}

	if (ret == OC_FORM_RESULT_CANCELLED || ret < 0)
		nuke_opt_values(form->opts);

	if (do_sso) {
		free(vpninfo->sso_cookie_value);
		free(vpninfo->sso_username);
		vpninfo->sso_cookie_value = NULL;
		vpninfo->sso_username = NULL;

		/* Handle the special Cisco external browser mode */
		if (vpninfo->sso_browser_mode && !strcmp(vpninfo->sso_browser_mode, "external")) {
			ret = handle_external_browser(vpninfo);
		} else if (vpninfo->open_webview) {
			ret = vpninfo->open_webview(vpninfo, vpninfo->sso_login, vpninfo->cbdata);
		} else {
			vpn_progress(vpninfo, PRG_ERR,
				     _("No SSO handler\n")); /* XX: print more debugging info */
			ret = -EINVAL;
		}
		if (!ret) {
			for (opt = form->opts; opt; opt = opt->next) {
				if (opt->type == OC_FORM_OPT_SSO_TOKEN) {
					free(opt->_value);
					opt->_value = vpninfo->sso_cookie_value;
					vpninfo->sso_cookie_value = NULL;
				} else if (opt->type == OC_FORM_OPT_SSO_USER) {
					free(opt->_value);
					opt->_value = vpninfo->sso_username;
					vpninfo->sso_username = NULL;
				}
			}
		}
		free(vpninfo->sso_username);
		vpninfo->sso_username = NULL;
		free(vpninfo->sso_cookie_value);
		vpninfo->sso_cookie_value = NULL;
		free(vpninfo->sso_browser_mode);
		vpninfo->sso_browser_mode = NULL;
	}

	return ret;
}

void openconnect_set_webview_callback(struct openconnect_info *vpninfo,
				      openconnect_open_webview_vfn webview_fn)
{
	vpninfo->open_webview = webview_fn;
	vpninfo->try_http_auth = 0;
}

void openconnect_set_external_browser_callback(struct openconnect_info *vpninfo,
					       openconnect_open_webview_vfn browser_fn)
{
	vpninfo->open_ext_browser = browser_fn;
	vpninfo->try_http_auth = 0;
}

int openconnect_webview_load_changed(struct openconnect_info *vpninfo,
				      const struct oc_webview_result *result)
{
	if (!vpninfo || !result)
		return -EINVAL;

	if (vpninfo->proto->sso_detect_done)
		return (vpninfo->proto->sso_detect_done)(vpninfo, result);

	return -EOPNOTSUPP;
}
