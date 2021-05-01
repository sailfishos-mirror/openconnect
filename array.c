/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020 David Woodhouse
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

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>
#include <sys/types.h>

#include "json.h"

#include "openconnect-internal.h"

static struct oc_auth_form *plain_auth_form() {
        struct oc_auth_form *form;
        struct oc_form_opt *opt, *opt2, *opt3;

        form = calloc(1, sizeof(*form));
        if (!form) {
        nomem:
                free_auth_form(form);
                return NULL;
        }
	form->auth_id = strdup("form");
        opt = form->opts = calloc(1, sizeof(*opt));
        if (!opt)
                goto nomem;
        opt->label = strdup("authgroup:");
        opt->name = strdup("method");
        opt->type = OC_FORM_OPT_TEXT;

        opt2 = opt->next = calloc(1, sizeof(*opt2));
        if (!opt2)
                goto nomem;
        opt2->label = strdup("username:");
        opt2->name = strdup("uname");
        opt2->type = OC_FORM_OPT_TEXT;

        opt3 = opt2->next = calloc(1, sizeof(*opt3));
        if (!opt3)
                goto nomem;
        opt3->label = strdup("password:");
        opt3->name = strdup("pwd");
        opt3->type = OC_FORM_OPT_PASSWORD;
        return form;
}

int array_obtain_cookie(struct openconnect_info *vpninfo)
{
	struct oc_auth_form *form = plain_auth_form();
	if (!form)
		return -ENOMEM;

	struct oc_text_buf *req_buf = buf_alloc();
	int ret;
        if ((ret = buf_error(req_buf)))
                goto out;

	do {
		ret = process_auth_form(vpninfo, form);
	} while (ret == OC_FORM_RESULT_NEWGROUP);
	if (ret)
		goto out;

	append_form_opts(vpninfo, form, req_buf);
	if ((ret = buf_error(req_buf)))
		goto out;

	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup("prx/000/http/localhost/login");
	if (!vpninfo->urlpath) {
		ret = -ENOMEM;
		goto out;
	}

	char *resp_buf = NULL;
	ret = do_https_request(vpninfo, "POST",
			       "application/x-www-form-urlencoded",
			       req_buf, &resp_buf, 2);
	free(resp_buf);
	if (ret <= 0)
		goto out;

	struct oc_vpn_option *cookie;
	for (cookie = vpninfo->cookies; cookie; cookie = cookie->next) {
		if (!strncmp(cookie->option, "ANsession", 9)) {
			free(vpninfo->cookie);
			if (asprintf(&vpninfo->cookie, "%s=%s", cookie->option, cookie->value) <= 0)
				return -ENOMEM;
			ret = 0;
			goto out;
		}
	}
	vpn_progress(vpninfo, PRG_INFO, _("No ANsession cookie found\n"));
	ret = -EPERM;

 out:
        if (form) free_auth_form(form);
        if (req_buf) buf_free(req_buf);
	printf("obtain return %d\n", ret);
        return ret;
}

/* XXX: Lifted from oncp.c. Share it. */
static int parse_cookie(struct openconnect_info *vpninfo)
{
	char *p = vpninfo->cookie;

	/* We currenly expect the "cookie" to be contain multiple cookies:
	 * DSSignInUrl=/; DSID=xxx; DSFirstAccess=xxx; DSLastAccess=xxx
	 * Process those into vpninfo->cookies unless we already had them
	 * (in which case they'll may be newer. */
	while (p && *p) {
		char *semicolon = strchr(p, ';');
		char *equals;

		if (semicolon)
			*semicolon = 0;

		equals = strchr(p, '=');
		if (!equals) {
			vpn_progress(vpninfo, PRG_ERR, _("Invalid cookie '%s'\n"), p);
			return -EINVAL;
		}
		*equals = 0;
		http_add_cookie(vpninfo, p, equals+1, 0);
		*equals = '=';

		p = semicolon;
		if (p) {
			*p = ';';
			p++;
			while (*p && isspace((int)(unsigned char)*p))
				p++;
		}
	}

	return 0;
}

/* No idea what these structures are yet... */
static const unsigned char conf50[] = { 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const unsigned char conf54[] = { 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
					0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x0f,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x52, 0x54, 0x00, 0xde, 0xa2, 0xa6, 0x00, 0x00 };

static const unsigned char ipff[] = { 0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
				      0x00, 0xff, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
				      0x00, 0x00, 0x00, 0x00 };

static int parse_one_inc_exc(struct openconnect_info *vpninfo, struct oc_vpn_option **opts,
			     struct oc_ip_info *ip_info, int incl, int ipv6, json_value *val)
{
	if (val->type != json_object) {
		vpn_progress(vpninfo, PRG_ERR, "Include not object\n");
		return -EINVAL;
	}

	/* We have no idea how they expose IPv6 yet. Hopefully not
	   as wrong-endian integers like Legacy IP! */
	if (ipv6)
		return 0;

	uint32_t route_ip = 0, route_mask = 0;
	int route_ip_found = 0, route_mask_found = 0;

	for (int i = 0; i < val->u.object.length; i++) {
		json_char *child_name = val->u.object.values[i].name;
		json_value *child_val = val->u.object.values[i].value;

		if (child_val->type != json_integer)
			continue;

		if (!strcmp(child_name, "ip")) {
			store_le32(&route_ip, child_val->u.integer);
			route_ip_found = 1;
		} else if (!strcmp(child_name, "mask")) {
			store_le32(&route_mask, child_val->u.integer);
			route_mask_found = 1;
		}
	}
	if (route_ip_found && route_mask_found) {
		char buf[64];
		if (!inet_ntop(AF_INET, &route_ip, buf, sizeof(buf)/2))
			return -errno;
		char *p = buf + strlen(buf);
		*(p++) = '/';
		if (!inet_ntop(AF_INET, &route_mask, p, sizeof(buf) - (p - buf)))
			return -errno;

		vpn_progress(vpninfo, PRG_INFO, "Found split route %s\n", buf);

		struct oc_split_include *inc = malloc(sizeof (*inc));
		if (!inc)
			return -ENOMEM;

		struct oc_split_include **list;
		if (incl)
			list = &ip_info->split_includes;
		else
			list = &ip_info->split_excludes;

		inc->route = add_option_dup(opts, "split-include", buf, -1);
		inc->next = *list;
		*list = inc;
	}

	return 0;
}

static int parse_network_inc_exc(struct openconnect_info *vpninfo, struct oc_vpn_option **opts,
				 struct oc_ip_info *ip_info, int incl, json_value *val)
{
	int ret = 0;

	if (val->type != json_object) {
		vpn_progress(vpninfo, PRG_ERR, "Includes not object\n");
		return -EINVAL;
	}

	for (int i = 0; i < val->u.object.length; i++) {
		json_char *child_name = val->u.object.values[i].name;
		json_value *child_val = val->u.object.values[i].value;
		int is_ipv6;

		if (child_val->type != json_array)
			continue;

		if (!strcmp(child_name, "ipv6"))
			is_ipv6 = 1;
		else if (!strcmp(child_name, "ipv4"))
			is_ipv6 = 0;
		else
			continue;

		for (int j = 0; j < child_val->u.array.length; j++) {
			ret = parse_one_inc_exc(vpninfo, opts, ip_info, incl, is_ipv6,
						child_val->u.array.values[j]);
			if (ret)
				goto out;
		}
	}
 out:
	return ret;
}

static int parse_proxy_script(struct openconnect_info *vpninfo, struct oc_vpn_option **opts,
			      struct oc_ip_info *ip_info, json_value *val)
{
	return 0;
}

static int parse_dns_servers(struct openconnect_info *vpninfo, struct oc_vpn_option **opts,
			     struct oc_ip_info *ip_info, json_value *val)
{
	int servers_found = 0;

	if (val->type != json_array)
		return -EINVAL;
	/*
	 * The 'dns_servers' object is an array, containing object[s] with
	 * children named 'ipv4' and, presumably, 'ipv6'. Each of those is
	 * *itself* an array. It isn't clear why we need an array of arrays.
	 * Nor why IPv6 and Legacy IP need to be separate at all.
	 *
	 * "dns_servers": [{
	 *			"ipv4":	[67373064, 134744072]
	 *		  }],
	*/
	for (int i = 0; i < val->u.array.length; i++) {
		json_value *elem1 = val->u.array.values[i];

		if (elem1->type != json_object)
			continue;

		for (int j = 0; j < elem1->u.object.length; j++) {
			json_char *child_name = elem1->u.object.values[j].name;
			json_value *child_val = elem1->u.object.values[j].value;

			if (child_val->type != json_array)
				continue;

			int legacyip;

			if (!strcmp(child_name, "ipv4"))
				legacyip = 1;
			else if (!strcmp(child_name, "ipv6"))
				legacyip = 0;
			else
				continue;

			for (int k = 0; k < child_val->u.array.length; k++) {
				json_value *elem2 = child_val->u.array.values[k];
				char buf[32];
				const char *server = buf;

				if (legacyip && elem2->type == json_integer) {
					uint32_t addr;
					store_le32(&addr, elem2->u.integer);
					if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf)))
						return -errno;
				} else if (!legacyip && elem2->type == json_string) {
					server = elem2->u.string.ptr;
				} else continue;

				vpn_progress(vpninfo, PRG_INFO, _("Found DNS server %s\n"), server);

				if (servers_found < 4)
					ip_info->dns[servers_found++] = add_option_dup(opts, "DNS", server, -1);
			}
		}
	}

	return 0;
}

static int parse_search_domains(struct openconnect_info *vpninfo, struct oc_vpn_option **opts,
				struct oc_ip_info *ip_info, json_value *val)
{
	if (val->type != json_array)
		return -EINVAL;

	struct oc_text_buf *domains = buf_alloc();

	for (int i = 0; i < val->u.array.length; i++) {
		json_value *elem = val->u.array.values[i];

		if (elem->type != json_string)
			continue;

		vpn_progress(vpninfo, PRG_INFO, _("Got search domain '%s'\n"),
			     elem->u.string.ptr);

		buf_append(domains, "%s ", elem->u.string.ptr);
	}

	if (buf_error(domains))
		return buf_free(domains);

	if (domains->pos) {
		domains->data[domains->pos - 1] = '\0';
		ip_info->domain = add_option_steal(opts, "search", &domains->data);
	}

	buf_free(domains);
	return 0;
}

static int parse_interface_info(struct openconnect_info *vpninfo,
				json_value *val)
{
	struct oc_vpn_option *new_opts = NULL;
	struct oc_ip_info new_ip_info = {};
	int i, ret = 0;

	if (val->type != json_object)
		return -EINVAL;

	for (i = 0; i < val->u.object.length; i++) {
		json_char *child_name = val->u.object.values[i].name;
		json_value *child_val = val->u.object.values[i].value;

		if (child_val->type == json_integer) {
			json_int_t ival = child_val->u.integer;

			/* The Array server gives us Legacy IP addresses as
			 * decimal integers, in wrong-endian form. So an IP
			 * address of e.g. 1.2.3.4 is presented as 0x04030201
			 * or "client_ipv4: 67305985" in the JSON response.
			 * Obviously, integers represented as decimal strings
			 * don't have an endianness on the wire per se; this
			 * is only "wrong" endian. So... since the address in
			 * struct in_addr is supposed to be stored in network
			 * (big) endian form, we need to store the
			 * wrong-endian integer as *little* endian in order
			 * end up with the correct result. */

			if (!strcmp(child_name, "client_ipv4")) {
				uint32_t ip;
				store_le32(&ip, ival);
				new_ip_info.addr = add_option_ipaddr(&new_opts,
								     "client_ipv4",
								     AF_INET, &ip);
				printf("Found Legacy IP address %s\n", new_ip_info.addr);
			} else if (!strcmp(child_name, "client_ipv4_mask")) {
				uint32_t mask;
				store_le32(&mask, ival);
				new_ip_info.netmask = add_option_ipaddr(&new_opts,
									"client_ipv4_mask",
									AF_INET, &mask);
				printf("Found Legacy IP netmask %s\n", new_ip_info.netmask);
			}
			else goto unknown;
		} else if (child_val->type == json_object) {
			if (!strcmp(child_name, "include_network_resource")) {
				ret = parse_network_inc_exc(vpninfo, &new_opts, &new_ip_info,
							    1, child_val);
			} else if (!strcmp(child_name, "exclude_network_resource")) {
				ret = parse_network_inc_exc(vpninfo, &new_opts, &new_ip_info,
							    0, child_val);
			} else if (!strcmp(child_name, "proxy_script")) {
				ret = parse_proxy_script(vpninfo, &new_opts, &new_ip_info,
							 child_val);
			}
			else goto unknown;
		} else if (child_val->type == json_array) {
			if (!strcmp(child_name, "dns_servers")) {
				ret = parse_dns_servers(vpninfo, &new_opts, &new_ip_info,
							child_val);
			} else if (!strcmp(child_name, "search_domains")) {
				ret = parse_search_domains(vpninfo, &new_opts, &new_ip_info,
							   child_val);
			}
			else goto unknown;
		} else {
		unknown:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Unknown Array config element '%s'\n"),
				     child_name);
		}
		if (ret)
			goto out;
	}

	if (!ret)
		ret = install_vpn_opts(vpninfo, new_opts, &new_ip_info);
 out:
	if (ret) {
		free_optlist(new_opts);
                free_split_routes(&new_ip_info);
	}
	return ret;
}

static int parse_speed_tunnel(struct openconnect_info *vpninfo,
			      json_value *val)
{
	int speed_tunnel = 0, speed_tunnel_enc = 0, dpd = 0;
	int i;
	for (i = 0; i < val->u.object.length; i++) {
		json_char *child_name = val->u.object.values[i].name;
		json_value *child_val = val->u.object.values[i].value;

		if (child_val->type == json_integer) {
			json_int_t ival = child_val->u.integer;

			if (!strcmp(child_name, "allow_speed_tunnel"))
				speed_tunnel = ival;
			else if (!strcmp(child_name, "speed_tunnel_encryption"))
				speed_tunnel_enc = ival;
			else if (!strcmp(child_name, "keepalive_interval"))
				dpd = ival;
		}
	}

	vpn_progress(vpninfo, PRG_INFO,
		     _("Initial config: Speed tunnel %d, enc %d, DPD %d\n"),
		     speed_tunnel, speed_tunnel_enc, dpd);

	if (!speed_tunnel)
		vpninfo->dtls_state = DTLS_DISABLED;

	/* We don't support DPD yet...*/
	if (0 && dpd) {
		if (!vpninfo->ssl_times.dpd || vpninfo->ssl_times.dpd > dpd)
			vpninfo->ssl_times.dpd = dpd;
		if (!vpninfo->dtls_times.dpd || vpninfo->dtls_times.dpd > dpd)
			vpninfo->dtls_times.dpd = dpd;
	}

	return 0;
}

static int do_json_request(struct openconnect_info *vpninfo, void *req, int reqlen,
			   int (*rq_parser)(struct openconnect_info *vpninfo,
					    json_value *val))
{
	unsigned char bytes[16384];
	int ret;

	if (vpninfo->dump_http_traffic)
		dump_buf_hex(vpninfo, PRG_DEBUG, '>', req, reqlen);

	ret = vpninfo->ssl_write(vpninfo, req, reqlen);
	if (ret != reqlen) {
		if (ret >= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Short write in Array JSON negotiation\n"));
			return -EIO;
		}
		return ret;
	}

	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to read Array JSON response\n"));
		return ret;
	}

	if (vpninfo->dump_http_traffic)
		dump_buf_hex(vpninfo, PRG_DEBUG, '<', bytes, ret);

	if (ret <= 16 || bytes[16] != '{') {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected response to Array JSON request\n"));
		return -EINVAL;
	}

	dump_buf(vpninfo, '<', (char *)bytes + 16);

	json_settings settings = { 0 };
	char json_err[json_error_max];

	json_value *val = json_parse_ex(&settings, (json_char *)bytes + 16, ret - 16, json_err);
	if (!val) {
	eparse:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse conf50 response\n"));
		return -EINVAL;
	}

	if (vpninfo->verbose >= PRG_DEBUG)
		dump_json(vpninfo, PRG_DEBUG, val);

	if (val->type != json_object) {
		json_value_free(val);
		goto eparse;
	}

	ret = rq_parser(vpninfo, val);

	json_value_free(val);

	return ret;
}


int array_connect(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *reqbuf;
	unsigned char bytes[65536];

	if (!vpninfo->cookies) {
		ret = parse_cookie(vpninfo);
		if (ret)
			return ret;
	}

	/* We abuse ppp_dtls_connect_req for the random client-id */
	if (!vpninfo->ppp_dtls_connect_req) {
		struct oc_text_buf *buf = buf_alloc();
		unsigned char bin[16];

		ret = openconnect_random(bin, sizeof(bin));
		if (ret)
			return ret;

		buf_append(buf, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
			   bin[0], bin[1], bin[2], bin[3], bin[4], bin[5], bin[6], bin[7],
			   bin[8], bin[9], bin[10], bin[11], bin[12], bin[13], bin[14], bin[15]);
		if (buf_error(buf))
			return buf_free(buf);

		vpninfo->ppp_dtls_connect_req = buf;
	}

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();

	buf_append(reqbuf, "GET /vpntunnel HTTP/1.1\r\n");
	http_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "appid: SSPVPN\r\n");
	buf_append(reqbuf, "clientid: %s\r\n", vpninfo->ppp_dtls_connect_req->data);
	buf_append(reqbuf, "cpuid: %s\r\n", vpninfo->ppp_dtls_connect_req->data);
	buf_append(reqbuf, "hostname: %s\r\n", vpninfo->localname);
	buf_append(reqbuf, "payload-ip-version: 6\r\n");
	buf_append(reqbuf, "x-devtype: 6\r\n");
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating array negotiation request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	ret = process_http_response(vpninfo, 1, NULL, reqbuf);
	if (ret < 0)
		goto out;

	if (ret != 201 && ret != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	ret = do_json_request(vpninfo, (void *)conf50, sizeof(conf50),
			      parse_speed_tunnel);
	if (ret)
		goto out;

	ret = do_json_request(vpninfo, (void *)conf54, sizeof(conf54),
			      parse_interface_info);
	if (ret)
		goto out;

	/* Send third request 'ipff' */
	dump_buf_hex(vpninfo, PRG_DEBUG, '>', (void *)ipff, sizeof(ipff));
	ret = vpninfo->ssl_write(vpninfo,  (void *)ipff, sizeof(ipff));
	if (ret != sizeof(ipff)) {
		if (ret >= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Short write in array negotiation\n"));
			ret = -EIO;
		}
		goto out;
	}

	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to read ipff response\n"));
		goto out;
	}

	/* Parse it, learn what we need from it */
	dump_buf_hex(vpninfo, PRG_DEBUG, '<', bytes, ret);

	ret = 0; /* success */
 out:
	if (ret)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
		vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);
	}
	buf_free(reqbuf);

	free(vpninfo->cstp_pkt);
	vpninfo->cstp_pkt = NULL;

	vpninfo->ip_info.mtu = 1400;

	return ret;
}

int array_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int ret;
	int work_done = 0;

	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

	/* FIXME: The poll() handling here is fairly simplistic. Actually,
	   if the SSL connection stalls it could return a WANT_WRITE error
	   on _either_ of the SSL_read() or SSL_write() calls. In that case,
	   we should probably remove POLLIN from the events we're looking for,
	   and add POLLOUT. As it is, though, it'll just chew CPU time in that
	   fairly unlikely situation, until the write backlog clears. */
	while (readable) {
		/* Some servers send us packets that are larger than
		   negotiated MTU. We reserve some extra space to
		   handle that */
		int receive_mtu = MAX(16384, vpninfo->deflate_pkt_size ? : vpninfo->ip_info.mtu);
		int len;

		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + receive_mtu);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		len = ssl_nonblock_read(vpninfo, 0, vpninfo->cstp_pkt->data, receive_mtu);
		if (!len)
			break;
		if (len < 0)
			goto do_reconnect;
		if (len < 8) {
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		/* Check it looks like a valid IP packet, and then check for the special
		 * IP protocol 255 that is used for control stuff. Maybe also look at length
		 * and be prepared to *split* IP packets received in the same read() call. */

		vpninfo->ssl_times.last_rx = time(NULL);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Received uncompressed data packet of %d bytes\n"),
			     len);
		vpninfo->cstp_pkt->len = len;
		queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
		vpninfo->cstp_pkt = NULL;
		work_done = 1;
		continue;
	}


	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

		ret = ssl_nonblock_write(vpninfo, 0,
					 vpninfo->current_ssl_pkt->data,
					 vpninfo->current_ssl_pkt->len);
		if (ret < 0)
			goto do_reconnect;
		else if (!ret) {
			/* -EAGAIN: ssl_nonblock_write() will have added the SSL
			   fd to ->select_wfds if appropriate, so we can just
			   return and wait. Unless it's been stalled for so long
			   that DPD kicks in and we kill the connection. */
			switch (ka_stalled_action(&vpninfo->ssl_times, timeout)) {
			case KA_DPD_DEAD:
				goto peer_dead;
			case KA_REKEY:
				goto do_rekey;
			case KA_NONE:
				return work_done;
			default:
				/* This should never happen */
				;
			}
		}

		if (ret != vpninfo->current_ssl_pkt->len) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 8, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}

		vpninfo->current_ssl_pkt = NULL;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_REKEY:
	do_rekey:
		/* Not that this will ever happen; we don't even process
		   the setting when we're asked for it. */
		vpn_progress(vpninfo, PRG_INFO, _("CSTP rekey due\n"));
		if (vpninfo->ssl_times.rekey_method == REKEY_TUNNEL)
			goto do_reconnect;
		else if (vpninfo->ssl_times.rekey_method == REKEY_SSL) {
			ret = cstp_handshake(vpninfo, 0);
			if (ret) {
				/* if we failed rehandshake try establishing a new-tunnel instead of failing */
				vpn_progress(vpninfo, PRG_ERR, _("Rehandshake failed; attempting new-tunnel\n"));
				goto do_reconnect;
			}

			goto do_dtls_reconnect;
		}
		break;

	case KA_DPD_DEAD:
	peer_dead:
		vpn_progress(vpninfo, PRG_ERR,
			     _("CSTP Dead Peer Detection detected dead peer!\n"));
	do_reconnect:
		ret = ssl_reconnect(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("TCP reconnect failed\n"));
			vpninfo->quit_reason = "TCP reconnect failed";
			return ret;
		}

	do_dtls_reconnect:
		/* succeeded, let's rekey DTLS, if it is not rekeying
		 * itself. */
		if (vpninfo->dtls_state > DTLS_SLEEPING &&
		    vpninfo->dtls_times.rekey_method == REKEY_NONE) {
			vpninfo->dtls_need_reconnect = 1;
		}

		return 1;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP DPD\n"));

		//vpninfo->current_ssl_pkt = (struct pkt *)&dpd_pkt;
		//goto handle_outgoing;
		break;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_state != DTLS_CONNECTED &&
		    vpninfo->outgoing_queue.head)
			break;

		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP Keepalive\n"));

		//vpninfo->current_ssl_pkt = (struct pkt *)&keepalive_pkt;
		//goto handle_outgoing;
		break;

	case KA_NONE:
		;
	}

	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_state != DTLS_CONNECTED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending uncompressed data packet of %d bytes\n"),
			     this->len);

		vpninfo->current_ssl_pkt = this;
		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

int array_bye(struct openconnect_info *vpninfo, const char *reason)
{
	char *orig_path;
	char *res_buf=NULL;
	int ret;

	/* We need to close and reopen the HTTPS connection (to kill
	 * the array tunnel) and submit a new HTTPS request to logout.
	 */
	openconnect_close_https(vpninfo, 0);

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup("prx/000/http/localhost/logout"); /* redirect segfaults without strdup */
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, 0);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;

	if (ret < 0)
		vpn_progress(vpninfo, PRG_ERR, _("Logout failed.\n"));
	else
		vpn_progress(vpninfo, PRG_INFO, _("Logout successful.\n"));

	free(res_buf);
	return ret;
}

