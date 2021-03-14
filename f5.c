/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020-2021 David Woodhouse, Daniel Lenski
 *
 * Author: David Woodhouse <dwmw2@infradead.org>, Daniel Lenski <dlenski@gmail.com>
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

#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>

#include "openconnect-internal.h"

#define XCAST(x) ((const xmlChar *)(x))

static struct oc_auth_form *plain_auth_form() {
	struct oc_auth_form *form;
	struct oc_form_opt *opt, *opt2;

	form = calloc(1, sizeof(*form));
	if (!form) {
	nomem:
		free_auth_form(form);
		return NULL;
	}
	opt = form->opts = calloc(1, sizeof(*opt));
	if (!opt)
		goto nomem;
	opt->label = strdup("username:");
	opt->name = strdup("username");
	opt->type = OC_FORM_OPT_TEXT;

	opt2 = opt->next = calloc(1, sizeof(*opt2));
	if (!opt2)
		goto nomem;
	opt2->label = strdup("password:");
	opt2->name = strdup("password");
	opt2->type = OC_FORM_OPT_PASSWORD;
	return form;
}

static int check_cookie_success(struct openconnect_info *vpninfo)
{
	struct oc_vpn_option *cookie;
	const char *session = NULL, *f5_st = NULL;

	/* XX: if login succeeded worked, we should have a response size of zero, and F5_ST
	 * and MRHSession cookies in the response.
	 */
	for (cookie = vpninfo->cookies; cookie; cookie = cookie->next) {
		if (!strcmp(cookie->option, "MRHSession"))
			session = cookie->value;
		else if (!strcmp(cookie->option, "F5_ST"))
			f5_st = cookie->value;
	}
	if (session && f5_st) {
		free(vpninfo->cookie);
		if (asprintf(&vpninfo->cookie, "MRHSession=%s; F5_ST=%s", session, f5_st) <= 0)
			return -ENOMEM;
		return 0;
	}
	return -ENOENT;
}

int f5_obtain_cookie(struct openconnect_info *vpninfo)
{
	int ret;
	xmlDocPtr doc = NULL;
	xmlNode *node;
	struct oc_text_buf *req_buf = NULL;
	struct oc_auth_form *form = NULL;
	char *form_id = NULL;

	req_buf = buf_alloc();
	if ((ret = buf_error(req_buf)))
		goto out;

	while (1) {
		char *resp_buf = NULL;
		char *url;

		if (req_buf && req_buf->pos)
			ret = do_https_request(vpninfo, "POST",
					       "application/x-www-form-urlencoded",
					       req_buf, &resp_buf, 2);
		else
			ret = do_https_request(vpninfo, "GET", NULL, NULL,
					       &resp_buf, 2);

		if (ret < 0)
			break;

		if (!check_cookie_success(vpninfo)) {
			free(resp_buf);
			ret = 0;
			break;
		}

		url = internal_get_url(vpninfo);
		if (!url) {
			free(resp_buf);
		nomem:
			ret = -ENOMEM;
			break;
		}

		doc = htmlReadMemory(resp_buf, ret, url, NULL,
				     HTML_PARSE_RECOVER|HTML_PARSE_NOERROR|HTML_PARSE_NOWARNING|HTML_PARSE_NONET);
		free(url);
		free(resp_buf);
		if (!doc) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse HTML document\n"));
			ret = -EINVAL;
			break;
		}

		buf_truncate(req_buf);

		node = find_form_node(doc);
		if (!node) {
			/* XX: some F5 VPNs simply do not have a static HTML form to parse */
			vpn_progress(vpninfo, PRG_ERR,
				     _("WARNING: no HTML login form found; assuming username and password fields\n"));
			if ((form = plain_auth_form()) == NULL)
				goto nomem;
		} else {
			if (!xmlnode_get_prop(node, "id", &form_id) && !strcmp(form_id, "auth_form"))
				form = parse_form_node(vpninfo, node, NULL, FORM_FLAVOR_F5, NULL);
			else {
				vpn_progress(vpninfo, PRG_ERR, _("Unknown form ID '%s' (expected 'auth_form')\n"),
					     form_id);

				fprintf(stderr, _("Dumping unknown HTML form:\n"));
				htmlNodeDumpFileFormat(stderr, node->doc, node, NULL, 1);
				ret = -EINVAL;
				break;
			}
		}

		if (!form) {
			ret = -EINVAL;
			break;
		}

		/* XX: do_gen_tokencode would go here, if we knew of any
		 * token-based 2FA options for F5.
		 */

		do {
			ret = process_auth_form(vpninfo, form);
		} while (ret == OC_FORM_RESULT_NEWGROUP);
		if (ret)
			goto out;

		append_form_opts(vpninfo, form, req_buf);
		if ((ret = buf_error(req_buf)))
			goto out;

		if (form->action) {
			vpninfo->redirect_url = form->action;
			form->action = NULL;
		}
		free_auth_form(form);
		form = NULL;
		if (vpninfo->redirect_url)
			handle_redirect(vpninfo);

		xmlFreeDoc(doc);
		doc = NULL;
	}

 out:
	if (doc)
		xmlFreeDoc(doc);
	free(form_id);
	if (form) free_auth_form(form);
	if (req_buf) buf_free(req_buf);
	return ret;
}

/*
 * Parse the 'favorites' profile information from
 * /vdesk/vpn/index.php3?outform=xml&client_version=2.0
 * which looks something like this:
 *
 *   <?xml version="1.0" encoding="utf-8"?>
 *     <favorites type="VPN" limited="YES">
 *       <favorite id="/Common/demo_vpn_resource">
 *         <caption>demo_vpn_resource</caption>
 *         <name>/Common/demo_vpn_resource</name>
 *         <params>resourcename=/Common/demo_vpn_resource</params>
 *       </favorite>
 *     </favorites>
 *
 * Extract the content of the "params" node which is needed for the
 * next request.
 */
static int parse_profile(struct openconnect_info *vpninfo, char *buf, int len,
			 char **params)
{
	xmlDocPtr xml_doc;
	xmlNode *xml_node, *xml_node2, *xml_node3;
	char *type = NULL;
	int ret;

	if (!buf || !len)
		return -EINVAL;

	xml_doc = xmlReadMemory(buf, len, "noname.xml", NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	if (!xml_doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse F5 profile response\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), buf);
		return -EINVAL;
	}
	xml_node = xmlDocGetRootElement(xml_doc);
	for (; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!xmlnode_is_named(xml_node, "favorites"))
			continue;

		type = (char *)xmlGetProp(xml_node, XCAST("type"));
		if (!type)
			continue;

		if (strcmp(type, "VPN")) {
			free(type);
			continue;
		}
		free(type);

		for (xml_node2 = xmlFirstElementChild(xml_node);
		     xml_node2;
		     xml_node2 = xmlNextElementSibling(xml_node2)) {
			if (!xmlnode_is_named(xml_node2, "favorite"))
				continue;

			for (xml_node3 = xmlFirstElementChild(xml_node2);
			     xml_node3;
			     xml_node3 = xmlNextElementSibling(xml_node3)) {
				if (!xmlnode_is_named(xml_node3, "params"))
					continue;
				*params = (char *)xmlNodeGetContent(xml_node3);
				ret = 0;
				goto out;
			}
		}
	}

	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to find VPN profile parameters\n"));
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Response was:%s\n"), buf);
	ret = -EINVAL;
 out:
	xmlFreeDoc(xml_doc);
	return ret;
}

static int xmlnode_bool_or_int_value(struct openconnect_info *vpninfo, xmlNode *node)
{
	int ret = -1;
	char *content = (char *)xmlNodeGetContent(node);
	if (!content)
		return -1;

	if (isdigit(content[0]))
		ret = atoi(content);
	if (!strcasecmp(content, "yes") || !strcasecmp(content, "on"))
		ret = 1;
	if (!strcasecmp(content, "no") || !strcasecmp(content, "off"))
		ret = 0;

	free(content);
	return ret;
}

/* We behave like CSTP — create a linked list in vpninfo->cstp_options
 * with the strings containing the information we got from the server,
 * and oc_ip_info contains const copies of those pointers.
 *
 * (unlike version in oncp.c, val is stolen rather than strdup'ed) */

static const char *add_option(struct openconnect_info *vpninfo, const char *opt, char **val)
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
	new->next = vpninfo->cstp_options;
	vpninfo->cstp_options = new;

	return new->value;
}

static int parse_options(struct openconnect_info *vpninfo, char *buf, int len,
			 char **session_id, char **ur_z, int *ipv4, int *ipv6, int *hdlc)
{
	xmlNode *fav_node, *obj_node, *xml_node;
	xmlDocPtr xml_doc;
	int ret = 0, ii, n_dns = 0, n_nbns = 0, default_route = 0;
	char *s = NULL;
	struct oc_text_buf *domains = NULL;

	if (!buf || !len)
		return -EINVAL;

	xml_doc = xmlReadMemory(buf, len, "noname.xml", NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	if (!xml_doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse F5 options response\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), buf);
		return -EINVAL;
	}
	fav_node = xmlDocGetRootElement(xml_doc);
	if (!xmlnode_is_named(fav_node, "favorite"))
		goto err;

	obj_node = xmlFirstElementChild(fav_node);
	if (!xmlnode_is_named(obj_node, "object"))
		goto err;

	/* Clear old options which will be overwritten */
	vpninfo->ip_info.addr = vpninfo->ip_info.netmask = NULL;
	vpninfo->ip_info.addr6 = vpninfo->ip_info.netmask6 = NULL;
	vpninfo->ip_info.domain = NULL;
	vpninfo->cstp_options = NULL;
	for (ii = 0; ii < 3; ii++)
		vpninfo->ip_info.dns[ii] = vpninfo->ip_info.nbns[ii] = NULL;
	free_split_routes(vpninfo);

	domains = buf_alloc();

	for (xml_node = xmlFirstElementChild(obj_node);
	     xml_node;
	     xml_node = xmlNextElementSibling(xml_node)) {
		if (xmlnode_is_named(xml_node, "ur_Z"))
			*ur_z = (char *)xmlNodeGetContent(xml_node);
		else if (xmlnode_is_named(xml_node, "Session_ID"))
			*session_id = (char *)xmlNodeGetContent(xml_node);
		else if (xmlnode_is_named(xml_node, "IPV4_0"))
			*ipv4 = xmlnode_bool_or_int_value(vpninfo, xml_node);
		else if (xmlnode_is_named(xml_node, "IPV6_0")) {
			if (!vpninfo->disable_ipv6)
				*ipv6 = xmlnode_bool_or_int_value(vpninfo, xml_node);
		} else if (xmlnode_is_named(xml_node, "hdlc_framing"))
			*hdlc = xmlnode_bool_or_int_value(vpninfo, xml_node);
		else if (xmlnode_is_named(xml_node, "idle_session_timeout")) {
			int sec = vpninfo->idle_timeout = xmlnode_bool_or_int_value(vpninfo, xml_node);
			vpn_progress(vpninfo, PRG_INFO, _("Idle timeout is %d minutes\n"), sec/60);
		} else if (xmlnode_is_named(xml_node, "tunnel_port_dtls")) {
			int port = xmlnode_bool_or_int_value(vpninfo, xml_node);
			udp_sockaddr(vpninfo, port);
			vpn_progress(vpninfo, PRG_INFO, _("DTLS port is %d\n"), port);
		} else if (xmlnode_is_named(xml_node, "UseDefaultGateway0")) {
			default_route = xmlnode_bool_or_int_value(vpninfo, xml_node);
			vpn_progress(vpninfo, PRG_INFO, _("Got UseDefaultGateway0 value of %d\n"), default_route);
		} else if (xmlnode_is_named(xml_node, "SplitTunneling0")) {
			int st = xmlnode_bool_or_int_value(vpninfo, xml_node);
			vpn_progress(vpninfo, PRG_INFO, _("Got SplitTunneling0 value of %d\n"), st);
                }
		/* XX: This is an objectively stupid way to use XML, a hierarchical data format. */
		else if (   (!strncmp((char *)xml_node->name, "DNS", 3) && isdigit(xml_node->name[3]))
			 || (!strncmp((char *)xml_node->name, "DNS6_", 5) && isdigit(xml_node->name[5])) ) {
			free(s);
			s = (char *)xmlNodeGetContent(xml_node);
			if (s && *s) {
				vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d DNS server %s\n"),
					     xml_node->name[4]=='_' ? 6 : 4, s);
				if (n_dns < 3) vpninfo->ip_info.dns[n_dns++] = add_option(vpninfo, "DNS", &s);
			}
		} else if (!strncmp((char *)xml_node->name, "WINS", 4) && isdigit(xml_node->name[4])) {
			free(s);
			s = (char *)xmlNodeGetContent(xml_node);
			if (s && *s) {
				vpn_progress(vpninfo, PRG_INFO, _("Got WINS/NBNS server %s\n"), s);
				if (n_nbns < 3) vpninfo->ip_info.dns[n_nbns++] = add_option(vpninfo, "WINS", &s);
			}
		} else if (!strncmp((char *)xml_node->name, "DNSSuffix", 9) && isdigit(xml_node->name[9])) {
			free(s);
			s = (char *)xmlNodeGetContent(xml_node);
			if (s && *s) {
				vpn_progress(vpninfo, PRG_INFO, _("Got search domain %s\n"), s);
				buf_append(domains, "%s ", s);
			}
		} else if (   (!strncmp((char *)xml_node->name, "LAN", 3) && isdigit((char)xml_node->name[3]))
			   || (!strncmp((char *)xml_node->name, "LAN6_", 5) && isdigit((char)xml_node->name[5]))) {
			s = (char *)xmlNodeGetContent(xml_node);
			if (s && *s) {
				char *word, *next;
				struct oc_split_include *inc;

				for (word = (char *)add_option(vpninfo, "route-list", &s);
				     *word; word = next) {
					for (next = word; *next && !isspace(*next); next++);
					if (*next)
						*next++ = 0;
					if (next == word + 1)
						continue;

					inc = malloc(sizeof(*inc));
					inc->route = word;
					inc->next = vpninfo->ip_info.split_includes;
					vpninfo->ip_info.split_includes = inc;
					vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d route %s\n"),
						     xml_node->name[4]=='_' ? 6 : 4, word);
				}
			}
		}
	}

	if (default_route && *ipv4)
		vpninfo->ip_info.netmask = strdup("0.0.0.0");
	if (default_route && *ipv6)
		vpninfo->ip_info.netmask6 = strdup("::/0");
	if (buf_error(domains) == 0 && domains->pos > 0) {
		domains->data[domains->pos-1] = '\0';
		vpninfo->ip_info.domain = add_option(vpninfo, "search", &domains->data);
	}
	buf_free(domains);

	if ( (*ipv4 < 1 && *ipv6 < 1) || !*ur_z || !*session_id) {
	err:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to find VPN options\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), buf);
		ret = -EINVAL;
	}
 	xmlFreeDoc(xml_doc);
	free(s);
	return ret;
}

static int get_ip_address(struct openconnect_info *vpninfo, char *header, char *val) {
	char *s = strdup(val);
	if (!strcasecmp(header, "X-VPN-client-IP")) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("Got legacy IP address %s\n"), val);
		vpninfo->ip_info.addr = add_option(vpninfo, "ipaddr", &s);
	} else if (!strcasecmp(header, "X-VPN-client-IPv6")) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("Got IPv6 address %s\n"), val);
		/* XX: Should we treat this as a /64 netmask? Or an /128 address? */
		vpninfo->ip_info.addr6 = add_option(vpninfo, "ipaddr6", &s);
	}
        /* XX: The server's IP address(es) X-VPN-server-{IP,IPv6} are also
         * sent, but the utility of these is unclear. As remarked in oncp.c,
	 * "this is a tunnel; having a gateway is meaningless." */
	free(s);
	return 0;
}

int f5_connect(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *reqbuf = NULL;
	struct oc_vpn_option *cookie;
	char *profile_params = NULL;
	char *sid = NULL, *ur_z = NULL;
	int ipv4 = -1, ipv6 = -1, hdlc = -1;
	char *res_buf = NULL;
	struct oc_vpn_option *old_cstp_opts = vpninfo->cstp_options;
	const char *old_addr = vpninfo->ip_info.addr;
	const char *old_netmask = vpninfo->ip_info.netmask;
	const char *old_addr6 = vpninfo->ip_info.addr6;
	const char *old_netmask6 = vpninfo->ip_info.netmask6;

	if (!vpninfo->cookies) {
		/* XX: This will happen if authentication was separate/external */
		ret = internal_split_cookies(vpninfo, 1, "MRHSession");
		if (ret)
			return ret;
	}

	/* XX: parse "session timeout" cookie to get auth expiration */
	for (cookie = vpninfo->cookies; cookie; cookie = cookie->next) {
		if (!strcmp(cookie->option, "F5_ST")) {
			int junk, start, dur;
			char c = 0;
			if (sscanf(cookie->value, "%dz%dz%dz%dz%d%c", &junk, &junk, &junk, &start, &dur, &c) >= 5
			    && (c == 0 || c == 'z'))
				vpninfo->auth_expiration = start + dur;
			break;
		}
	}

	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup("vdesk/vpn/index.php3?outform=xml&client_version=2.0");
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, 0);
	if (ret < 0)
		goto out;

	ret = parse_profile(vpninfo, res_buf, ret, &profile_params);
	if (ret)
		goto out;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Got profile parameters '%s'\n"), profile_params);

	free(res_buf);
	res_buf = NULL;

	free(vpninfo->urlpath);
	if (asprintf(&vpninfo->urlpath, "vdesk/vpn/connect.php3?%s&outform=xml&client_version=2.0",
		     profile_params) == -1) {
		ret = -ENOMEM;
		goto out;
	}
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, 0);
	if (ret < 0)
		goto out;

	ret = parse_options(vpninfo, res_buf, ret, &sid, &ur_z, &ipv4, &ipv6, &hdlc);
	if (ret)
		goto out;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Got ipv4 %d ipv6 %d hdlc %d ur_Z '%s'\n"), ipv4, ipv6, hdlc, ur_z);

	if (ipv4 == -1)
		ipv4 = 0;
	if (ipv6 == -1)
		ipv6 = 0;

	/* Now establish the actual connection */
	ret = openconnect_open_https(vpninfo);
	if (ret)
		goto out;

	reqbuf = buf_alloc();
	buf_append(reqbuf, "GET /myvpn?sess=%s&hdlc_framing=%s&ipv4=%s&ipv6=%s&Z=%s&hostname=",
		   sid, hdlc?"yes":"no", ipv4?"yes":"no", ipv6?"yes":"no", ur_z);
	buf_append_base64(reqbuf, vpninfo->localname, strlen(vpninfo->localname));
	buf_append(reqbuf, " HTTP/1.1\r\n");
	http_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error establishing F5 connection\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	ret = process_http_response(vpninfo, 1, get_ip_address, reqbuf);
	if (ret < 0)
		goto out;

	if (ret != 201 && ret != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		ret = (ret == 504) ? -EPERM : -EINVAL;
		goto out;
	}

	ret = check_address_sanity(vpninfo, old_addr, old_netmask, old_addr6, old_netmask6);
	if (ret < 0)
		goto out;

	ret = openconnect_ppp_new(vpninfo, hdlc ? PPP_ENCAP_F5_HDLC : PPP_ENCAP_F5, ipv4, ipv6);

 out:
	free_optlist(old_cstp_opts);
	free(res_buf);
	free(profile_params);
	free(sid);
	free(ur_z);
	if (ret)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
	}
	buf_free(reqbuf);

	return ret;
}

int f5_bye(struct openconnect_info *vpninfo, const char *reason)
{
	char *orig_path;
	char *res_buf = NULL;
	int ret;

	/* We need to close and reopen the HTTPS connection (to kill
	 * the f5 tunnel) and submit a new HTTPS request to logout.
	 */
	openconnect_close_https(vpninfo, 0);

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup("vdesk/hangup.php3?hangup_error=1"); /* redirect segfaults without strdup */
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
