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

#include "openconnect-internal.h"

#define XCAST(x) ((const xmlChar *)(x))

void fortinet_common_headers(struct openconnect_info *vpninfo,
			 struct oc_text_buf *buf)
{
	char *orig_ua = vpninfo->useragent;

	/* XX: This is what openfortivpn uses */
	vpninfo->useragent = (char *)"Mozilla/5.0 SV1";
	http_common_headers(vpninfo, buf);
	vpninfo->useragent = orig_ua;

	/* XXX: Openfortivpn additionally sends the following
	 * headers, even with GET requests, which should not be
	 * necessary:

	   buf_append(buf,
		      "Accept: *" "/" "*\r\n"
		      "Accept-Encoding: gzip, deflate, br\r\n"
		      "Pragma: no-cache\r\n"
		      "Cache-Control: no-store, no-cache, must-revalidate\r\n"
		      "If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n"
		      "Content-Type: application/x-www-form-urlencoded\r\n"
		      "Content-Length: 0\r\n");
	*/
}

int fortinet_obtain_cookie(struct openconnect_info *vpninfo)
{
	return -EINVAL;
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

/* Parse this:
<?xml version="1.0" encoding="utf-8"?>
<sslvpn-tunnel ver="2" dtls="1" patch="1">
  <dtls-config heartbeat-interval="10" heartbeat-fail-count="10" heartbeat-idle-timeout="10" client-hello-timeout="10"/>
  <tunnel-method value="ppp"/>
  <tunnel-method value="tun"/>
  <fos platform="FG100E" major="5" minor="06" patch="6" build="1630" branch="1630"/>
  <client-config save-password="off" keep-alive="on" auto-connect="off"/>
  <ipv4>
    <dns ip="1.1.1.1"/>
    <dns ip="8.8.8.8" domain="foo.com"/>
    <assigned-addr ipv4="172.16.1.1"/>
    <split-tunnel-info>
      <addr ip="10.11.10.10" mask="255.255.255.255"/>
      <addr ip="10.11.1.0" mask="255.255.255.0"/>
    </split-tunnel-info>
  </ipv4>
  <idle-timeout val="3600"/>
  <auth-timeout val="18000"/>
</sslvpn-tunnel>
*/
static int parse_fortinet_xml_config(struct openconnect_info *vpninfo, char *buf, int len,
				     int *ipv4, int *ipv6)
{
	xmlNode *xml_node, *x, *x2;
	xmlDocPtr xml_doc;
	int ret = 0, ii, n_dns = 0 /*, n_nbns = 0, default_route = 0 */;
	char *s = NULL, *s2 = NULL;
	struct oc_text_buf *domains = NULL;

	if (!buf || !len)
		return -EINVAL;

	xml_doc = xmlReadMemory(buf, len, "noname.xml", NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	if (!xml_doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse Fortinet config XML\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), buf);
		return -EINVAL;
	}

	xml_node = xmlDocGetRootElement(xml_doc);
	if (!xml_node || !xmlnode_is_named(xml_node, "sslvpn-tunnel"))
		return -EINVAL;

	/* Clear old options which will be overwritten */
	vpninfo->ip_info.addr = vpninfo->ip_info.netmask = NULL;
	vpninfo->ip_info.addr6 = vpninfo->ip_info.netmask6 = NULL;
	vpninfo->ip_info.domain = NULL;
	vpninfo->cstp_options = NULL;
	for (ii = 0; ii < 3; ii++)
		vpninfo->ip_info.dns[ii] = vpninfo->ip_info.nbns[ii] = NULL;
	free_split_routes(vpninfo);

	domains = buf_alloc();

	if (!xmlnode_get_prop(xml_node, "dtls", &s) && atoi(s))
		vpn_progress(vpninfo, PRG_ERR,
			     _("WARNING: Fortinet server enables DTLS, but OpenConnect does not implement it yet.\n"));

	for (xml_node = xml_node->children; xml_node; xml_node=xml_node->next) {
		if (xmlnode_is_named(xml_node, "auth-timeout") && !xmlnode_get_prop(xml_node, "val", &s))
			vpn_progress(vpninfo, PRG_INFO, _("Session will expire after %d minutes.\n"), atoi(s)/60);
		else if (xmlnode_is_named(xml_node, "idle-timeout") && !xmlnode_get_prop(xml_node, "val", &s)) {
			int sec = vpninfo->idle_timeout = atoi(s);
			vpn_progress(vpninfo, PRG_INFO, _("Idle timeout is %d minutes.\n"), sec/60);
		} else if (xmlnode_is_named(xml_node, "fos")) {
			char platform[80], *p = platform, *e = platform + 80;
			if (!xmlnode_get_prop(xml_node, "platform", &s)) {
			    p+=snprintf(p, e-p, "%s", s);
			    if (!xmlnode_get_prop(xml_node, "major", &s))  p+=snprintf(p, e-p, " v%s", s);
			    if (!xmlnode_get_prop(xml_node, "minor", &s))  p+=snprintf(p, e-p, ".%s", s);
			    if (!xmlnode_get_prop(xml_node, "patch", &s))  p+=snprintf(p, e-p, ".%s", s);
			    if (!xmlnode_get_prop(xml_node, "build", &s))  p+=snprintf(p, e-p, " build %s", s);
			    if (!xmlnode_get_prop(xml_node, "branch", &s))    snprintf(p, e-p, " branch %s", s);
			    vpn_progress(vpninfo, PRG_INFO,
					 _("Reported platform is %s\n"), platform);
			}
		} else if (xmlnode_is_named(xml_node, "ipv4")) {
			*ipv4 = 1;
			for (x = xml_node->children; x; x=x->next) {
				if (xmlnode_is_named(x, "assigned-addr") && !xmlnode_get_prop(x, "ipv4", &s)) {
					vpn_progress(vpninfo, PRG_INFO, _("Got legacy IP address %s\n"), s);
					vpninfo->ip_info.addr = add_option(vpninfo, "ipaddr", &s);
				} else if (xmlnode_is_named(x, "dns")) {
					if (!xmlnode_get_prop(x, "domain", &s) && s && *s) {
						vpn_progress(vpninfo, PRG_INFO, _("Got search domain %s\n"), s);
						buf_append(domains, "%s ", s);
					}
					if (!xmlnode_get_prop(x, "ip", &s) && s && *s) {
						vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d DNS server %s\n"), 4, s);
						if (n_dns < 3) vpninfo->ip_info.dns[n_dns++] = add_option(vpninfo, "DNS", &s);
					}
				} else if (xmlnode_is_named(x, "split-tunnel-info")) {
					for (x2 = x->children; x2; x2=x2->next) {
						if (xmlnode_is_named(x2, "addr")) {
							if (!xmlnode_get_prop(x2, "ip", &s) &&
							    !xmlnode_get_prop(x2, "mask", &s2) &&
							    s && s2 && *s && *s2) {
								struct oc_split_include *inc = malloc(sizeof(*inc));
								char *route = malloc(32);
								if (!route || !inc) {
									free(route);
									free(inc);
									ret = -ENOMEM;
									goto out;
								}
								snprintf(route, 32, "%s/%s", s, s2);
								vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d route %s\n"), 4, route);
								inc->route = add_option(vpninfo, "split-include", &route);
								inc->next = vpninfo->ip_info.split_includes;
								vpninfo->ip_info.split_includes = inc;
								/* XX: static analyzer doesn't realize that add_option will steal route's reference, so... */
								free(route);
							}
						}
					}
				}
			}
		}
	}

	/* if (default_route && *ipv4) */
	/* 	vpninfo->ip_info.netmask = strdup("0.0.0.0"); */
	/* if (default_route && *ipv6) */
	/*       vpninfo->ip_info.netmask6 = strdup("::/0"); */
	if (buf_error(domains) == 0 && domains->pos > 0) {
		domains->data[domains->pos-1] = '\0';
		vpninfo->ip_info.domain = add_option(vpninfo, "search", &domains->data);
	}
	buf_free(domains);

	if (*ipv4 < 1 && *ipv6 < 1) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to find VPN options\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), buf);
		ret = -EINVAL;
	}
 out:
 	xmlFreeDoc(xml_doc);
	free(s);
	free(s2);
	return ret;
}

int fortinet_connect(struct openconnect_info *vpninfo)
{
	char *res_buf = NULL;
	struct oc_text_buf *reqbuf = NULL;
	int ret, ipv4 = -1, ipv6 = -1;

	/* XXX: We should do what cstp_connect() does to check that configuration
	   hasn't changed on a reconnect. */

	if (!vpninfo->cookies) {
		/* XX: This will happen if authentication was separate/external */
		ret = internal_split_cookies(vpninfo, 1, "SVPNCOOKIE");
		if (ret)
			return ret;
	}

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();

	/* Request VPN allocation
	 *
	 * XXX: Should this be done on every reconnect, or should it have
	 * been part of fortinet_obtain_cookie(). For the moment while
	 * we're letting the auth happen externally for now, let's do it
	 * here...
	 */
	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup("remote/index");
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, 0);
	/* XXX: 401/403 is apparently normal and can be ignored (further
	 * evidence that this is vestigial, or at least not necessary for
	 * reconnect.
	 */
	if (ret < 0 && ret != -EPERM)
		goto out;
	/* We don't care what it returned */
	free(res_buf);
	res_buf = NULL;

	/* XXX: Why was auth_request_vpn_allocation() doing this anyway?
	 * It's fetching the legacy non-XML configuration, isn't it?
	 * Do we *actually* have to do this, before fetching the XML config?
	 */
	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup("remote/fortisslvpn");
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, 0);
	if (ret < 0)
		goto out;
	/* We don't care what it returned as long as it was successful */
	free(res_buf);
	res_buf = NULL;
	free(vpninfo->urlpath);

	/* Now fetch the connection options in XML format */
	vpninfo->urlpath = strdup("remote/fortisslvpn_xml");
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, 0);
	if (ret < 0) {
		if (ret == -EPERM)
			vpn_progress(vpninfo, PRG_ERR,
				     _("Server doesn't support XML config format, only ancient HTML. Not currently implemented.\n"));
		goto out;
	}

	ret = parse_fortinet_xml_config(vpninfo, res_buf, ret, &ipv4, &ipv6);
	if (ret)
		goto out;

	if (ipv4 == -1)
		ipv4 = 0;
	if (ipv6 == -1)
		ipv6 = 0;

	/* XX: Openfortivpn closes and reopens the HTTPS connection here, and
	 * also sends 'Host: sslvpn' (rather than the true hostname). Neither
	 * appears to be necessary, and either might prevent connecting to
	 * a vhost-based Fortinet server.
	 */
	ret = openconnect_open_https(vpninfo);
	if (ret)
		goto out;
	reqbuf = buf_alloc();
	buf_append(reqbuf, "GET /remote/sslvpn-tunnel HTTP/1.1\r\n");
	fortinet_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating fortinet connection request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	/* XX: If this connection request succeeds, no HTTP response appears.
	 * We just start sending our encapsulated PPP configuration packets.
	 * However, if the request FAILS, it WILL send an HTTP response.
	 * We handle that in the PPP mainloop.
	 *
	 * Don't blame me. I didn't design this.
	 */

	ret = openconnect_ppp_new(vpninfo, PPP_ENCAP_FORTINET, ipv4, ipv6);

 out:
	if (ret)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
	}
	buf_free(reqbuf);
	free(res_buf);

	return ret;
}

int fortinet_bye(struct openconnect_info *vpninfo, const char *reason)
{
	char *orig_path;
	char *res_buf=NULL;
	int ret;

	/* XX: handle clean PPP termination?
	   ppp_bye(vpninfo); */

	/* We need to close and reopen the HTTPS connection (to kill
	 * the fortinet tunnel) and submit a new HTTPS request to logout.
	 */
	openconnect_close_https(vpninfo, 0);

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup("remote/logout");
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
