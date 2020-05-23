/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020 Andreas Gnau
 *
 * Author: Andreas Gnau <rondom@rondom.de>
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

#include <ctype.h>
#include <errno.h>

#include "openconnect-internal.h"

static char const ipv4_default_route[] = "0.0.0.0/0.0.0.0";
static char const ipv6_default_route[] = "::/0";

int nx_obtain_cookie(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR, _("Authentication for Net Extender not implemented yet.\n"));
	return -EINVAL;
}

void nx_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	http_common_headers(vpninfo, buf);
	dump_buf(vpninfo, PRG_ERR, buf->data); // TODO: XXX
	// TODO: Is this the place to manipulate user agent (NX requires the UA to contain netextender)
}
/*
 * Trim any trailing blanks from key and
 * by validating the key for acceptable characters
 * detect HTML in a roundabout way
 */
static int validate_and_trim_key(char const **key, int *key_len)
{
	char const *k = *key;
	int i;
	while (isblank(k[*key_len - 1]))
		*key_len -= 1;

	for (i = 0; i < *key_len; i++) {
		if (!isalnum(k[i]) && k[i] != '.' && k[i] != '_') {
			return -EINVAL;
		}
	}
	return 0;
}

/*
 * first remove blanks in front,
 * then remove optional trailing semicolon and enclosing quotes
 */
static void trim_value(char const **value, int *value_len)
{
	while (isblank(**value))
		(*value)++;

	if (*(*value + *value_len - 1) == ';') {
		*value_len -= 1;
	}

	if (**value == '"' && *(*value + *value_len - 1) == '"') {
		(*value)++;
		*value_len -= 2;
	}
}

/*
 * allocates cfg_key and cfg_value,
 * leaves line intact so it can be printed in case of failure
 */
static int parse_connection_info_line(struct openconnect_info *vpninfo, char const *line, int const line_len,
				      char **cfg_key, char **cfg_value)
{
	/*
	<html><head><title>SonicWALL - Virtual Office</title><meta http-equiv='pragma' content='no-cache'><meta http-equiv='cache-control' content='no-cache'><meta http-equiv='cache-control' content='must-revalidate'><meta http-equiv='Content-Type' content='text/html;charset=UTF-8'><link href='/styleblueblackgrey.css' rel=stylesheet type='text/css'><script>function neLauncherInit(){
	NELaunchX1.userName = "someUsername";
	NELaunchX1.domainName = "LocalDomain";
	SessionId = QkMO6MFoXUdjMiCNLyakRw==;
	Route = 1.2.3.0/255.255.255.0
	Route = 4.5.6.0/255.255.255.0
	Ipv6Route = dead:beef:f00d:20::/64
	Ipv6Route = dead:beef:f00d:20::/64
	dns1 = 1.2.3.4
	dns2 = 4.5.6.7
	ipv6Support = yes
	GlobalIPv6Addr = dead:beef:f00d:1::1234
	dnsSuffix = example.com
	dnsSuffixes =example.com
	pppFrameEncoded = 0;
	PppPref = async
	TunnelAllMode = 0;
	ExitAfterDisconnect = 0;
	UninstallAfterExit = 0;
	NoProfileCreate = 0;
	AllowSavePassword = 0;
	AllowSaveUser = 1;
	AllowSavePasswordInKeychain = 0
	AllowSavePasswordInKeystore = 0
	ClientIPLower = "1.2.3.123";
	ClientIPHigh = "1.2.3.234";
	}</script></head></html>
	 */
	char const *key = NULL, *value = NULL;
	int key_len, value_len;
	char *equal_sign;
	*cfg_key = NULL;
	*cfg_value = NULL;
	/*
	 * The response is HTML and pretty inconsistent.
	 * Try to parse every line on a best-effort basis.
	 * - actual data is enclosed in a script-tag on some servers, on others they are not
	 * - keys are in one of the following forms delimited by newlines:
	 *    - Key = Value
	 *    - Key =Value
	 *    - Key = Value;
	 *    - Key = "Value"
	 *    - Key = "Value";
	 * - One server might use any of the above in the same response
	 *   (with/without quotes, with/without trailing semicolon,
	 *    with/without space around equals-sign)
	 */

	equal_sign = strchr(line, '=');
	if (!equal_sign)
		return -EINVAL;

	key = line;
	key_len = equal_sign - key;
	if (validate_and_trim_key(&key, &key_len))
		return -EINVAL;

	value = equal_sign + 1;
	value_len = line_len - (value - line);
	trim_value(&value, &value_len);

	*cfg_value = strndup(value, value_len);
	*cfg_key = strndup(key, key_len);
	if (!*cfg_key || !*cfg_value) {
		free(cfg_key);
		free(cfg_value);
		return -ENOMEM;
	}
	return 0;
}

/*
 * allocates and adds a new cstp_option (key and value must be allocated by someone else)
 */
static char *add_cstp_option(struct openconnect_info *vpninfo, char *key, char *value)
{
	struct oc_vpn_option *option_entry = malloc(sizeof(*option_entry));
	if (!option_entry) {
		return NULL;
	}
	option_entry->option = key;
	option_entry->value = value;
	option_entry->next = vpninfo->cstp_options;
	vpninfo->cstp_options = option_entry;
	return value;
}

static struct oc_split_include *add_split_include(struct openconnect_info *vpninfo, char const *route)
{
	struct oc_split_include *include = malloc(sizeof(*include));
	if (!include) {
		return NULL;
	}
	include->route = route;
	include->next = vpninfo->ip_info.split_includes;
	vpninfo->ip_info.split_includes = include;
	return include;
}

/*
 * Takes ownership of key and value
 * We behave like CSTP — create a linked list in vpninfo->cstp_options
 * with the strings containing the information we got from the server,
 * and oc_ip_info contains const copies of those pointers.
 * Takes care of freeing if key is not added to vpninfo->cstp_options.
 */
static int populate_vpninfo(struct openconnect_info *vpninfo, char *key, char *value)
{
	if (strcmp(key, "Route") == 0 || strcmp(key, "Ipv6Route") == 0) {
		add_split_include(vpninfo, add_cstp_option(vpninfo, key, value));
	} else if (strcmp(key, "dns1") == 0) {
		vpninfo->ip_info.dns[0] = add_cstp_option(vpninfo, key, value);
	} else if (strcmp(key, "dns2") == 0) {
		vpninfo->ip_info.dns[1] = add_cstp_option(vpninfo, key, value);
	} else if (strcmp(key, "GlobalIPv6Addr") == 0) {
		vpninfo->ip_info.addr6 = add_cstp_option(vpninfo, key, value);
	} else if (strcmp(key, "dnsSuffix") == 0) {
		if (vpninfo->ip_info.domain) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Not overwriting DNS domains with 'dnsSuffix', "
				       "because value from dnsSuffixes take precedence"));
			free(key);
			free(value);
			return 0;
		}
		vpninfo->ip_info.domain = add_cstp_option(vpninfo, key, value);
	} else if (strcmp(key, "dnsSuffixes") == 0) {
		vpninfo->ip_info.domain = add_cstp_option(vpninfo, key, value);
	} else {
		/* going to throw away key and value for the following keys */
		if (strcmp(key, "NX_TUNNEL_PROTO_VER") == 0) {
			if (strcmp(value, "2.0") != 0)
				vpn_progress(vpninfo, PRG_INFO,
					     _("Unknown NX tunnel protocol version '%s'.\n"
					       "Please report this to <openconnect-devel@lists.infradead.org>.\n"),
					     value);

		} else if (strcmp(key, "TunnelAllMode") == 0) {
			if (strcmp(value, "1") == 0) {
				add_split_include(vpninfo, ipv4_default_route);
				if (vpninfo->ip_info.addr6) {
					add_split_include(vpninfo, ipv6_default_route);
				}
			}
		} else if (strcmp(key, "SessionId") == 0) {
			/* separate in order to not print out secrets in message below */
		} else if (strcmp(key, "NELaunchX1.userName") == 0 ||
			   strcmp(key, "NELaunchX1.domainName") == 0 ||
			   strcmp(key, "ipv6Support") == 0 ||
			   strcmp(key, "pppFrameEncoded") == 0 ||
			   strcmp(key, "PppPref") == 0 ||
			   strcmp(key, "ExitAfterDisconnect") == 0 ||
			   strcmp(key, "UninstallAfterExit") == 0 ||
			   strcmp(key, "NoProfileCreate") == 0 ||
			   strcmp(key, "AllowSavePassword") == 0 ||
			   strcmp(key, "AllowSaveUser") == 0 ||
			   strcmp(key, "AllowSavePasswordInKeychain") == 0 ||
			   strcmp(key, "AllowSavePasswordInKeystore") == 0 ||
			   strcmp(key, "ClientIPLower") == 0 ||
			   strcmp(key, "ClientIPHigh") == 0) {
			vpn_progress(vpninfo, PRG_TRACE, _("Ignoring known config key/value-pair: %s: %s\n"), key,
				     value);
		} else {
			vpn_progress(vpninfo, PRG_DEBUG, _("Encountered unknown config key/value-pair: %s: %s\n"), key,
				     value);
		}
		free(key);
		free(value);
	}
	return 0;
}

static int nx_get_connection_info(struct openconnect_info *vpninfo)
{
	int ret = 0;
	char *result_buf = NULL;
	char *line, *line_break;
	int line_len;
	char *key, *value;
	char url[70];
	char const *support_ipv6 = (!vpninfo->disable_ipv6) ? "yes" : "no";
	snprintf(url, sizeof(url), "cgi-bin/sslvpnclient?launchplatform=mac&neProto=3&supportipv6=%s", support_ipv6);
	if (!vpninfo->cookies && vpninfo->cookie)
		http_add_cookie(vpninfo, "swap", vpninfo->cookie, 1);
	vpninfo->urlpath = url;
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &result_buf, 0);
	vpninfo->urlpath = NULL;
	if (ret < 0)
		goto out;

	/* clear old data */
	/* TODO: fail on changing IP at reconnection later during IPCP negotiation? */
	vpninfo->ip_info.addr6 = vpninfo->ip_info.netmask6 = NULL;
	vpninfo->ip_info.domain = NULL;
	vpninfo->ip_info.dns[0] = vpninfo->ip_info.dns[1] = vpninfo->ip_info.dns[2] = NULL;
	free_split_routes(vpninfo);
	free_optlist(vpninfo->cstp_options);

	if (!strstr(result_buf, "SessionId")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Did not get the expected response to the NX connection info request\n"
			       "Has the session expired?\n"));
		ret = -EINVAL;
		goto out;
	}
	line = result_buf;
	while (line) {
		line_break = strchr(line, '\n');
		if (line_break)
			*line_break = '\0';

		line_len = (line_break) ? line_break - line : strlen(line);
		ret = parse_connection_info_line(vpninfo, line, line_len, &key, &value);
		if (ret) {
			vpn_progress(vpninfo, PRG_DEBUG, _("Could not parse NX connection info line, ignoring: %s\n"),
				     line);
			ret = 0;
		} else {
			ret = populate_vpninfo(vpninfo, key, value);
			if (ret)
				goto out;
		}
		line = line_break ? (line_break + 1) : NULL;
	}
out:
	free(result_buf);
	return ret;
}

int nx_connect(struct openconnect_info *vpninfo)
{
	int ret = -EINVAL;
	struct oc_text_buf *reqbuf = NULL;
	char *auth_token = NULL;
	int auth_token_len = -1;
	int ipv4 = 1;

	if (!vpninfo->cookie) {
		vpn_progress(vpninfo, PRG_ERR, _("Malformed cookie or no cookie given\n"));
		return -EINVAL;
	}

	ret = nx_get_connection_info(vpninfo);
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed getting NX connection information\n"));
		return -EINVAL;
	}
	auth_token = openconnect_base64_decode(&auth_token_len, vpninfo->cookie);
	if (!auth_token) {
		ret = auth_token_len;
		goto out;
	}
	// TODO: get ECP (trojan) info from /cgi-bin/sslvpnclient?epcversionquery=nxx
	ret = openconnect_open_https(vpninfo);
	if (ret)
		goto out;

	reqbuf = buf_alloc();
	if (!reqbuf) {
		ret = -ENOMEM;
		goto out;
	}
	buf_append(reqbuf, "CONNECT localhost:0 HTTP/1.0\r\n");
	buf_append(reqbuf, "X-SSLVPN-PROTOCOL: 2.0\r\n");
	buf_append(reqbuf, "X-SSLVPN-SERVICE: NETEXTENDER\r\n");
	buf_append(reqbuf, "Connection-Medium: MacOS\r\n");
	buf_append(reqbuf, "Frame-Encode: off\r\n");
	buf_append(reqbuf, "X-NE-PROTOCOL: 2.0\r\n");
	buf_append(reqbuf, "Proxy-Authorization: %.*s\r\n", auth_token_len, auth_token);
	// TODO: use set string for nx in openconnect_set_reported_os
	buf_append(reqbuf, "X-NX-Client-Platform: Linux\r\n");
	buf_append(reqbuf, "User-Agent: %s\r\n", vpninfo->useragent);
	buf_append(reqbuf, "\r\n");
	if ((ret = buf_error(reqbuf) != 0)) {
		vpn_progress(vpninfo, PRG_ERR, _("Error creating HTTPS CONNECT request\n"));
		goto out;
	}
	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);
	vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);

	// In case of success, there won't be a HTTP 200, data will start straight away
	// TODO: refactor process_http_response to handle this, so we can use it and do proper error handling
	// We expect either a HTTP response (failure) or a size (BE, 4b) (success).
	// The size will be smaller than 0x01000000 for sure, so we can use the
	// first byte as an indicator of success and don't need to check for "HTTP"
	// TODO: actually handle errors as described above
	vpn_progress(vpninfo, PRG_DEBUG, _("Connection established\n"));
	ret = openconnect_ppp_new(vpninfo, PPP_ENCAP_NX_HDLC, ipv4, vpninfo->ip_info.addr6 != NULL);

out:
	if (ret < 0)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
	}

	buf_free(reqbuf);
	free(auth_token);
	return ret;
}

int nx_bye(struct openconnect_info *vpninfo, const char *reason)
{
	int ret = 0;
	char *resp_buf = NULL;
	struct oc_text_buf *request_body = NULL;
	/* close tunnel */
	openconnect_close_https(vpninfo, 0);

	request_body = buf_alloc();
	if (!request_body) {
		ret = buf_error(request_body);
		goto out;
	}
	append_opt(request_body, "userLogout", "1");
	vpninfo->urlpath = strdup("cgi-bin/userLogout");
	ret = do_https_request(vpninfo, "POST", "application/x-www-form-urlencoded", request_body, &resp_buf, 0);
	free(vpninfo->urlpath);
	vpninfo->urlpath = NULL;
	printf("ret=%d\n", ret);
	if (ret < 0)
		vpn_progress(vpninfo, PRG_ERR, _("Logout failed.\n"));
	else {
		ret = 0;
		vpn_progress(vpninfo, PRG_INFO, _("Logout successful.\n"));
	}

out:
	free(resp_buf);
	free(request_body);
	return ret;
}
