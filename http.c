/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
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

#include <libxml/uri.h>

#include <unistd.h>
#include <fcntl.h>

#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

static int proxy_write(struct openconnect_info *vpninfo, char *buf, size_t len);
static int proxy_read(struct openconnect_info *vpninfo, char *buf, size_t len);

/*
 * We didn't really want to have to do this for ourselves -- one might have
 * thought that it would be available in a library somewhere. But neither
 * cURL nor Neon have reliable cross-platform ways of either using a cert
 * from the TPM, or just reading from / writing to a transport which is
 * provided by their caller.
 */

int http_add_cookie(struct openconnect_info *vpninfo, const char *option,
		    const char *value, int replace)
{
	struct oc_vpn_option *new, **this;

	if (*value) {
		new = malloc(sizeof(*new));
		if (!new) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("No memory for allocating cookies\n"));
			return -ENOMEM;
		}
		new->next = NULL;
		new->option = strdup(option);
		new->value = strdup(value);
		if (!new->option || !new->value) {
			free(new->option);
			free(new->value);
			free(new);
			return -ENOMEM;
		}
	} else {
		/* Kill cookie; don't replace it */
		new = NULL;
		/* This would be meaningless */
		if (!replace)
			return -EINVAL;
	}
	for (this = &vpninfo->cookies; *this; this = &(*this)->next) {
		if (!strcmp(option, (*this)->option)) {
			if (!replace) {
				free(new->value);
				free(new->option);
				free(new);
				return 0;
			}
			/* Replace existing cookie */
			if (new)
				new->next = (*this)->next;
			else
				new = (*this)->next;

			free((*this)->option);
			free((*this)->value);
			free(*this);
			*this = new;
			break;
		}
	}
	if (new && !*this) {
		*this = new;
		new->next = NULL;
	}
	return 0;
}

const char *http_get_cookie(struct openconnect_info *vpninfo, const char *name)
{
	struct oc_vpn_option *this;

	for (this = vpninfo->cookies; this; this = this->next) {
		if (!strcmp(this->option, name))
			return this->value;
	}
	return NULL;
}

/* Some protocols use an "authentication cookie" which needs
 * to be split into multiple HTTP cookies. (For example, oNCP
 * 'DSSignInUrl=/; DSID=xxx; DSFirstAccess=xxx; DSLastAccess=xxx')
 * Process those into vpninfo->cookies.
 */
int internal_split_cookies(struct openconnect_info *vpninfo, int replace, const char *def_cookie)
{
	char *p = vpninfo->cookie;

	while (p && *p) {
		char *semicolon = strchr(p, ';');
		char *equals;

		if (semicolon)
			*semicolon = 0;

		equals = strchr(p, '=');
		if (equals) {
			*equals = 0;
			http_add_cookie(vpninfo, p, equals+1, replace);
			*equals = '=';
		} else if (def_cookie) {
			/* XX: assume this represents a single cookie's value */
			http_add_cookie(vpninfo, def_cookie, p, replace);
		} else {
			vpn_progress(vpninfo, PRG_ERR, _("Invalid cookie '%s'\n"), p);
			return -EINVAL;
		}

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

int urldecode_inplace(char *p)
{
	char *q;
	if (!p)
		return -EINVAL;

	for (q = p; *p; p++, q++) {
		if (*p == '+') {
			*q = ' ';
		} else if (*p == '%' && isxdigit((int)(unsigned char)p[1]) &&
			   isxdigit((int)(unsigned char)p[2])) {
			*q = unhex(p + 1);
			p += 2;
		} else
			*q = *p;
	}
	*q = 0;
	return 0;
}

/* Read one HTTP header line into hdrbuf, potentially allowing for
 * continuation lines. Will never leave a character in 'nextchar' when
 * an empty line (signifying end of headers) is received. Will only
 * return success when hdrbuf is valid. */
static int read_http_header(struct openconnect_info *vpninfo, char *nextchar,
			    struct oc_text_buf *hdrbuf, int allow_cont)
{
	int eol = 0;
	int ret;
	char c;


	buf_truncate(hdrbuf);

	c = *nextchar;
	if (c) {
		*nextchar = 0;
		goto skip_first;
	}

	while (1) {
		ret = vpninfo->ssl_read(vpninfo, &c, 1);
		if (ret < 0)
			return ret;
		if (ret != 1)
			return -EINVAL;

		/* If we were looking for a continuation line and didn't get it,
		 * stash the character we *did* get into *nextchar for next time. */
		if (eol && c != ' ' && c != '\t') {
			*nextchar = c;
			return buf_error(hdrbuf);
		}
		eol = 0;

	skip_first:
		if (c == '\n') {
			if (!buf_error(hdrbuf) && hdrbuf->pos &&
			    hdrbuf->data[hdrbuf->pos - 1] == '\r') {
				hdrbuf->pos--;
				hdrbuf->data[hdrbuf->pos] = 0;
			}

			/* For a non-empty header line, see if there's a continuation */
			if (allow_cont && hdrbuf->pos) {
				eol = 1;
				continue;
			}

			return buf_error(hdrbuf);
		}
		buf_append_bytes(hdrbuf, &c, 1);
	}
	return buf_error(hdrbuf);
}

#define BODY_HTTP10 -1
#define BODY_CHUNKED -2

int process_http_response(struct openconnect_info *vpninfo, int connect,
			  int (*header_cb)(struct openconnect_info *, char *, char *),
			  struct oc_text_buf *body)
{
	struct oc_text_buf *hdrbuf = buf_alloc();
	char nextchar = 0;
	int bodylen = BODY_HTTP10;
	int closeconn = 0;
	int result;
	int ret = -EINVAL;
	int i;

	buf_truncate(body);

	/* Ensure it has *something* in it, so that we can dereference hdrbuf->data
	 * later without checking (for anything except buf_error(hdrbuf), which is
	 * what read_http_header() uses for its return code anyway). */
	buf_append_bytes(hdrbuf, "\0", 1);
 cont:
	ret = read_http_header(vpninfo, &nextchar, hdrbuf, 0);
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR, _("Error reading HTTP response: %s\n"),
			     strerror(-ret));
		goto err;
	}

	if (!strncmp(hdrbuf->data, "HTTP/1.0 ", 9))
		closeconn = 1;

	if ((!closeconn && strncmp(hdrbuf->data, "HTTP/1.1 ", 9)) ||
	    !(result = atoi(hdrbuf->data + 9))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse HTTP response '%s'\n"), hdrbuf->data);
		ret = -EINVAL;
		goto err;
	}

	vpn_progress(vpninfo, (result == 200 || result == 407) ? PRG_DEBUG : PRG_INFO,
		     _("Got HTTP response: %s\n"), hdrbuf->data);

	/* Eat headers... */
	while (1) {
		char *colon;
		char *hdrline;

		ret = read_http_header(vpninfo, &nextchar, hdrbuf, 1);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Error reading HTTP response: %s\n"),
				     strerror(-ret));
			goto err;
		}

		/* Empty line ends headers */
		if (!hdrbuf->pos)
			break;

		hdrline = hdrbuf->data;

		colon = strchr(hdrline, ':');
		if (!colon) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Ignoring unknown HTTP response line '%s'\n"), hdrline);
			continue;
		}
		*(colon++) = 0;
		if (*colon == ' ')
			colon++;

		/* Handle Set-Cookie first so that we can avoid printing the
		   webvpn cookie in the verbose debug output */
		if (!strcasecmp(hdrline, "Set-Cookie")) {
			char *semicolon = strchr(colon, ';');
			const char *print_equals;
			char *equals = strchr(colon, '=');

			if (semicolon)
				*semicolon = 0;

			if (!equals) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Invalid cookie offered: %s\n"), hdrline);
				ret = -EINVAL;
				goto err;
			}
			*(equals++) = 0;

			print_equals = equals;
			/* Don't print the webvpn cookie unless it's empty; we don't
			   want people posting it in public with debugging output */
			if (vpninfo->proto->secure_cookie && !strcmp(colon, vpninfo->proto->secure_cookie) && *equals)
				print_equals = _("<elided>");
			vpn_progress(vpninfo, PRG_DEBUG, "%s: %s=%s%s%s\n",
				hdrline, colon, print_equals, semicolon ? ";" : "",
				     semicolon ? (semicolon+1) : "");

			/* The server tends to ask for the username and password as
			   usual, even if we've already failed because it didn't like
			   our cert. Thankfully it does give us this hint... */
			if (!strcmp(colon, "ClientCertAuthFailed"))
				vpn_progress(vpninfo, PRG_ERR,
					     _("SSL certificate authentication failed\n"));

			ret = http_add_cookie(vpninfo, colon, equals, 1);
			if (ret)
				goto err;
		} else {
			vpn_progress(vpninfo, PRG_DEBUG, "%s: %s\n", hdrline, colon);
		}

		if (!strcasecmp(hdrline, "Connection")) {
			if (!strcasecmp(colon, "Close"))
				closeconn = 1;
#if 0
			/* This might seem reasonable, but in fact it breaks
			   certificate authentication with some servers. If
			   they give an HTTP/1.0 response, even if they
			   explicitly give a Connection: Keep-Alive header,
			   just close the connection. */
			else if (!strcasecmp(colon, "Keep-Alive"))
				closeconn = 0;
#endif
		}
		if (!strcasecmp(hdrline, "Location")) {
			vpninfo->redirect_url = strdup(colon);
			if (!vpninfo->redirect_url) {
				ret = -ENOMEM;
				goto err;
			}
		}
		if (!strcasecmp(hdrline, "Content-Length")) {
			bodylen = atoi(colon);
			if (bodylen < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Response body has negative size (%d)\n"),
					     bodylen);
				ret = -EINVAL;
				goto err;
			}
		}
		if (!strcasecmp(hdrline, "Transfer-Encoding")) {
			if (!strcasecmp(colon, "chunked"))
				bodylen = BODY_CHUNKED;
			else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unknown Transfer-Encoding: %s\n"),
					     colon);
				ret = -EINVAL;
				goto err;
			}
		}
		if (header_cb)
			header_cb(vpninfo, hdrline, colon);
	}

	/* Handle 'HTTP/1.1 100 Continue'. Not that we should ever see it */
	if (result == 100)
		goto cont;

	/* On successful CONNECT or upgrade, there is no body. Return success */
	if (connect && (result == 200 || result == 101)) {
		buf_free(hdrbuf);
		return result;
	}

	/* Now the body, if there is one */
	vpn_progress(vpninfo, PRG_DEBUG, _("HTTP body %s (%d)\n"),
		     bodylen == BODY_HTTP10 ? "http 1.0" :
		     bodylen == BODY_CHUNKED ? "chunked" : "length: ",
		     bodylen);

	/* If we were given Content-Length, it's nice and easy... */
	if (bodylen > 0) {
		if (buf_ensure_space(body, bodylen + 1)) {
			ret = buf_error(body);
			goto err;
		}

		while (body->pos < bodylen) {
			i = vpninfo->ssl_read(vpninfo, body->data + body->pos, bodylen - body->pos);
			if (i < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Error reading HTTP response body\n"));
				ret = i;
				goto err;
			}
			body->pos += i;
		}
	} else if (bodylen == BODY_CHUNKED) {
		char clen_buf[16];
		/* ... else, chunked */
		while ((i = vpninfo->ssl_gets(vpninfo, clen_buf, sizeof(clen_buf)))) {
			char *endp;
			int lastchunk = 0;
			long chunklen;

			if (i < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Error fetching chunk header\n"));
				ret = i;
				goto err;
			}
			chunklen = strtol(clen_buf, &endp, 16);
			if (endp != clen_buf)
				/* Be lenient with extraneous trailing spaces in chunk-size */
				while (*endp && isspace(*endp))
					++endp;
			if (endp == clen_buf || (*endp && *endp != ';')) {
				/* XX: Anything other than a non-negative hex integer followed by EOL or ';' is an error. */
				vpn_progress(vpninfo, PRG_ERR,
					     _("Error in chunked decoding. Expected hexadecimal chunk length, got: '%s'\n"),
					     clen_buf);
				goto err;
			}
			if (!chunklen) {
				/* Zero indicates the last chunk */
				lastchunk = 1;
				goto skip;
			}
			if (chunklen < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("HTTP chunk length is negative (%ld)\n"), chunklen);
				ret = -EINVAL;
				goto err;
			}
			if (chunklen >= INT_MAX) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("HTTP chunk length is too large (%ld)\n"), chunklen);
				ret = -EINVAL;
				goto err;
			}
			if (buf_ensure_space(body, chunklen + 1)) {
				ret = buf_error(body);
				goto err;
			}
			while (chunklen) {
				i = vpninfo->ssl_read(vpninfo, body->data + body->pos, chunklen);
				if (i < 0) {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Error reading HTTP response body\n"));
					ret = i;
					goto err;
				}
				chunklen -= i;
				body->pos += i;
			}
		skip:
			if ((i = vpninfo->ssl_gets(vpninfo, clen_buf, sizeof(clen_buf)))) {
				if (i < 0) {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Error fetching HTTP response body\n"));
					ret = i;
				} else {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Error in chunked decoding. Expected '', got: '%s'\n"),
						     clen_buf);
					ret = -EINVAL;
				}
				goto err;
			}

			if (lastchunk)
				break;
		}
	} else if (bodylen == BODY_HTTP10) {
		if (!closeconn) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Cannot receive HTTP 1.0 body without closing connection\n"));
			openconnect_close_https(vpninfo, 0);
			buf_free(hdrbuf);
			return -EINVAL;
		}

		/* HTTP 1.0 response. Just eat all we can in 4KiB chunks */
		while (1) {
			if (buf_ensure_space(body, 4096 + 1)) {
				ret = buf_error(body);
				goto err;
			}
			i = vpninfo->ssl_read(vpninfo, body->data + body->pos, 4096);
			if (i < 0) {
				/* Error */
				ret = i;
				goto err;
			} else if (!i)
				break;

			/* Got more data */
			body->pos += i;
		}
	}

	if (body && body->data)
		body->data[body->pos] = 0;
	ret = result;

	if (closeconn || vpninfo->no_http_keepalive) {
	err:
		openconnect_close_https(vpninfo, 0);
	}
	buf_free(hdrbuf);
	return ret;
}

int internal_parse_url(const char *url, char **res_proto, char **res_host,
		       int *res_port, char **res_path, int default_port)
{
	const char *orig_host, *orig_path;
	char *host, *port_str;
	int port, proto_len = 0;

	orig_host = strstr(url, "://");
	if (orig_host) {
		proto_len = orig_host - url;
		orig_host += 3;

		if (strprefix_match(url, proto_len, "https"))
			port = 443;
		else if (strprefix_match(url, proto_len, "http"))
			port = 80;
		else if (strprefix_match(url, proto_len, "socks") ||
			 strprefix_match(url, proto_len, "socks4") ||
			 strprefix_match(url, proto_len, "socks5"))
			port = 1080;
		else
			return -EPROTONOSUPPORT;
	} else {
		if (default_port) {
			port = default_port;
			orig_host = url;
		} else
			return -EINVAL;
	}

	orig_path = strchr(orig_host, '/');
	if (orig_path) {
		host = strndup(orig_host, orig_path - orig_host);
		orig_path++;
	} else
		host = strdup(orig_host);
	if (!host)
		return -ENOMEM;

	port_str = strrchr(host, ':');
	if (port_str) {
		char *end;
		int new_port = strtol(port_str + 1, &end, 10);

		if (!*end) {
			*port_str = 0;
			port = new_port;
			if (port <= 0 || port > 0xffff) {
				free(host);
				return -EINVAL;
			}
		}
	}

	if (res_proto)
		*res_proto = proto_len ? strndup(url, proto_len) : NULL;
	if (res_host)
		*res_host = host;
	else
		free(host);
	if (res_port)
		*res_port = port;
	if (res_path)
		*res_path = (orig_path && *orig_path) ? strdup(orig_path) : NULL;

	return 0;
}

char *internal_get_url(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *buf = buf_alloc();
	char *url;

	buf_append(buf, "https://%s", vpninfo->hostname);
	if (vpninfo->port != 443)
		buf_append(buf, ":%d", vpninfo->port);
	buf_append(buf, "/");
	if (vpninfo->urlpath)
		buf_append(buf, "%s", vpninfo->urlpath);

	if (buf_error(buf)) {
		buf_free(buf);
		return NULL;
	} else {
		url = buf->data;
		buf->data = NULL;
		buf_free(buf);
		return url;
	}
}

void openconnect_clear_cookies(struct openconnect_info *vpninfo)
{
	struct oc_vpn_option *opt, *next;

	for (opt = vpninfo->cookies; opt; opt = next) {
		next = opt->next;

		free(opt->option);
		free(opt->value);
		free(opt);
	}
	vpninfo->cookies = NULL;
}

/* Return value:
 *  < 0, on error
 *  = 0, on success (go ahead and retry with the latest vpninfo->{hostname,urlpath,port,...})
 */
int handle_redirect(struct openconnect_info *vpninfo)
{
	vpninfo->redirect_type = REDIR_TYPE_LOCAL;

	if (!strncmp(vpninfo->redirect_url, "https://", 8)) {
		/* New host. Tear down the existing connection and make a new one */
		char *host;
		int port;
		int ret;

		free(vpninfo->urlpath);
		vpninfo->urlpath = NULL;

		ret = internal_parse_url(vpninfo->redirect_url, NULL, &host, &port, &vpninfo->urlpath, 0);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse redirected URL '%s': %s\n"),
				     vpninfo->redirect_url, strerror(-ret));
			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;
			return ret;
		}

		if (strcasecmp(vpninfo->hostname, host) || port != vpninfo->port) {
			openconnect_set_hostname(vpninfo, host);
			vpninfo->port = port;

			/* Kill the existing connection, and a new one will happen */
			openconnect_close_https(vpninfo, 0);
			openconnect_clear_cookies(vpninfo);
			vpninfo->redirect_type = REDIR_TYPE_NEWHOST;
		}
		free(host);

		free(vpninfo->redirect_url);
		vpninfo->redirect_url = NULL;

		return 0;
	} else if (vpninfo->redirect_url[0] == '\0' || vpninfo->redirect_url[0] == '#') {
		/* Empty redirect, no op */
		free(vpninfo->redirect_url);
		vpninfo->redirect_url = NULL;
		return 0;
	} else if (vpninfo->redirect_url[0] == '/') {
		/* Absolute redirect within same host */
		free(vpninfo->urlpath);
		vpninfo->urlpath = strdup(vpninfo->redirect_url + 1);
		free(vpninfo->redirect_url);
		vpninfo->redirect_url = NULL;
		return 0;
	} else if (strstr(vpninfo->redirect_url, "://")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Cannot follow redirection to non-https URL '%s'\n"),
			     vpninfo->redirect_url);
		free(vpninfo->redirect_url);
		vpninfo->redirect_url = NULL;
		return -EINVAL;
	} else {
		char *lastslash = NULL;
		if (vpninfo->urlpath)
			lastslash = strrchr(vpninfo->urlpath, '/');
		if (!lastslash) {
			free(vpninfo->urlpath);
			vpninfo->urlpath = vpninfo->redirect_url;
			vpninfo->redirect_url = NULL;
		} else {
			char *oldurl = vpninfo->urlpath;
			*lastslash = 0;
			vpninfo->urlpath = NULL;
			if (asprintf(&vpninfo->urlpath, "%s/%s",
				     oldurl, vpninfo->redirect_url) == -1) {
				int err = -errno;
				vpn_progress(vpninfo, PRG_ERR,
					     _("Allocating new path for relative redirect failed: %s\n"),
					     strerror(-err));
				return err;
			}
			free(oldurl);
			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;
		}
		return 0;
	}
}

void do_dump_buf(struct openconnect_info *vpninfo, char prefix, char *buf)
{
	while (*buf) {
		char *eol = buf;
		char eol_char = 0;

		while (*eol) {
			if (*eol == '\r' || *eol == '\n') {
				eol_char = *eol;
				*eol = 0;
				break;
			}
			eol++;
		}

		vpn_progress(vpninfo, PRG_DEBUG, "%c %s\n", prefix, buf);
		if (!eol_char)
			break;

		*eol = eol_char;
		buf = eol + 1;
		if (eol_char == '\r' && *buf == '\n')
			buf++;
	}
}

void do_dump_buf_hex(struct openconnect_info *vpninfo, int loglevel, char prefix, unsigned char *buf, int len)
{
	struct oc_text_buf *line = buf_alloc();
	int i;

	for (i = 0; i < len; i+=16) {
		int j;

		buf_truncate(line);
		buf_append(line, "%04x:", i);
		for (j = i; j < i+16; j++) {
			if (!(j & 7))
				buf_append(line, " ");

			if (j < len)
				buf_append(line, " %02x", buf[j]);
			else
				buf_append(line, "   ");
		}
		buf_append(line, "  |");
		for (j = i; j < i+16 && j < len; j++)
			buf_append(line, "%c", isprint(buf[j])? buf[j] : '.');
		buf_append(line, "|");
		if (buf_error(line))
			break;
		vpn_progress(vpninfo, loglevel, "%c %s\n", prefix, line->data);
	}
	buf_free(line);
}

static int https_socket_closed(struct openconnect_info *vpninfo)
{
	char c;

	if (!openconnect_https_connected(vpninfo))
		return 1;

	if (recv(vpninfo->ssl_fd, &c, 1, MSG_PEEK) == 0) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("HTTPS socket closed by peer; reopening\n"));
		openconnect_close_https(vpninfo, 0);
		return 1;
	}

	return 0;
}


/* Inputs:
 *  method:             GET or POST
 *  vpninfo->hostname:  Host DNS name
 *  vpninfo->port:      TCP port, typically 443
 *  vpninfo->urlpath:   Relative path, e.g. /+webvpn+/foo.html
 *  request_body_type:  Content type for a POST (e.g. text/html).  Can be NULL.
 *  request_body:       POST content
 *  form_buf:           Callee-allocated buffer for server content
 *  header_cb:          Callback executed on every header line
 *                      If HTTP authentication is needed, the callback specified needs to call http_auth_hdrs.
 *  flags (bitfield):   HTTP_REDIRECT: follow redirects;
 *                      HTTP_REDIRECT_TO_GET: follow redirects, but change POST to GET;
 *                      HTTP_BODY_ON_ERR: return server content in form_buf even on error
 *
 * Return value:
 *  < 0, on error
 *  >=0, on success, indicating the length of the data in *form_buf
 */
int do_https_request(struct openconnect_info *vpninfo, const char *method, const char *request_body_type,
		     struct oc_text_buf *request_body, char **form_buf,
		     int (*header_cb)(struct openconnect_info *, char *, char *), int flags)
{
	struct oc_text_buf *buf;
	int result;
	int rq_retry;
	int rlen, pad;
	int i, auth = 0;
	int max_redirects = 10;

	if (!header_cb)
		header_cb = http_auth_hdrs;

	if (request_body_type && buf_error(request_body))
		return buf_error(request_body);

	buf = buf_alloc();

 redirected:
	if (max_redirects-- <= 0) {
		result = -EIO;
		goto out;
	}

	vpninfo->redirect_type = REDIR_TYPE_NONE;

	if (*form_buf) {
		free(*form_buf);
		*form_buf = NULL;
	}

	/*
	 * A long time ago, I *wanted* to use an HTTP client library like cURL
	 * for this. But we need a *lot* of control over the underlying SSL
	 * transport, and we also have to do horrid tricks like the Juniper NC
	 * 'GET' request that actually behaves like a 'CONNECT'.
	 *
	 * So the world gained Yet Another HTTP Implementation. Sorry.
	 *
	 */
	buf_truncate(buf);
	buf_append(buf, "%s /%s HTTP/1.1\r\n", method, vpninfo->urlpath ?: "");
	if (auth) {
		result = gen_authorization_hdr(vpninfo, 0, buf);
		if (result)
			goto out;

		/* Forget existing challenges */
		clear_auth_states(vpninfo, vpninfo->http_auth, 0);
	}
	if (vpninfo->proto->add_http_headers)
		vpninfo->proto->add_http_headers(vpninfo, buf);

	if (request_body_type) {
		rlen = request_body->pos;

		/* force body length to be a multiple of 64, to avoid leaking
		 * password length. */
		pad = 64*(1+rlen/64) - rlen;
		buf_append(buf, "X-Pad: %0*d\r\n", pad, 0);

		buf_append(buf, "Content-Type: %s\r\n", request_body_type);
		buf_append(buf, "Content-Length: %d\r\n", (int)rlen);
	}
	buf_append(buf, "\r\n");

	if (request_body_type)
		buf_append_bytes(buf, request_body->data, request_body->pos);

	if (vpninfo->port == 443)
		vpn_progress(vpninfo, PRG_INFO, "%s https://%s/%s\n",
			     method, vpninfo->hostname,
			     vpninfo->urlpath ?: "");
	else
		vpn_progress(vpninfo, PRG_INFO, "%s https://%s:%d/%s\n",
			     method, vpninfo->hostname, vpninfo->port,
			     vpninfo->urlpath ?: "");

	if (buf_error(buf))
		return buf_free(buf);

	vpninfo->retry_on_auth_fail = 0;

 retry:
	if (!https_socket_closed(vpninfo)) {
		/* The session is already connected. If we get a failure on
		* *sending* the request, try it again immediately with a new
		* connection. */
		rq_retry = 1;
	} else {
		rq_retry = 0;
		if ((openconnect_open_https(vpninfo))) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to open HTTPS connection to %s\n"),
				     vpninfo->hostname);
			/* We really don't want to return -EINVAL if we have
			   failed to even connect to the server, because if
			   we do that openconnect_obtain_cookie() might try
			   again without XMLPOST... with the same result. */
			result = -EIO;
			goto out;
		}
	}

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', buf->data);

	for (i = 0; i < buf->pos; i += 16384) {
		result = vpninfo->ssl_write(vpninfo, buf->data + i, MIN(buf->pos - i, 16384) );
		if (result < 0) {
			if (rq_retry) {
				/* Retry if we failed to send the request on
				   an already-open connection */
				openconnect_close_https(vpninfo, 0);
				goto retry;
			}
			/* We'll already have complained about whatever offended us */
			goto out;
		}
	}

	result = process_http_response(vpninfo, 0, header_cb, buf);
	if (result < 0) {
		if (rq_retry) {
			openconnect_close_https(vpninfo, 0);
			vpn_progress(vpninfo, PRG_INFO,
				     _("Retrying failed %s request on new connection\n"),
				     method);
			/* All the way back to 'redirected' since we need to rebuild
			 * the request in 'buf' from scratch. */
			goto redirected;
		}
		goto out;
	}
	if (vpninfo->dump_http_traffic && buf->pos)
		dump_buf(vpninfo, '<', buf->data);

	if (result == 401 && vpninfo->try_http_auth) {
		auth = 1;
		goto redirected;
	}
	if (result != 200 && vpninfo->redirect_url) {
		result = handle_redirect(vpninfo);
		if (result == 0) {
			if (!(flags & (HTTP_REDIRECT | HTTP_REDIRECT_TO_GET)))
				goto out;
			if (flags & HTTP_REDIRECT_TO_GET) {
				/* Some protocols require a GET after a redirected POST */
				method = "GET";
				request_body_type = NULL;
			}
			if (vpninfo->redirect_type == REDIR_TYPE_NEWHOST)
				clear_auth_states(vpninfo, vpninfo->http_auth, 1);
			goto redirected;
		}
		goto out;
	}
	if (!buf->pos || result != 200) {
		if (!buf->pos)
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected empty response body from server\n"));
		else
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected %d result from server\n"),
				     result);
		if (result == 401 || result == 403)
			result = -EPERM;
		else if (result == 512) /* GlobalProtect invalid username/password */
			result = -EACCES;
		else if (result == 405) /* Method not supported */
			result = -EOPNOTSUPP;
		else
			result = -EINVAL;

		if (!buf->pos || !(flags & HTTP_BODY_ON_ERROR))
			goto out;
	} else
		result = buf->pos;

	*form_buf = buf->data;
	buf->data = NULL;

 out:
	buf_free(buf);
	/* On success, clear out all authentication state for the next request */
	clear_auth_states(vpninfo, vpninfo->http_auth, 1);
	return result;
}

char *openconnect_create_useragent(const char *base)
{
	char *uagent;

	if (asprintf(&uagent, "%s %s", base, openconnect_version_str) < 0)
		return NULL;

	return uagent;
}

static int proxy_gets(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	return cancellable_gets(vpninfo, vpninfo->proxy_fd, buf, len);
}

static int proxy_write(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	return cancellable_send(vpninfo, vpninfo->proxy_fd, buf, len);
}

static int proxy_read(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	return cancellable_recv(vpninfo, vpninfo->proxy_fd, buf, len);
}

static const char * const socks_errors[] = {
	N_("request granted"),
	N_("general failure"),
	N_("connection not allowed by ruleset"),
	N_("network unreachable"),
	N_("host unreachable"),
	N_("connection refused by destination host"),
	N_("TTL expired"),
	N_("command not supported / protocol error"),
	N_("address type not supported")
};

static int socks_password_auth(struct openconnect_info *vpninfo)
{
	int ul, pl, i;
	char buf[1024];

	if (!vpninfo->proxy_user || !vpninfo->proxy_pass) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("SOCKS server requested username/password but we have none\n"));
		return -EIO;
	}
	ul = strlen(vpninfo->proxy_user);
	pl = strlen(vpninfo->proxy_pass);

	if (ul > 255 || pl > 255) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Username and password for SOCKS authentication must be < 255 bytes\n"));
		return -EINVAL;
	}

	buf[0] = 1;
	buf[1] = ul;
	memcpy(buf + 2, vpninfo->proxy_user, ul);
	buf[2 + ul] = pl;
	memcpy(buf + 3 + ul, vpninfo->proxy_pass, pl);

	i = proxy_write(vpninfo, buf, 3 + ul + pl);
	/* Don't leave passwords lying around if we can easily avoid it... */
	memset(buf, 0, sizeof(buf));
	if (i < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error writing auth request to SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}


	if ((i = proxy_read(vpninfo, buf, 2)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error reading auth response from SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}

	if (buf[0] != 1) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected auth response from SOCKS proxy: %02x %02x\n"),
			     buf[0], buf[1]);
		return -EIO;
	}
	if (buf[1] == 0) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Authenticated to SOCKS server using password\n"));
		return 0;
	} else {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Password authentication to SOCKS server failed\n"));
		return -EIO;
	}
}

#define SOCKS_AUTH_NONE			0	/* RFC1928 */
#define SOCKS_AUTH_GSSAPI		1	/* RFC1961 */
#define SOCKS_AUTH_PASSWORD		2	/* RFC1929 */
#define SOCKS_AUTH_NO_ACCEPTABLE	0xff	/* RFC1928 */

static int process_socks_proxy(struct openconnect_info *vpninfo)
{
	char buf[1024];
	int i, nr_auth_methods = 0;

	buf[0] = 5; /* SOCKS version */

	buf[2 + nr_auth_methods++] = SOCKS_AUTH_NONE;
#if defined(HAVE_GSSAPI) || defined(_WIN32)
	if (vpninfo->proxy_auth[AUTH_TYPE_GSSAPI].state > AUTH_FAILED &&
	    !vpninfo->proxy_user && !vpninfo->proxy_pass)
		buf[2 + nr_auth_methods++] = SOCKS_AUTH_GSSAPI;
#endif
	/*
	 * Basic auth is disabled by default. But for SOCKS, if the user has
	 * actually provided a password then that should implicitly allow
	 * basic auth since that's all that SOCKS can do. We shouldn't force
	 * the user to also add --proxy-auth=basic on the command line.
	 */
	if ((vpninfo->proxy_auth[AUTH_TYPE_BASIC].state > AUTH_FAILED ||
	     vpninfo->proxy_auth[AUTH_TYPE_BASIC].state == AUTH_DEFAULT_DISABLED) &&
	    vpninfo->proxy_user && vpninfo->proxy_pass)
		buf[2 + nr_auth_methods++] = SOCKS_AUTH_PASSWORD;

	buf[1] = nr_auth_methods;

	if ((i = proxy_write(vpninfo, buf, 2 + nr_auth_methods)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error writing auth request to SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}

	if ((i = proxy_read(vpninfo, buf, 2)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error reading auth response from SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	if (buf[0] != 5) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected auth response from SOCKS proxy: %02x %02x\n"),
			     buf[0], buf[1]);
		return -EIO;
	}
	switch ((unsigned char)buf[1]) {
	case SOCKS_AUTH_NONE:
		/* No authentication */
		break;

	case SOCKS_AUTH_GSSAPI:
#if defined(HAVE_GSSAPI) || defined(_WIN32)
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("SOCKS server requested GSSAPI authentication\n"));
		if (socks_gssapi_auth(vpninfo))
			return -EIO;
		break;
#else
		/* This should never happen since we didn't ask for it! */
		vpn_progress(vpninfo, PRG_ERR,
			     _("SOCKS server requested GSSAPI authentication\n"));
		return -EIO;
#endif

	case SOCKS_AUTH_PASSWORD:
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("SOCKS server requested password authentication\n"));
		if (socks_password_auth(vpninfo))
			return -EIO;
		break;

	case SOCKS_AUTH_NO_ACCEPTABLE:
		vpn_progress(vpninfo, PRG_ERR,
			     _("SOCKS server requires authentication\n"));
#if !defined(HAVE_GSSAPI) && !defined(_WIN32)
		vpn_progress(vpninfo, PRG_INFO,
			     _("This version of OpenConnect was built without GSSAPI support\n"));
#endif
		return -EIO;

	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("SOCKS server requested unknown authentication type %02x\n"),
			     (unsigned char)buf[1]);
		return -EIO;
	}

	vpn_progress(vpninfo, PRG_INFO,
		     _("Requesting SOCKS proxy connection to %s:%d\n"),
		     vpninfo->hostname, vpninfo->port);

	buf[0] = 5; /* SOCKS version */
	buf[1] = 1; /* CONNECT */
	buf[2] = 0; /* Reserved */
	buf[3] = 3; /* Address type is domain name */
	buf[4] = strlen(vpninfo->hostname);
	strcpy((char *)buf + 5, vpninfo->hostname);
	i = strlen(vpninfo->hostname) + 5;
	store_be16(buf + i, vpninfo->port);
	i += 2;

	if ((i = proxy_write(vpninfo, buf, i)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error writing connect request to SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	/* Read 5 bytes -- up to and including the first byte of the returned
	   address (which might be the length byte of a domain name) */
	if ((i = proxy_read(vpninfo, buf, 5)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error reading connect response from SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	if (i != 5 || buf[0] != 5) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected connect response from SOCKS proxy: %02x %02x...\n"),
			     buf[0], buf[1]);
		return -EIO;
	}
	if (buf[1]) {
		unsigned char err = buf[1];
		if (err < ARRAY_SIZE(socks_errors))
			vpn_progress(vpninfo, PRG_ERR,
				     _("SOCKS proxy error %02x: %s\n"),
				     err, _(socks_errors[err]));
		else
			vpn_progress(vpninfo, PRG_ERR,
				     _("SOCKS proxy error %02x\n"), err);
		return -EIO;
	}

	/* Connect responses contain an address */
	switch (buf[3]) {
	case 1: /* Legacy IP */
		i = 5;
		break;
	case 3: /* Domain name */
		i = buf[4] + 2;
		break;
	case 4: /* IPv6 */
		i = 17;
		break;
	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected address type %02x in SOCKS connect response\n"),
			     buf[3]);
		return -EIO;
	}

	if ((i = proxy_read(vpninfo, buf, i)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error reading connect response from SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	return 0;
}

static int process_http_proxy(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *reqbuf;
	int result;
	int auth = vpninfo->proxy_close_during_auth;

	vpninfo->proxy_close_during_auth = 0;

	vpn_progress(vpninfo, PRG_INFO,
		     _("Requesting HTTP proxy connection to %s:%d\n"),
		     vpninfo->hostname, vpninfo->port);

 retry:
	reqbuf = buf_alloc();
	buf_append(reqbuf, "CONNECT %s:%d HTTP/1.1\r\n", vpninfo->hostname, vpninfo->port);
	if (vpninfo->port == 443)
		buf_append(reqbuf, "Host: %s\r\n", vpninfo->hostname);
	else
		buf_append(reqbuf, "Host: %s:%d\r\n", vpninfo->hostname, vpninfo->port);
	buf_append(reqbuf, "User-Agent: %s\r\n", vpninfo->useragent);
	buf_append(reqbuf, "Proxy-Connection: keep-alive\r\n");
	buf_append(reqbuf, "Connection: keep-alive\r\n");
	buf_append(reqbuf, "Accept-Encoding: identity\r\n");
	if (auth) {
		result = gen_authorization_hdr(vpninfo, 1, reqbuf);
		if (result) {
			buf_free(reqbuf);
			return result;
		}
		/* Forget existing challenges */
		clear_auth_states(vpninfo, vpninfo->proxy_auth, 0);
	}
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf))
		return buf_free(reqbuf);

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);

	result = proxy_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (result < 0) {
		buf_free(reqbuf);
		vpn_progress(vpninfo, PRG_ERR,
			     _("Sending proxy request failed: %s\n"),
			     strerror(-result));
		return result;
	}

	result = process_http_response(vpninfo, 1, proxy_auth_hdrs, reqbuf);
	buf_free(reqbuf);
	if (result < 0)
		return -EINVAL;

	if (result == 407) {
		/* If the proxy asked us to close the connection, do so */
		if (vpninfo->proxy_close_during_auth)
			return -EAGAIN;

		auth = 1;
		goto retry;
	}

	if (result == 200)
		return 0;

	vpn_progress(vpninfo, PRG_ERR,
		     _("Proxy CONNECT request failed: %d\n"), result);
	return -EIO;
}

int process_proxy(struct openconnect_info *vpninfo, int ssl_sock)
{
	int ret;

	vpninfo->proxy_fd = ssl_sock;
	vpninfo->ssl_read = proxy_read;
	vpninfo->ssl_write = proxy_write;
	vpninfo->ssl_gets = proxy_gets;

	if (!vpninfo->proxy_type || !strcmp(vpninfo->proxy_type, "http"))
		ret = process_http_proxy(vpninfo);
	else if (!strcmp(vpninfo->proxy_type, "socks") ||
		 !strcmp(vpninfo->proxy_type, "socks5"))
		ret = process_socks_proxy(vpninfo);
	else {
		vpn_progress(vpninfo, PRG_ERR, _("Unknown proxy type '%s'\n"),
			     vpninfo->proxy_type);
		ret = -EIO;
	}

	vpninfo->proxy_fd = -1;
	if (!vpninfo->proxy_close_during_auth)
		clear_auth_states(vpninfo, vpninfo->proxy_auth, 1);

	return ret;
}

int openconnect_set_http_proxy(struct openconnect_info *vpninfo,
			       const char *proxy)
{
	char *p;
	int ret;

	free(vpninfo->proxy_type);
	vpninfo->proxy_type = NULL;
	free(vpninfo->proxy);
	vpninfo->proxy = NULL;

	ret = internal_parse_url(proxy, &vpninfo->proxy_type, &vpninfo->proxy,
				 &vpninfo->proxy_port, NULL, 80);
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to parse proxy '%s'\n"), proxy);
		return ret;
	}

	p = strrchr(vpninfo->proxy, '@');
	if (p) {
		/* Proxy username/password */
		*p = 0;
		vpninfo->proxy_user = vpninfo->proxy;
		vpninfo->proxy = strdup(p + 1);
		p = strchr(vpninfo->proxy_user, ':');
		if (p) {
			*p = 0;
			vpninfo->proxy_pass = strdup(p + 1);
			xmlURIUnescapeString(vpninfo->proxy_pass, 0, vpninfo->proxy_pass);
		}
		xmlURIUnescapeString(vpninfo->proxy_user, 0, vpninfo->proxy_user);
	}

	if (vpninfo->proxy_type &&
	    strcmp(vpninfo->proxy_type, "http") &&
	    strcmp(vpninfo->proxy_type, "socks") &&
	    strcmp(vpninfo->proxy_type, "socks5")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Only http or socks(5) proxies supported\n"));
		free(vpninfo->proxy_type);
		vpninfo->proxy_type = NULL;
		free(vpninfo->proxy);
		vpninfo->proxy = NULL;
		return -EINVAL;
	}

	return 0;
}

void http_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	struct oc_vpn_option *opt;

	if (vpninfo->port == 443)
		buf_append(buf, "Host: %s\r\n", vpninfo->hostname);
	else
		buf_append(buf, "Host: %s:%d\r\n", vpninfo->hostname, vpninfo->port);
	buf_append(buf, "User-Agent: %s\r\n", vpninfo->useragent);

	if (vpninfo->cookies) {
		buf_append(buf, "Cookie: ");
		for (opt = vpninfo->cookies; opt; opt = opt->next)
			buf_append(buf, "%s=%s%s", opt->option,
				      opt->value, opt->next ? "; " : "\r\n");
	}
}
