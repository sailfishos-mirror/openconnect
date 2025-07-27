/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
 * Copyright © 2013 John Morrissey <jwm@horde.net>
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

#ifdef HAVE_GETLINE
/* Various BSD systems require this for getline() to be visible */
#define _WITH_GETLINE
#endif

#include <getopt.h>

#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <locale.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef LIBPROXY_HDR
#include LIBPROXY_HDR
#endif

#define MAX_READ_STDIN_SIZE 4096

#ifdef _WIN32
#include <shlwapi.h>
#include <wtypes.h>
#include <wincon.h>
#else
#include <sys/utsname.h>
#include <pwd.h>
#include <termios.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#ifdef HAVE_NL_LANGINFO
#include <langinfo.h>

static const char *legacy_charset;
#endif

static int write_new_config(void *_vpninfo,
			    const char *buf, int buflen);
static void __attribute__ ((format(printf, 3, 4)))
    write_progress(void *_vpninfo, int level, const char *fmt, ...);
static int validate_peer_cert(void *_vpninfo, const char *reason);
static int process_auth_form_cb(void *_vpninfo,
				struct oc_auth_form *form);
static void init_token(struct openconnect_info *vpninfo,
		       oc_token_mode_t token_mode, const char *token_str);

/* A sanity check that the openconnect executable is running against a
   library of the same version */
#define openconnect_version_str openconnect_binary_version
#include <version.c>
#undef openconnect_version_str

static int timestamp;
#ifndef _WIN32
static int background;
static int use_syslog; /* static variable initialised to 0 */
static int wrote_pid; /* static variable initialised to 0 */
static char *pidfile; /* static variable initialised to NULL */
#endif
static int do_passphrase_from_fsid;
static int non_inter;
static int cookieonly;
static int allow_stdin_read;

static char *token_filename;
static int allowed_fingerprints;

struct accepted_cert {
	struct accepted_cert *next;
	char *fingerprint;
	char *host;
	int port;
} *accepted_certs;

static char *username;
static char *password;
static char *authgroup;
static int authgroup_set;
static int last_form_empty;

static int sig_cmd_fd;
static struct openconnect_info *sig_vpninfo;

static void add_form_field(char *field);

#ifdef __ANDROID__
#include <android/log.h>
static void __attribute__ ((format(printf, 3, 4)))
    syslog_progress(void *_vpninfo, int level, const char *fmt, ...)
{
	struct openconnect_info *vpninfo = _vpninfo;
	static int l[4] = {
		ANDROID_LOG_ERROR,	/* PRG_ERR   */
		ANDROID_LOG_INFO,	/* PRG_INFO  */
		ANDROID_LOG_DEBUG,	/* PRG_DEBUG */
		ANDROID_LOG_DEBUG	/* PRG_TRACE */
	};
	va_list args, args2;

	if (vpninfo->verbose >= level) {
		va_start(args, fmt);
		va_copy(args2, args);
		__android_log_vprint(l[level], "openconnect", fmt, args);
		/* Android wants it to stderr too, so the GUI can scrape
		   it and display it as well as going to syslog */
		vfprintf(stderr, fmt, args2);
		va_end(args);
		va_end(args2);
	}
}
#define openlog(...)  /* */
#elif defined(_WIN32) || defined(__native_client__)
/*
 * FIXME: Perhaps we could implement syslog_progress() using these APIs:
 * https://docs.microsoft.com/en-us/windows/win32/etw/tracing-events
 */
#else /* !__ANDROID__ && !_WIN32 && !__native_client__ */
#include <syslog.h>
static void  __attribute__ ((format(printf, 3, 4)))
    syslog_progress(void *_vpninfo, int level, const char *fmt, ...)
{
	struct openconnect_info *vpninfo = _vpninfo;
	int priority = level ? LOG_INFO : LOG_NOTICE;
	va_list args;

	if (vpninfo->verbose >= level) {
		va_start(args, fmt);
		vsyslog(priority, fmt, args);
		va_end(args);
	}
}
#endif

enum {
	OPT_AUTHENTICATE = 0x100,
	OPT_AUTHGROUP,
	OPT_BASEMTU,
	OPT_CAFILE,
	OPT_COMPRESSION,
	OPT_CONFIGFILE,
	OPT_COOKIEONLY,
	OPT_COOKIE_ON_STDIN,
	OPT_CSD_USER,
	OPT_CSD_WRAPPER,
	OPT_CIPHERSUITES,
	OPT_DISABLE_IPV6,
	OPT_DTLS_CIPHERS,
	OPT_DTLS12_CIPHERS,
	OPT_DUMP_HTTP,
	OPT_EXT_BROWSER,
	OPT_FORCE_DPD,
	OPT_FORCE_TROJAN,
	OPT_GNUTLS_DEBUG,
	OPT_JUNIPER,
	OPT_KEY_PASSWORD_FROM_FSID,
	OPT_LIBPROXY,
	OPT_NO_CERT_CHECK,
	OPT_NO_DTLS,
	OPT_NO_EXTERNAL_AUTH,
	OPT_NO_HTTP_KEEPALIVE,
	OPT_NO_SYSTEM_TRUST,
	OPT_NO_PASSWD,
	OPT_NO_PROXY,
	OPT_NO_XMLPOST,
	OPT_PIDFILE,
	OPT_PASSWORD_ON_STDIN,
	OPT_PRINTCOOKIE,
	OPT_RECONNECT_TIMEOUT,
	OPT_SERVERCERT,
	OPT_RESOLVE,
	OPT_SNI,
	OPT_USERAGENT,
	OPT_NON_INTER,
	OPT_DTLS_LOCAL_PORT,
	OPT_TOKEN_MODE,
	OPT_TOKEN_SECRET,
	OPT_OS,
	OPT_TIMESTAMP,
	OPT_PFS,
	OPT_ALLOW_INSECURE_CRYPTO,
	OPT_PROXY_AUTH,
	OPT_HTTP_AUTH,
	OPT_LOCAL_HOSTNAME,
	OPT_PROTOCOL,
	OPT_PASSTOS,
	OPT_VERSION,
	OPT_SERVER,
	OPT_MULTICERT_CERT,
	OPT_MULTICERT_KEY,
	OPT_MULTICERT_KEY_PASSWORD,
};

#ifdef __sun__
/*
 * The 'name' field in Solaris 'struct option' lacks the 'const', and causes
 * lots of warnings unless we cast it... https://www.illumos.org/issues/1881
*/
#define OPTION(name, arg, abbrev) {(char *)name, arg, NULL, abbrev}
#else
#define OPTION(name, arg, abbrev) {name, arg, NULL, abbrev}
#endif

static const struct option long_options[] = {
#ifndef _WIN32
	OPTION("background", 0, 'b'),
	OPTION("pid-file", 1, OPT_PIDFILE),
	OPTION("setuid", 1, 'U'),
	OPTION("script-tun", 0, 'S'),
	OPTION("syslog", 0, 'l'),
	OPTION("csd-user", 1, OPT_CSD_USER),
	OPTION("csd-wrapper", 1, OPT_CSD_WRAPPER),
#endif
#if defined(HAVE_POSIX_SPAWN) || defined(_WIN32)
	OPTION("external-browser", 1, OPT_EXT_BROWSER),
#endif
	OPTION("no-external-auth", 0, OPT_NO_EXTERNAL_AUTH),
	OPTION("pfs", 0, OPT_PFS),
	OPTION("allow-insecure-crypto", 0, OPT_ALLOW_INSECURE_CRYPTO),
	OPTION("certificate", 1, 'c'),
	OPTION("sslkey", 1, 'k'),
	OPTION("cookie", 1, 'C'),
	OPTION("compression", 1, OPT_COMPRESSION),
	OPTION("deflate", 0, 'd'),
	OPTION("juniper", 0, OPT_JUNIPER),
	OPTION("no-deflate", 0, 'D'),
	OPTION("cert-expire-warning", 1, 'e'),
	OPTION("usergroup", 1, 'g'),
	OPTION("help", 0, 'h'),
	OPTION("http-auth", 1, OPT_HTTP_AUTH),
	OPTION("interface", 1, 'i'),
	OPTION("mtu", 1, 'm'),
	OPTION("base-mtu", 1, OPT_BASEMTU),
	OPTION("script", 1, 's'),
	OPTION("timestamp", 0, OPT_TIMESTAMP),
	OPTION("passtos", 0, OPT_PASSTOS),
	OPTION("key-password", 1, 'p'),
	OPTION("proxy", 1, 'P'),
	OPTION("proxy-auth", 1, OPT_PROXY_AUTH),
	OPTION("user", 1, 'u'),
	OPTION("verbose", 0, 'v'),
	OPTION("version", 0, 'V'),
	OPTION("cafile", 1, OPT_CAFILE),
	OPTION("config", 1, OPT_CONFIGFILE),
	OPTION("no-dtls", 0, OPT_NO_DTLS),
	OPTION("authenticate", 0, OPT_AUTHENTICATE),
	OPTION("cookieonly", 0, OPT_COOKIEONLY),
	OPTION("printcookie", 0, OPT_PRINTCOOKIE),
	OPTION("quiet", 0, 'q'),
	OPTION("queue-len", 1, 'Q'),
	OPTION("xmlconfig", 1, 'x'),
	OPTION("cookie-on-stdin", 0, OPT_COOKIE_ON_STDIN),
	OPTION("passwd-on-stdin", 0, OPT_PASSWORD_ON_STDIN),
	OPTION("no-passwd", 0, OPT_NO_PASSWD),
	OPTION("reconnect-timeout", 1, OPT_RECONNECT_TIMEOUT),
	OPTION("dtls-ciphers", 1, OPT_DTLS_CIPHERS),
	OPTION("dtls12-ciphers", 1, OPT_DTLS12_CIPHERS),
	OPTION("authgroup", 1, OPT_AUTHGROUP),
	OPTION("servercert", 1, OPT_SERVERCERT),
	OPTION("resolve", 1, OPT_RESOLVE),
	OPTION("sni", 1, OPT_SNI),
	OPTION("key-password-from-fsid", 0, OPT_KEY_PASSWORD_FROM_FSID),
	OPTION("useragent", 1, OPT_USERAGENT),
	OPTION("version-string", 1, OPT_VERSION),
	OPTION("local-hostname", 1, OPT_LOCAL_HOSTNAME),
	OPTION("disable-ipv6", 0, OPT_DISABLE_IPV6),
	OPTION("no-proxy", 0, OPT_NO_PROXY),
	OPTION("libproxy", 0, OPT_LIBPROXY),
	OPTION("no-http-keepalive", 0, OPT_NO_HTTP_KEEPALIVE),
	OPTION("no-cert-check", 0, OPT_NO_CERT_CHECK),
	OPTION("force-dpd", 1, OPT_FORCE_DPD),
	OPTION("force-trojan", 1, OPT_FORCE_TROJAN),
	OPTION("non-inter", 0, OPT_NON_INTER),
	OPTION("dtls-local-port", 1, OPT_DTLS_LOCAL_PORT),
	OPTION("token-mode", 1, OPT_TOKEN_MODE),
	OPTION("token-secret", 1, OPT_TOKEN_SECRET),
	OPTION("os", 1, OPT_OS),
	OPTION("no-xmlpost", 0, OPT_NO_XMLPOST),
	OPTION("dump-http-traffic", 0, OPT_DUMP_HTTP),
	OPTION("no-system-trust", 0, OPT_NO_SYSTEM_TRUST),
	OPTION("protocol", 1, OPT_PROTOCOL),
	OPTION("form-entry", 1, 'F'),
#ifdef OPENCONNECT_GNUTLS
	OPTION("gnutls-debug", 1, OPT_GNUTLS_DEBUG),
	OPTION("gnutls-priority", 1, OPT_CIPHERSUITES),
#elif defined(OPENCONNECT_OPENSSL)
	OPTION("openssl-ciphers", 1, OPT_CIPHERSUITES),
#endif
	OPTION("server", 1, OPT_SERVER),
	OPTION("mca-certificate", 1, OPT_MULTICERT_CERT),
	OPTION("mca-key", 1, OPT_MULTICERT_KEY),
	OPTION("mca-key-password", 1, OPT_MULTICERT_KEY_PASSWORD),
	OPTION(NULL, 0, 0)
};

#ifdef OPENCONNECT_GNUTLS
static void oc_gnutls_log_func(int level, const char *str)
{
	fputs(str, stderr);
}
#endif

#ifdef _WIN32
static int __attribute__ ((format(printf, 2, 0)))
    vfprintf_utf8(FILE *f, const char *fmt, va_list args)
{
	HANDLE h = GetStdHandle(f == stdout ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
	wchar_t wbuf[1024];
	char buf[1024];
	int bytes, wchars;

	/* No need to NUL-terminate strings here */
	bytes = _vsnprintf(buf, sizeof(buf), fmt, args);
	if (bytes < 0)
		return bytes;
	if (bytes > sizeof(buf))
		bytes = sizeof(buf);

	wchars = MultiByteToWideChar(CP_UTF8, 0, buf, bytes, wbuf, ARRAY_SIZE(wbuf));
	if (!wchars)
		return -1;

	/*
	 * If writing to console fails, that's probably due to redirection.
	 * Convert to console CP and write to the FH, following the example of
	 * https://github.com/wine-mirror/wine/blob/e909986e6e/programs/whoami/main.c#L33-L49
	 */
	if (!WriteConsoleW(h, wbuf, wchars, NULL, NULL)) {
		bytes = WideCharToMultiByte(GetConsoleOutputCP(), 0, wbuf, wchars,
					    buf, sizeof(buf), NULL, NULL);
		if (!bytes)
			return -1;

		return fwrite(buf, 1, bytes, f);
	}
	return bytes;
}

static int __attribute__ ((format(printf, 2, 3)))
    fprintf_utf8(FILE *f, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vfprintf_utf8(f, fmt, args);
	va_end(args);

	return ret;
}

static wchar_t **argv_w;

/* This isn't so much "convert" the arg to UTF-8, as go grubbing
 * around in the real UTF-16 command line and find the corresponding
 * argument *there*, and convert *that* to UTF-8. Ick. But the
 * alternative is to implement wgetopt(), and that's even more horrid. */
static char *convert_arg_to_utf8(char **argv, char *arg)
{
	char *utf8;
	int chars;
	int offset;

	if (!argv_w) {
		int argc_w;

		argv_w = CommandLineToArgvW(GetCommandLineW(), &argc_w);
		if (!argv_w) {
			char *errstr = openconnect__win32_strerror(GetLastError());
			fprintf(stderr, _("CommandLineToArgv() failed: %s\n"),
				errstr);
			free(errstr);
			exit(1);
		}
	}

	offset = arg - argv[optind - 1];

	/* Sanity check */
	if (offset < 0 || offset >= strlen(argv[optind - 1]) ||
	    (offset && (argv[optind - 1][offset-1] != '=' ||
			argv_w[optind - 1][offset - 1] != '='))) {
		fprintf(stderr, _("Fatal error in command line handling\n"));
		exit(1);
	}

	chars = WideCharToMultiByte(CP_UTF8, 0, argv_w[optind-1] + offset, -1,
				    NULL, 0, NULL, NULL);
	utf8 = malloc(chars);
	if (!utf8)
		return arg;

	WideCharToMultiByte(CP_UTF8, 0, argv_w[optind-1] + offset, -1, utf8,
			    chars, NULL, NULL);
	return utf8;
}

#undef fprintf
#undef vfprintf
#define fprintf fprintf_utf8
#define vfprintf vfprintf_utf8
#define is_arg_utf8(str) (0)

static void read_stdin(char **string, int hidden, int allow_fail)
{
	CONSOLE_READCONSOLE_CONTROL rcc = { sizeof(rcc), 0, 13, 0 };
	HANDLE stdinh = GetStdHandle(STD_INPUT_HANDLE);
	DWORD cmode, nr_read, last_error;
	wchar_t wbuf[MAX_READ_STDIN_SIZE];
	char *buf;

	if (GetConsoleMode(stdinh, &cmode)) {
		if (hidden)
			SetConsoleMode(stdinh, cmode & (~ENABLE_ECHO_INPUT));

		SetLastError(0);

		if (!ReadConsoleW(stdinh, wbuf, ARRAY_SIZE(wbuf), &nr_read, &rcc)) {
			char *errstr = openconnect__win32_strerror(GetLastError());
			fprintf(stderr, _("ReadConsole() failed: %s\n"), errstr);
			free(errstr);
			*string = NULL;
			if (hidden)
				SetConsoleMode(stdinh, cmode);
			return;
		}

		last_error = GetLastError();

		if (hidden)
			SetConsoleMode(stdinh, cmode);

		if (!nr_read) {
			if (allow_fail) {
				*string = NULL;
				return;
			} else {
				if (last_error == ERROR_OPERATION_ABORTED) {
					fprintf(stderr, _("Operation aborted by user\n"));
				} else {
					/* Should never happen */
					fprintf(stderr, _("ReadConsole() didn't read any input\n"));
				}
				exit(1);
			}
		}
	} else {
		/* Not a console; maybe reading from a piped stdin? */
		if (!fgetws(wbuf, ARRAY_SIZE(wbuf), stdin)) {
			perror(_("fgetws (stdin)"));
			*string = NULL;
			return;
		}
		nr_read = wcslen(wbuf);
	}
	if (nr_read >= 2 && wbuf[nr_read - 1] == 10 && wbuf[nr_read - 2] == 13) {
		/* remove trailing "\r\n" */
		wbuf[nr_read - 2] = 0;
		nr_read -= 2;
	} else if (nr_read >= 1 && wbuf[nr_read - 1] == 10) {
		/* remove trailing "\n" */
		wbuf[nr_read - 1] = 0;
		nr_read -= 1;
	}

	nr_read = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
	if (!nr_read) {
		char *errstr = openconnect__win32_strerror(GetLastError());
		fprintf(stderr, _("Error converting console input: %s\n"),
			errstr);
		free(errstr);
		return;
	}
	buf = malloc(nr_read);
	if (!buf) {
		perror(_("Allocation failure for string from stdin"));
		exit(1);
	}

	if (!WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, nr_read, NULL, NULL)) {
		char *errstr = openconnect__win32_strerror(GetLastError());
		fprintf(stderr, _("Error converting console input: %s\n"),
			errstr);
		free(errstr);
		free(buf);
		return;
	}

	*string = buf;
}

#elif defined(HAVE_ICONV)
#include <iconv.h>

static int is_ascii(char *str)
{
	while (str && *str) {
		if ((unsigned char)*str > 0x7f)
			return 0;
		str++;
	}

	return 1;
}

static int __attribute__ ((format(printf, 2, 0)))
    vfprintf_utf8(FILE *f, const char *fmt, va_list args)
{
	char *utf8_str;
	iconv_t ic;
	int ret;
	char outbuf[80];
	ICONV_CONST char *ic_in;
	char *ic_out;
	size_t insize, outsize;

	if (!legacy_charset)
		return vfprintf(f, fmt, args);

	ret = vasprintf(&utf8_str, fmt, args);
	if (ret < 0)
		return -1;

	if (is_ascii(utf8_str))
		return fwrite(utf8_str, 1, strlen(utf8_str), f);

	ic = iconv_open(legacy_charset, "UTF-8");
	if (ic == (iconv_t) -1) {
		/* Better than nothing... */
		ret = fprintf(f, "%s", utf8_str);
		free(utf8_str);
		return ret;
	}

	ic_in = utf8_str;
	insize = strlen(utf8_str);
	ret = 0;

	while (insize) {
		ic_out = outbuf;
		outsize = sizeof(outbuf) - 1;

		if (iconv(ic, &ic_in, &insize, &ic_out, &outsize) == (size_t)-1) {
			if (errno == EILSEQ) {
				do {
					ic_in++;
					insize--;
				} while (insize && (ic_in[0] & 0xc0) == 0x80);
				ic_out[0] = '?';
				outsize--;
			} else if (errno != E2BIG)
				break;
		}
		ret += fwrite(outbuf, 1, sizeof(outbuf) - 1 - outsize, f);
	}

	iconv_close(ic);

	return ret;
}

static int __attribute__ ((format(printf, 2, 3)))
    fprintf_utf8(FILE *f, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vfprintf_utf8(f, fmt, args);
	va_end(args);

	return ret;
}

static char *convert_to_utf8(char *legacy, int free_it)
{
	char *utf8_str;
	iconv_t ic;
	ICONV_CONST char *ic_in;
	char *ic_out;
	size_t insize, outsize;

	if (!legacy_charset || is_ascii(legacy))
		return legacy;

	ic = iconv_open("UTF-8", legacy_charset);
	if (ic == (iconv_t) -1)
		return legacy;

	insize = strlen(legacy) + 1;
	ic_in = legacy;

	outsize = insize;
	ic_out = utf8_str = malloc(outsize);
	if (!utf8_str) {
	enomem:
		iconv_close(ic);
		return legacy;
	}

	while (insize) {
		if (iconv(ic, &ic_in, &insize, &ic_out, &outsize) == (size_t)-1) {
			if (errno == E2BIG) {
				int outlen = ic_out - utf8_str;
				realloc_inplace(utf8_str, outlen + 10);
				if (!utf8_str)
					goto enomem;
				ic_out = utf8_str + outlen;
				outsize = 10;
			} else {
				/* Should never happen */
				perror("iconv");
				free(utf8_str);
				goto enomem;
			}
		}
	}

	iconv_close(ic);
	if (free_it)
		free(legacy);
	return utf8_str;
}

#define fprintf fprintf_utf8
#define vfprintf vfprintf_utf8
#define convert_arg_to_utf8(av, l) convert_to_utf8((l), 0)
#define is_arg_utf8(a) (!legacy_charset || is_ascii(a))
#else
#define convert_to_utf8(l,f) (l)
#define convert_arg_to_utf8(av, l) (l)
#define is_arg_utf8(a) (1)
#endif

static void helpmessage(void)
{
	printf(_("For assistance with OpenConnect, please see the web page at\n"
		 "  %s\n"),
	       "https://www.infradead.org/openconnect/mail.html");
}

static void print_build_opts(void)
{
	const char comma[] = ", ", *sep = comma + 1;

	printf(_("Using %s. Features present:"), openconnect_get_tls_library_version());

	if (openconnect_has_tss_blob_support()) {
		printf("%sTPM", sep);
		sep = comma;
	}
	if (openconnect_has_tss2_blob_support()) {
		printf("%sTPMv2", sep);
		sep = comma;
	}
#if defined(OPENCONNECT_OPENSSL) && defined(HAVE_ENGINE)
	else {
		printf("%sTPM (%s)", sep, _("OpenSSL ENGINE not present"));
		sep = comma;
	}
#endif
	if (openconnect_has_pkcs11_support()) {
		printf("%sPKCS#11", sep);
		sep = comma;
	}
	if (openconnect_has_stoken_support()) {
		printf("%sRSA software token", sep);
		sep = comma;
	}
	switch (openconnect_has_oath_support()) {
	case 2:
		printf("%sHOTP software token", sep);
		sep = comma;
		/* fall through */
	case 1:
		printf("%sTOTP software token", sep);
		sep = comma;
	}
	if (openconnect_has_yubioath_support()) {
		printf("%sYubikey OATH", sep);
		sep = comma;
	}
	if (openconnect_has_system_key_support()) {
		printf("%sSystem keys", sep);
		sep = comma;
	}

#ifdef HAVE_DTLS
	printf("%sDTLS", sep);
#endif
#ifdef HAVE_ESP
	printf("%sESP", sep);
#endif
	printf("\n");

#if !defined(HAVE_DTLS) || !defined(HAVE_ESP)
	printf(_("WARNING: This binary lacks DTLS and/or ESP support. Performance will be impaired.\n"));
#endif
}

static void print_supported_protocols(void)
{
	const char comma[] = ", ", *sep = comma + 1;
	struct oc_vpn_proto *protos, *p;
	int n;

	n = openconnect_get_supported_protocols(&protos);
        if (n>=0) {
		printf(_("Supported protocols:"));
		for (p=protos; n; p++, n--) {
			printf("%s%s%s", sep, p->name, p==protos ? _(" (default)") : "");
			sep = comma;
		}
		printf("\n");
		free(protos);
	}
}

static void print_supported_protocols_usage(void)
{
	struct oc_vpn_proto *protos, *p;
	int n;

	n = openconnect_get_supported_protocols(&protos);
        if (n>=0) {
		printf("\n%s:\n", _("Set VPN protocol"));
		for (p=protos; n; p++, n--)
			printf("      --protocol=%-16s %s%s\n",
				   p->name, p->description, p==protos ? _(" (default)") : "");
		openconnect_free_supported_protocols(protos);
	}
}

#ifndef _WIN32
static const char default_vpncscript[] = DEFAULT_VPNCSCRIPT;
static void read_stdin(char **string, int hidden, int allow_fail)
{
	char *c, *got, *buf = malloc(MAX_READ_STDIN_SIZE+1);
	int fd = fileno(stdin);
	struct termios t;

	if (!buf) {
		fprintf(stderr, _("Allocation failure for string from stdin\n"));
		exit(1);
	}

	if (hidden) {
		tcgetattr(fd, &t);
		t.c_lflag &= ~ECHO;
		tcsetattr(fd, TCSANOW, &t);
	}

	got = fgets(buf, MAX_READ_STDIN_SIZE+1, stdin);

	if (hidden) {
		t.c_lflag |= ECHO;
		tcsetattr(fd, TCSANOW, &t);
		fprintf(stderr, "\n");
	}

	if (!got) {
		if (allow_fail) {
			*string = NULL;
			free(buf);
			return;
		} else {
			perror(_("fgets (stdin)"));
			exit(1);
		}
	}

	c = strchr(buf, '\n');
	if (c)
		*c = 0;

	*string = convert_to_utf8(buf, 1);
}

static void handle_signal(int sig)
{
	char cmd;

	switch (sig) {
	case SIGTERM:
		cmd = OC_CMD_CANCEL;
		break;
	case SIGHUP:
		cmd = OC_CMD_DETACH;
		break;
	case SIGINT:
#ifdef INSECURE_DEBUGGING
		cmd = OC_CMD_DETACH;
#else
		cmd = OC_CMD_CANCEL;
#endif
		break;
	case SIGUSR1:
		cmd = OC_CMD_STATS;
		break;
	case SIGUSR2:
	default:
		cmd = OC_CMD_PAUSE;
		break;
	}

	if (write(sig_cmd_fd, &cmd, 1) < 0) {
	/* suppress warn_unused_result */
	}
	if (sig_vpninfo)
		sig_vpninfo->need_poll_cmd_fd = 1;
}

static int checked_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	int ret = sigaction(signum, act, oldact);
	if (ret)
		fprintf(stderr, _("WARNING: Cannot set handler for signal %d: %s\n"),
			signum, strerror(errno));
	return ret;
}
#else /* _WIN32 */
static const char *default_vpncscript;
static void set_default_vpncscript(void)
{
	if (PathIsRelative(DEFAULT_VPNCSCRIPT)) {
		char *c = strrchr(_pgmptr, '\\');
		if (!c) {
			fprintf(stderr, _("Cannot process this executable path \"%s\""),
				_pgmptr);
			exit(1);
		}
		if (asprintf((char **)&default_vpncscript, "%.*s%s",
			     (int)(c - _pgmptr + 1), _pgmptr,
			     DEFAULT_VPNCSCRIPT) < 0) {
			fprintf(stderr, _("Allocation for vpnc-script path failed\n"));
			exit(1);
		}
	} else {
		default_vpncscript = DEFAULT_VPNCSCRIPT;
	}
}

static BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType)
{
	char cmd;

	/* Note: this function always runs in a separate thread */

	switch (dwCtrlType) {
	case CTRL_C_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		cmd = OC_CMD_CANCEL;
		break;
	case CTRL_BREAK_EVENT:
		cmd = OC_CMD_DETACH;
		break;
	default:
		return FALSE;
	}

	/* Use send() here since, on Windows, sig_cmd_fd is a socket descriptor */
	send(sig_cmd_fd, &cmd, 1, 0);

	if (sig_vpninfo)
		sig_vpninfo->need_poll_cmd_fd = 1;

	return TRUE;
}
#endif

static void print_default_vpncscript(void)
{
	printf("%s %s\n", _("Default vpnc-script (override with --script):"),
	       default_vpncscript);
}

static struct oc_vpn_option *gai_overrides;

static struct addrinfo *gai_add_or_free(struct addrinfo *list, struct addrinfo *elem)
{
	struct addrinfo **lp = &list;

	while (*lp) {
		struct addrinfo *p = *lp;
		if (p->ai_family == elem->ai_family &&
		    p->ai_socktype == elem->ai_socktype &&
		    p->ai_protocol == elem->ai_protocol &&
		    p->ai_addrlen == elem->ai_addrlen &&
		    !memcmp(p->ai_addr, elem->ai_addr, p->ai_addrlen)) {
			freeaddrinfo(elem);
			return list;
		}
		lp = &((*lp)->ai_next);
	}
	*lp = elem;
	return list;
}

static struct addrinfo *gai_merge(struct addrinfo *list1, struct addrinfo *list2)
{
	while (list2) {
		struct addrinfo *elem = list2;
		list2 = elem->ai_next;
		elem->ai_next = NULL;

		list1 = gai_add_or_free(list1, elem);
	}
	return list1;
}

static int gai_override_cb(void *cbdata, const char *node,
			   const char *service, const struct addrinfo *hints,
			   struct addrinfo **res)
{
	struct openconnect_info *vpninfo = cbdata;
	struct oc_vpn_option *p = gai_overrides;
	struct addrinfo *results = NULL;
	int ret = 0;

	while (p) {
		if (!strcmp(node, p->option)) {
			struct addrinfo *this_res = NULL;
			int this_ret = 0;

			vpn_progress(vpninfo, PRG_TRACE, _("Override hostname '%s' to '%s'\n"),
				     node, p->value);

			this_ret = getaddrinfo(p->value, service, hints, &this_res);
			/*
			 * Accumulate non-fatal results by precedence: If anything *works*,
			 * return success. If anything returns EAI_ADDRFAMILY, return that.
			 * Next EAI_NODATA, and finally return EAI_NONAME only if *every*
			 * lookup returned that. Any other errors are fatal.
			 */
			if (!this_ret) {
				/* As we process the list in reverse of the order they were
				 * given on the command line, *prepend* results. */
				results = gai_merge(this_res, results);
				ret = 0;
			} else {
#ifdef _WIN32
				char *errstr = openconnect__win32_strerror(this_ret);
#else
				const char *errstr = gai_strerror(this_ret);
#endif
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("getaddrinfo failed for host '%s': %s\n"),
					     p->value, errstr);
#ifdef _WIN32
				free(errstr);
#endif

#ifdef EAI_ADDRFAMILY /* Missing in MinGW */
				if (this_ret == EAI_ADDRFAMILY || ret == EAI_ADDRFAMILY) {
					ret = EAI_ADDRFAMILY;
				} else
#endif
				if (this_ret == EAI_NODATA || ret == EAI_NODATA) {
					ret = EAI_NODATA;
				} else if (this_ret == EAI_NONAME || ret == EAI_NONAME) {
					ret = EAI_NONAME;
				} else {
					/* Fatal errors abort the lookup */
					freeaddrinfo(results);
					return this_ret;
				}
			}
		}
		p = p->next;
	}

	/* Any override will set *either* 'results' on success, or 'ret' on failure. */
	if (results || ret) {
		*res = results;
		return ret;
	}

	return getaddrinfo(node, service, hints, res);
}

static void usage(void)
{
	printf(_("Usage:  openconnect [options] <server>\n"));
	printf(_("Open client for multiple VPN protocols, version %s\n\n"), openconnect_version_str);
	print_build_opts();
	printf("      --config=CONFIGFILE         %s\n", _("Read options from config file"));
	printf("  -V, --version                   %s\n", _("Report version number"));
	printf("  -h, --help                      %s\n", _("Display help text"));

	print_supported_protocols_usage();

	printf("\n%s:\n", _("Authentication"));
	printf("  -u, --user=NAME                 %s\n", _("Set login username"));
	printf("      --no-passwd                 %s\n", _("Disable password/SecurID authentication"));
	printf("      --non-inter                 %s\n", _("Do not expect user input; exit if it is required"));
	printf("      --passwd-on-stdin           %s\n", _("Read password from standard input"));
	printf("      --authgroup=GROUP           %s\n", _("Select GROUP from authentication dropdown (may be known"));
	printf("                                  %s\n", _("as \"realm\", \"domain\", \"gateway\"; protocol-dependent)"));
	printf("  -F, --form-entry=FORM:OPT=VALUE %s\n", _("Provide authentication form responses"));
	printf("  -c, --certificate=CERT          %s\n", _("Use SSL client certificate CERT"));
	printf("  -k, --sslkey=KEY                %s\n", _("Use SSL private key file KEY"));
	printf("  -e, --cert-expire-warning=DAYS  %s\n", _("Warn when certificate lifetime < DAYS"));
	printf("  -g, --usergroup=GROUP           %s\n", _("Set path of initial request URL"));
	printf("  -p, --key-password=PASS         %s\n", _("Set key passphrase or TPM SRK PIN"));
	printf("      --external-browser=BROWSER  %s\n", _("Set external browser executable"));
	printf("      --key-password-from-fsid    %s\n", _("Key passphrase is fsid of file system"));
	printf("      --token-mode=MODE           %s\n", _("Software token type: rsa, totp, hotp or oidc"));
	printf("      --token-secret=STRING       %s\n", _("Software token secret or oidc token"));
#ifndef HAVE_LIBSTOKEN
	printf("                                  %s\n", _("(NOTE: libstoken (RSA SecurID) disabled in this build)"));
#endif
#ifndef HAVE_LIBPCSCLITE
	printf("                                  %s\n", _("(NOTE: Yubikey OATH disabled in this build)"));
#endif

	printf("\n%s:\n", _("Server validation"));
	printf("      --servercert=FINGERPRINT    %s\n", _("Accept only server certificate with this fingerprint"));
	printf("      --no-system-trust           %s\n", _("Disable default system certificate authorities"));
	printf("      --cafile=FILE               %s\n", _("Cert file for server verification"));

	printf("\n%s:\n", _("Internet connectivity"));
	printf("      --server=SERVER             %s\n", _("Set VPN server"));
	printf("  -P, --proxy=URL                 %s\n", _("Set proxy server"));
	printf("      --proxy-auth=METHODS        %s\n", _("Set proxy authentication methods"));
	printf("      --no-proxy                  %s\n", _("Disable proxy"));
	printf("      --libproxy                  %s\n", _("Use libproxy to automatically configure proxy"));
#ifndef LIBPROXY_HDR
	printf("                                  %s\n", _("(NOTE: libproxy disabled in this build)"));
#endif
	printf("      --reconnect-timeout=SECONDS %s\n", _("Reconnection retry timeout (default is 300 seconds)"));
	printf("      --resolve=HOST:IP           %s\n", _("Use IP when connecting to HOST"));
	printf("      --sni=HOST                  %s\n", _("Always send HOST as TLS client SNI (domain fronting)"));
	printf("      --passtos                   %s\n", _("Copy TOS / TCLASS field into DTLS and ESP packets"));
	printf("      --dtls-local-port=PORT      %s\n", _("Set local port for DTLS and ESP datagrams"));

	printf("\n%s:\n", _("Authentication (two-phase)"));
	printf("  -C, --cookie=COOKIE             %s\n", _("Use authentication cookie COOKIE"));
	printf("      --cookie-on-stdin           %s\n", _("Read cookie from standard input"));
	printf("      --authenticate              %s\n", _("Authenticate only and print login info"));
	printf("      --cookieonly                %s\n", _("Fetch and print cookie only; don't connect"));
	printf("      --printcookie               %s\n", _("Print cookie before connecting"));

#ifndef _WIN32
	printf("\n%s:\n", _("Process control"));
	printf("  -b, --background                %s\n", _("Continue in background after startup"));
	printf("      --pid-file=PIDFILE          %s\n", _("Write the daemon's PID to this file"));
	printf("  -U, --setuid=USER               %s\n", _("Drop privileges after connecting"));
#endif

	printf("\n%s:\n", _("Logging (two-phase)"));
#ifndef _WIN32
	printf("  -l, --syslog                    %s\n", _("Use syslog for progress messages"));
#endif
	printf("  -v, --verbose                   %s\n", _("More output"));
	printf("  -q, --quiet                     %s\n", _("Less output"));
	printf("      --dump-http-traffic         %s\n", _("Dump HTTP authentication traffic (implies --verbose)"));
	printf("      --timestamp                 %s\n", _("Prepend timestamp to progress messages"));

	printf("\n%s:\n", _("VPN configuration script"));
	printf("  -i, --interface=IFNAME          %s\n", _("Use IFNAME for tunnel interface"));
	printf("  -s, --script=SCRIPT             %s\n", _("Shell command line for using a vpnc-compatible config script"));
	printf("                                  %s: \"%s\"\n", _("default"), default_vpncscript);
#ifndef _WIN32
	printf("  -S, --script-tun                %s\n", _("Pass traffic to 'script' program, not tun"));
#endif

	printf("\n%s:\n", _("Tunnel control"));
	printf("      --disable-ipv6              %s\n", _("Do not ask for IPv6 connectivity"));
	printf("  -x, --xmlconfig=CONFIG          %s\n", _("XML config file"));
	printf("  -m, --mtu=MTU                   %s\n", _("Request MTU from server (legacy servers only)"));
	printf("      --base-mtu=MTU              %s\n", _("Indicate path MTU to/from server"));
	printf("  -d, --deflate                   %s\n", _("Enable stateful compression (default is stateless only)"));
	printf("  -D, --no-deflate                %s\n", _("Disable all compression"));
	printf("      --force-dpd=INTERVAL        %s\n", _("Set Dead Peer Detection interval (in seconds)"));
	printf("      --pfs                       %s\n", _("Require perfect forward secrecy"));
	printf("      --no-dtls                   %s\n", _("Disable DTLS and ESP"));
	printf("      --dtls-ciphers=LIST         %s\n", _("OpenSSL ciphers to support for DTLS"));
	printf("  -Q, --queue-len=LEN             %s\n", _("Set packet queue limit to LEN pkts"));

	printf("\n%s:\n", _("Local system information"));
	printf("      --useragent=STRING          %s\n", _("HTTP header User-Agent: field"));
	printf("      --local-hostname=STRING     %s\n", _("Local hostname to advertise to server"));
	printf("      --os=STRING                 %s\n", _("OS type to report. Allowed values are the following:"));
	printf("                                  %s\n", _("linux, linux-64, win, mac-intel, android, apple-ios"));
	printf("      --version-string=STRING     %s\n", _("reported version string during authentication"));
	printf("                                  (%s %s)\n", _("default:"), openconnect_version_str);

	printf("\n%s:\n", _("Trojan binary (CSD) execution"));
#ifndef _WIN32
	printf("      --csd-user=USER             %s\n", _("Drop privileges during trojan execution"));
	printf("      --csd-wrapper=SCRIPT        %s\n", _("Run SCRIPT instead of trojan binary"));
#endif
	printf("      --force-trojan=INTERVAL     %s\n", _("Set minimum interval between trojan runs (in seconds)"));

	printf("\n%s:\n", _("Server bugs"));
	printf("      --no-external-auth          %s\n", _("Do not offer or use auth methods requiring external browser"));
	printf("      --no-http-keepalive         %s\n", _("Disable HTTP connection re-use"));
	printf("      --no-xmlpost                %s\n", _("Do not attempt XML POST authentication"));
	printf("      --allow-insecure-crypto     %s\n", _("Allow use of the ancient, insecure 3DES and RC4 ciphers"));

	printf("\n%s:\n", _("Multiple certificate authentication (MCA)"));
	printf("      --mca-certificate=MCACERT   %s\n", _("Use MCA certificate MCACERT"));
	printf("      --mca-key=MCAKEY            %s\n", _("Use MCA key MCAKEY"));
	printf("      --mca-key-password=MCAPASS  %s\n", _("Passphrase MCAPASS for MCACERT/MCAKEY"));

	printf("\n");

	helpmessage();
	exit(1);
}


static FILE *config_file; /* static variable initialised to NULL */
static int config_line_num;  /* static variable initialised to 0 */

static char *xstrdup(const char *arg)
{
	char *ret;

	if (!arg)
		return NULL;

	ret = strdup(arg);

	if (!ret) {
		fprintf(stderr, _("Failed to allocate string\n"));
		exit(1);
	}
	return ret;
}

/* There are three ways to handle config_arg:
 *
 * 1. We only care about it transiently and it can be lost entirely
 *    (e.g. vpninfo->reconnect_timeout = atoi(config_arg);
 * 2. We need to keep it, but it's a static string and will never be freed
 *    so when it's part of argv[] we can use it in place (unless it needs
 *    converting to UTF-8), but when it comes from a file we have to strdup()
 *    because otherwise it'll be overwritten.
 *    For this we use the keep_config_arg() macro below.
 * 3. It may be freed during normal operation, so we have to use strdup()
 *    or convert_arg_to_utf8() even when it's an option from argv[].
 *    (e.g. vpninfo->certinfo[0].password).
 *    For this we use the dup_config_arg() macro below.
 */

#define keep_config_arg() \
	(config_file ? xstrdup(config_arg) : convert_arg_to_utf8(argv, config_arg))

#define dup_config_arg() __dup_config_arg(argv, config_arg)

static inline char *__dup_config_arg(char **argv, char *config_arg)
{
	char *res;

	if (config_file || is_arg_utf8(config_arg))
		return xstrdup(config_arg);

	res = convert_arg_to_utf8(argv, config_arg);
	/* Force a copy, even if conversion failed */
	if (res == config_arg)
		res = xstrdup(res);
	return res;
}

static int next_option(int argc, char **argv, char **config_arg)
{
	/* These get re-used */
	static char *line_buf; /* static variable initialised to NULL */
	static size_t line_size; /* static variable initialised to 0 */

	ssize_t llen;
	int opt, optlen = 0;
	const struct option *this;
	char *line;
	int ate_equals = 0;

 next:
	if (!config_file) {
		opt = getopt_long(argc, argv,
#ifdef _WIN32
				  "C:c:Dde:F:g:hi:k:m:P:p:Q:qs:u:Vvx:",
#else
				  "bC:c:Dde:F:g:hi:k:lm:P:p:Q:qSs:U:u:Vvx:",
#endif
				  long_options, NULL);

		*config_arg = optarg;
		return opt;
	}

	llen = getline(&line_buf, &line_size, config_file);
	if (llen < 0) {
		if (feof(config_file)) {
			fclose(config_file);
			config_file = NULL;
			goto next;
		}
		fprintf(stderr, _("Failed to get line from config file: %s\n"),
			strerror(errno));
		exit(1);
	}
	line = line_buf;

	/* Strip the trailing newline (coping with DOS newlines) */
	if (llen && line[llen-1] == '\n')
		line[--llen] = 0;
	if (llen && line[llen-1] == '\r')
		line[--llen] = 0;

	/* Skip and leading whitespace */
	while (line[0] == ' ' || line[0] == '\t' || line[0] == '\r')
		line++;

	/* Ignore comments and empty lines */
	if (!line[0] || line[0] == '#') {
		config_line_num++;
		goto next;
	}

	/* Try to match on a known option... naïvely. This could be improved. */
	for (this = long_options; this->name; this++) {
		optlen = strlen(this->name);
		/* If the option isn't followed by whitespace or NUL, or
		   perhaps an equals sign if the option takes an argument,
		   then it's not a match */
		if (!strncmp(this->name, line, optlen) &&
		    (!line[optlen] || line[optlen] == ' ' || line[optlen] == '\t' ||
		     line[optlen] == '='))
			break;
	}
	if (!this->name) {
		char *l;

		for (l = line; *l && *l != ' ' && *l != '\t'; l++)
			;

		*l = 0;
		fprintf(stderr, _("Unrecognised option at line %d: '%s'\n"),
			config_line_num, line);
		return '?';
	}
	line += optlen;
	while (*line == ' ' || *line == '\t' ||
	       (*line == '=' && this->has_arg && !ate_equals && ++ate_equals))
		line++;

	if (!this->has_arg && *line) {
		fprintf(stderr, _("Option '%s' does not take an argument at line %d\n"),
			this->name, config_line_num);
		return '?';
	} else if (this->has_arg == 1 && !*line) {
		fprintf(stderr, _("Option '%s' requires an argument at line %d\n"),
			this->name, config_line_num);
		return '?';
	} else if (this->has_arg == 2 && !*line) {
		line = NULL;
	}

	config_line_num++;
	*config_arg = line;
	return this->val;

}

static void assert_nonnull_config_arg(const char *opt, const char *config_arg)
{
	if (!config_arg) { /* Should never happen */
		fprintf(stderr, _("Internal error; option '%s' unexpectedly yielded null config_arg\n"),
			opt);
		exit(1); /* Shut static analyzer up */
	}
}

#ifndef _WIN32
static void get_uids(const char *config_arg, uid_t *uid, gid_t *gid)
{
	char *strend;
	struct passwd *pw;

	*uid = strtol(config_arg, &strend, 0);
	if (strend[0]) {
		pw = getpwnam(config_arg);
		if (!pw) {
			fprintf(stderr, _("Invalid user \"%s\": %s\n"),
				config_arg, strerror(errno));
			exit(1);
		}
		*uid = pw->pw_uid;
		*gid = pw->pw_gid;
	} else {
		pw = getpwuid(*uid);
		if (!pw) {
			fprintf(stderr, _("Invalid user ID \"%d\": %s\n"),
				(int)*uid, strerror(errno));
			exit(1);
		}
		*gid = pw->pw_gid;
	}
}
#endif

static int complete_words(const char *comp_opt, int prefixlen, ...)
{
	int partlen = strlen(comp_opt + prefixlen);
	va_list vl;
	char *check;

	va_start(vl, prefixlen);
	while ( (check = va_arg(vl, char *)) ) {
		if (!strncmp(comp_opt + prefixlen, check, partlen))
			printf("%.*s%s\n", prefixlen, comp_opt, check);
	}
	va_end(vl);
	return 0;
}

static int autocomplete_special(const char *verb, const char *prefix,
				int prefixlen, const char *filterpat)
{
	printf("%s\n", verb);
	printf("%s\n", filterpat ? : "''");

	if (prefixlen)
		printf("%.*s\n", prefixlen, prefix);
	return 0;
}

static int autocomplete(int argc, char **argv)
{
	int opt;
	const char *comp_cword = getenv("COMP_CWORD");
	char *comp_opt;
	int cword, longidx, prefixlen = 0;

	/* Skip over the --autocomplete */
	argc--;
	argv++;

	if (!comp_cword)
		return -EINVAL;

	cword = atoi(comp_cword);
	if (cword <= 0 || cword > argc)
		return -EINVAL;

	comp_opt = argv[cword];
	if (!comp_opt)
		return -EINVAL;

	opterr = 0;

	while (argv[optind]) {
		/* If optind is the one that is being autocompleted, don't
		 * let getopt_long() see it; we process it directly. */
		if (argv[optind] == comp_opt) {
			if (!strncmp(comp_opt, "--", 2)) {
				const char *arg = strchr(comp_opt, '=');
				int matchlen;

				if (arg) {
					/* We have --option=... so complete the arg */
					matchlen = arg - comp_opt - 2;
					for (longidx = 0; long_options[longidx].name; longidx++) {
						if (!strncmp(comp_opt + 2, long_options[longidx].name, matchlen)) {
							prefixlen = matchlen + 3;
							opt = long_options[longidx].val;
							goto got_opt;
						}
					}
				} else {
					/* Not --option= just --opt so complete the option name(s) */
					comp_opt += 2;
				autocomplete_optname:
					matchlen = strlen(comp_opt);
					for (longidx = 0; long_options[longidx].name; longidx++) {
						if (!strncmp(comp_opt, long_options[longidx].name, matchlen)) {
							printf("--%s\n", long_options[longidx].name);
						}
					}
				}
			} else if (comp_opt[0] == '-') {
				if (!comp_opt[1]) {
					/* Just a single dash. Autocomplete like '--' with all the (long) options */
					comp_opt++;
					goto autocomplete_optname;
				}
				/* Single-char -X option, with or without an argument. */
				for (longidx = 0; long_options[longidx].name; longidx++) {
					if (comp_opt[1] == long_options[longidx].val) {
						if (comp_opt[2]) {
							if (long_options[longidx].has_arg) {
								prefixlen = 2;
								opt = long_options[longidx].val;
								goto got_opt;
							}
						} else {
							/* Just the option; complete to the long name of same. */
							printf("--%s\n", long_options[longidx].name);
						}
						break;
					}
				}
			} else
				printf("HOSTNAME\n");

			return 0;
		}

		/* Skip over non-option elements, in an attempt to prevent
		 * getopt_long() from reordering the array as we go. The problem
		 * is that we've seen it *delay* the reordering. So it processes
		 * the argv element *after* the non-option, but argv[optind] is
		 * still pointing to the non-option. */
		if (argv[optind][0] != '-') {
			optind++;
			continue;
		}

		opt = getopt_long(argc, argv,
#ifdef _WIN32
				  "C:c:Dde:F:g:hi:k:m:P:p:Q:qs:u:Vvx:",
#else
				  "bC:c:Dde:F:g:hi:k:lm:P:p:Q:qSs:U:u:Vvx:",
#endif
				  long_options, &longidx);

		if (opt == -1)
			break;

		if (optarg == comp_opt) {
			prefixlen = 0;
		got_opt:
			switch (opt) {
			case 'k': /* --sslkey */
			case 'c': /* --certificate */
				if (!strncmp(comp_opt + prefixlen, "pkcs11:", 7)) {
					/* We could do clever things here... */
					return 0; /* .. but we don't. */
				}
				autocomplete_special("FILENAME", comp_opt, prefixlen, "!*.@(pem|der|p12|crt)");
				break;

			case OPT_CAFILE: /* --cafile */
				autocomplete_special("FILENAME", comp_opt, prefixlen, "!*.@(pem|der|crt)");
				break;

			case 'x': /* --xmlconfig */
				autocomplete_special("FILENAME", comp_opt, prefixlen, "!*.xml");
				break;

			case OPT_CONFIGFILE: /* --config */
			case OPT_PIDFILE: /* --pid-file */
				autocomplete_special("FILENAME", comp_opt, prefixlen, NULL);
				break;

			case 's': /* --script */
			case OPT_CSD_WRAPPER: /* --csd-wrapper */
			case OPT_EXT_BROWSER: /* --external-browser */
				autocomplete_special("EXECUTABLE", comp_opt, prefixlen, NULL);
				break;

			case OPT_LOCAL_HOSTNAME: /* --local-hostname */
				autocomplete_special("HOSTNAME", comp_opt, prefixlen, NULL);
				break;

			case OPT_CSD_USER: /* --csd-user */
			case 'U': /* --setuid */
				autocomplete_special("USERNAME", comp_opt, prefixlen, NULL);
				break;

			case OPT_OS: /* --os */
				complete_words(comp_opt, prefixlen, "mac-intel", "android",
					       "linux-64", "linux", "apple-ios",
					       "win", NULL);
				break;

			case OPT_COMPRESSION: /* --compression */
				complete_words(comp_opt, prefixlen, "none", "off", "all",
					       "stateless", NULL);
				break;

			case OPT_PROTOCOL: /* --protocol */
			{
				struct oc_vpn_proto *protos, *p;
				int partlen = strlen(comp_opt + prefixlen);

				if (openconnect_get_supported_protocols(&protos) >= 0) {
					for (p = protos; p->name; p++) {
						if(!strncmp(comp_opt + prefixlen, p->name, partlen))
							printf("%.*s%s\n", prefixlen, comp_opt, p->name);
					}
					free(protos);
				}
				break;
			}

			case OPT_HTTP_AUTH: /* --http-auth */
			case OPT_PROXY_AUTH: /* --proxy-auth */
				/* FIXME: Expand latest list item */
				break;

			case OPT_TOKEN_MODE: /* --token-mode */
				complete_words(comp_opt, prefixlen, "totp", "hotp", "oidc", NULL);
				if (openconnect_has_stoken_support())
					complete_words(comp_opt, prefixlen, "rsa", NULL);
				if (openconnect_has_yubioath_support())
					complete_words(comp_opt, prefixlen, "yubioath", NULL);
				break;

			case OPT_TOKEN_SECRET: /* --token-secret */
				switch (comp_opt[prefixlen]) {
				case '@':
					prefixlen++;
					/* Fall through */
				case 0:
				case '/':
					autocomplete_special("FILENAME", comp_opt, prefixlen, NULL);
					break;
				}
				break;

			case OPT_SERVER: /* --server */
				autocomplete_special("HOSTNAME", comp_opt, prefixlen, NULL);
				break;

			case 'i': /* --interface */
				/* FIXME: Enumerate available tun devices */
				break;

			case OPT_SERVERCERT: /* --servercert */
				/* We could do something really evil here and actually
				 * connect, then return the result? */
				break;

			/* No autocomplete for these but handle them explicitly so that
			 * we can have automatic checking for *accidentally* unhandled
			 * options. Right after we do automated checking of man page
			 * entries and --help output for all supported options too. */

			case 'e': /* --cert-expire-warning */
			case 'C': /* --cookie */
			case 'g': /* --usergroup */
			case 'm': /* --mtu */
			case OPT_BASEMTU: /* --base-mtu */
			case 'p': /* --key-password */
			case 'P': /* --proxy */
			case 'u': /* --user */
			case 'Q': /* --queue-len */
			case OPT_RECONNECT_TIMEOUT: /* --reconnect-timeout */
			case OPT_AUTHGROUP: /* --authgroup */
			case OPT_RESOLVE: /* --resolve */
			case OPT_SNI: /* --sni */
			case OPT_USERAGENT: /* --useragent */
			case OPT_VERSION: /* --version-string */
			case OPT_FORCE_DPD: /* --force-dpd */
			case OPT_FORCE_TROJAN: /* --force-trojan */
			case OPT_DTLS_LOCAL_PORT: /* --dtls-local-port */
			case 'F': /* --form-entry */
			case OPT_GNUTLS_DEBUG: /* --gnutls-debug */
			case OPT_CIPHERSUITES: /* --gnutls-priority */
			case OPT_DTLS_CIPHERS: /* --dtls-ciphers */
			case OPT_DTLS12_CIPHERS: /* --dtls12-ciphers */
				break;

			case OPT_MULTICERT_CERT: /* --mca-certificate */
			case OPT_MULTICERT_KEY: /* --mca-key */
				if (!strncmp(comp_opt + prefixlen, "pkcs11:", 7)) {
					/* We could do clever things here... */
					return 0; /* .. but we don't. */
				}
				autocomplete_special("FILENAME", comp_opt, prefixlen, "!*.@(pem|der|p12|crt)");
				break;
			/* disable password autocomplete */
			case OPT_MULTICERT_KEY_PASSWORD: /* --mca-key-password */
				break;
			default:
				fprintf(stderr, _("Unhandled autocomplete for option %d '--%s'. Please report.\n"),
					opt, long_options[longidx].name);
				return -ENOENT;
			}

			return 0;
		}
	}

	/* The only non-option argument we accept is the hostname */
	printf("HOSTNAME\n");
	return 0;
}

static void print_connection_info(struct openconnect_info *vpninfo)
{
	const struct oc_ip_info *ip_info;
	const char *ssl_compr, *udp_compr, *dtls_state, *ssl_state;

	openconnect_get_ip_info(vpninfo, &ip_info, NULL, NULL);

	ssl_state = vpninfo->ssl_fd == -1 ? _("disconnected") : _("connected");

	switch (vpninfo->dtls_state) {
	case DTLS_NOSECRET:
		dtls_state = _("unsuccessful");
		break;
	case DTLS_SLEEPING:
	case DTLS_SECRET:
	case DTLS_CONNECTING:
		dtls_state = _("in progress");
		break;
	case DTLS_DISABLED:
		dtls_state = _("disabled");
		break;
	case DTLS_CONNECTED:
		dtls_state = _("connected");
		break;
	case DTLS_ESTABLISHED:
		dtls_state = _("established");
		break;
	default:
		dtls_state = _("unknown");
		break;
	}

	ssl_compr = openconnect_get_cstp_compression(vpninfo);
	udp_compr = openconnect_get_dtls_compression(vpninfo);
	vpn_progress(vpninfo, PRG_INFO,
		     _("Configured as %s%s%s, with SSL%s%s %s and %s%s%s %s\n"),
		     ip_info->addr?:"",
		     ((ip_info->netmask6 || ip_info->addr6) && ip_info->addr) ? " + " : "",
		     ip_info->netmask6 ? : (ip_info->addr6 ? : ""),
		     ssl_compr ? " + " : "", ssl_compr ? : "",
		     ssl_state,
		     vpninfo->proto->udp_protocol ? : "UDP", udp_compr ? " + " : "", udp_compr ? : "",
		     dtls_state);
	if (vpninfo->auth_expiration != 0) {
		char buf[80];
		struct tm *tm = localtime(&vpninfo->auth_expiration);
		strftime(buf, 80, "%a, %d %b %Y %H:%M:%S %Z", tm);
		vpn_progress(vpninfo, PRG_INFO,
			     _("Session authentication will expire at %s\n"),
			     buf);
	}
}

static void print_connection_stats(void *_vpninfo, const struct oc_stats *stats)
{
	struct openconnect_info *vpninfo = _vpninfo;
	int saved_loglevel = vpninfo->verbose;

	/* XX: print even if loglevel would otherwise suppress */
	openconnect_set_loglevel(vpninfo, PRG_INFO);

	print_connection_info(vpninfo);
	vpn_progress(vpninfo, PRG_INFO,
		     _("RX: %"PRIu64" packets (%"PRIu64" B); TX: %"PRIu64" packets (%"PRIu64" B)\n"),
		       stats->rx_pkts, stats->rx_bytes, stats->tx_pkts, stats->tx_bytes);

	if (vpninfo->ssl_fd != -1)
		vpn_progress(vpninfo, PRG_INFO, _("SSL ciphersuite: %s\n"), openconnect_get_cstp_cipher(vpninfo));
	if (vpninfo->dtls_state == DTLS_CONNECTED)
		vpn_progress(vpninfo, PRG_INFO, _("%s ciphersuite: %s\n"),
		     vpninfo->proto->udp_protocol ? : "UDP", openconnect_get_dtls_cipher(vpninfo));
	if (vpninfo->ssl_times.last_rekey && vpninfo->ssl_times.rekey)
		vpn_progress(vpninfo, PRG_INFO, _("Next SSL rekey in %ld seconds\n"),
			     (long)(vpninfo->ssl_times.last_rekey + vpninfo->ssl_times.rekey - time(NULL)));
	if (vpninfo->dtls_times.last_rekey && vpninfo->dtls_times.rekey)
		vpn_progress(vpninfo, PRG_INFO, _("Next %s rekey in %ld seconds\n"),
			     vpninfo->proto->udp_protocol ? : "UDP",
			     (long)(vpninfo->ssl_times.last_rekey + vpninfo->ssl_times.rekey - time(NULL)));
	if (vpninfo->trojan_interval && vpninfo->last_trojan)
		vpn_progress(vpninfo, PRG_INFO, _("Next Trojan invocation in %ld seconds\n"),
			     (long)(vpninfo->last_trojan + vpninfo->trojan_interval - time(NULL)));

	/* XX: restore loglevel */
	openconnect_set_loglevel(vpninfo, saved_loglevel);
}

#ifndef _WIN32
static int background_self(struct openconnect_info *vpninfo, char *pidfile)
{
	FILE *fp = NULL;
	int pid;

	/* Open the pidfile before forking, so we can report errors
	   more sanely. It's *possible* that we'll fail to write to
	   it, but very unlikely. */
	if (pidfile != NULL) {
		fp = openconnect_fopen_utf8(vpninfo, pidfile, "w");
		if (!fp) {
			fprintf(stderr, _("Failed to open '%s' for write: %s\n"),
				pidfile, strerror(errno));
			sig_vpninfo = NULL;
			openconnect_vpninfo_free(vpninfo);
			exit(1);
		}
	}
	pid = fork();
	if (pid == -1) {
		vpn_perror(vpninfo, _("Failed to continue in background"));
		exit(1);
	} else if (pid > 0) {
		if (fp) {
			fprintf(fp, "%d\n", pid);
			fclose(fp);
		}
		vpn_progress(vpninfo, PRG_INFO,
			     _("Continuing in background; pid %d\n"),
			     pid);
		sig_vpninfo = NULL;
		/* Don't invoke EPOLL_CTL_DEL; it'll mess up the real one */
#ifdef HAVE_EPOLL
		vpninfo->epoll_fd = -1;
#endif
		openconnect_vpninfo_free(vpninfo);
		exit(0);
	}
	if (fp)
		fclose(fp);
	return !!fp;
}
#endif /* _WIN32 */

static void fully_up_cb(void *_vpninfo)
{
	struct openconnect_info *vpninfo = _vpninfo;

	print_connection_info(vpninfo);
#ifndef _WIN32
	if (background)
		wrote_pid = background_self(vpninfo, pidfile);

#ifndef __native_client__
	if (use_syslog) {
		openlog("openconnect", LOG_PID, LOG_DAEMON);
		vpninfo->progress = syslog_progress;
	}
#endif /* !__native_client__ */
#endif /* !_WIN32 */
}

int main(int argc, char *argv[])
{
	struct openconnect_info *vpninfo;
	char *urlpath = NULL;
	struct oc_vpn_option *gai;
	struct accepted_cert *newcert;
	char *ip;
	char *proxy = getenv("https_proxy");
	char *vpnc_script = NULL;
	int autoproxy = 0;
	int opt;
	char *config_arg;
	char *config_filename;
	const char *server_url = NULL;
	char *token_str = NULL;
	oc_token_mode_t token_mode = OC_TOKEN_MODE_NONE;
	int reconnect_timeout = 300;
	int ret;
	int verbose = PRG_INFO;
#ifdef HAVE_NL_LANGINFO
	char *charset;
#endif
#ifndef _WIN32
	struct sigaction sa;
	struct sigaction sa_ignore;
	struct utsname utsbuf;
#endif

#ifdef ENABLE_NLS
	bindtextdomain("openconnect", LOCALEDIR);
#endif

	if (!setlocale(LC_ALL, ""))
		fprintf(stderr,
			_("WARNING: Cannot set locale: %s\n"), strerror(errno));

	if (argc > 2 && !strcmp(argv[1], "--autocomplete"))
		return autocomplete(argc, argv);

#ifdef HAVE_NL_LANGINFO
	charset = nl_langinfo(CODESET);
	if (charset && strcmp(charset, "UTF-8"))
		legacy_charset = strdup(charset);

#ifndef HAVE_ICONV
	if (legacy_charset)
		fprintf(stderr,
			_("WARNING: This version of OpenConnect was built without iconv\n"
			  "         support but you appear to be using the legacy character\n"
			  "         set \"%s\". Expect strangeness.\n"), legacy_charset);
#endif /* !HAVE_ICONV */
#endif /* HAVE_NL_LANGINFO */

	if (strcmp(openconnect_version_str, openconnect_binary_version)) {
		fprintf(stderr, _("WARNING: This version of OpenConnect is %s but\n"
				  "         the libopenconnect library is %s\n"),
			openconnect_binary_version, openconnect_version_str);
	}

#ifdef INSECURE_DEBUGGING
	fprintf(stderr,
		_("WARNING: This build is intended only for debugging purposes and\n"
		  "         may allow you to establish insecure connections.\n"));
#endif

	/* Some systems have a crypto policy which completely prevents DTLSv1.0
	 * from being used, which is entirely pointless and will just drive
	 * users back to the crappy proprietary clients. Or drive OpenConnect
	 * to implement its own DTLS instead of using the system crypto libs.
	 * We're happy to conform by default to the system policy which is
	 * carefully curated to keep up to date with developments in crypto
	 * attacks —  but we also *need* to be able to override it and connect
	 * anyway, when the user asks us to. Just as we *can* continue even
	 * when the server has an invalid certificate, based on user input.
	 * It was a massive oversight that GnuTLS implemented the system
	 * policy *without* that basic override facility, so until/unless
	 * it actually gets implemented properly we have to just disable it.
	 * We can't do this from openconnect_init_ssl() since that would be
	 * calling setenv() from a library in someone else's process. And
	 * thankfully we don't really need to since the auth-dialogs don't
	 * care; this is mostly for the DTLS connection.
	 */
#ifdef OPENCONNECT_GNUTLS
	setenv("GNUTLS_SYSTEM_PRIORITY_FILE", DEVNULL, 0);
#else
	setenv("OPENSSL_CONF", DEVNULL, 0);
#endif

	openconnect_init_ssl();

	vpninfo = openconnect_vpninfo_new("AnyConnect-compatible OpenConnect VPN Agent",
		validate_peer_cert, NULL, process_auth_form_cb, write_progress, NULL);
	if (!vpninfo) {
		fprintf(stderr, _("Failed to allocate vpninfo structure\n"));
		exit(1);
	}

	vpninfo->cbdata = vpninfo;
#ifdef _WIN32
	set_default_vpncscript();
#else
	vpninfo->use_tun_script = 0;
	vpninfo->uid = getuid();
	vpninfo->gid = getgid();

	if (!uname(&utsbuf)) {
		openconnect_set_localname(vpninfo, utsbuf.nodename);
	}
#endif

	while ((opt = next_option(argc, argv, &config_arg))) {

		if (opt < 0)
			break;

		switch (opt) {
#ifndef _WIN32
		case 'b':
			background = 1;
			break;
		case 'l':
			use_syslog = 1;
			break;
		case 'S':
			vpninfo->use_tun_script = 1;
			break;
		case 'U':
			assert_nonnull_config_arg("U", config_arg);
			get_uids(config_arg, &vpninfo->uid, &vpninfo->gid);
			break;
		case OPT_CSD_USER:
			assert_nonnull_config_arg("csd-user", config_arg);
			get_uids(config_arg, &vpninfo->uid_csd, &vpninfo->gid_csd);
			vpninfo->uid_csd_given = 1;
			break;
		case OPT_CSD_WRAPPER:
			vpninfo->csd_wrapper = keep_config_arg();
			break;
#endif /* !_WIN32 */
		case 'F':
			add_form_field(keep_config_arg());
			break;
		case OPT_PROTOCOL:
			if (openconnect_set_protocol(vpninfo, config_arg))
				exit(1);
			break;
		case OPT_JUNIPER:
			fprintf(stderr, _("WARNING: --juniper is deprecated, use --protocol=nc instead.\n"));
			openconnect_set_protocol(vpninfo, "nc");
			break;
		case OPT_CONFIGFILE:
			if (config_file) {
				fprintf(stderr, _("Cannot use 'config' option inside config file\n"));
				exit(1);
			}
			config_filename = keep_config_arg(); /* Convert to UTF-8 */
			config_file = openconnect_fopen_utf8(vpninfo, config_filename, "r");
			if (config_filename != config_arg)
				free(config_filename);
			if (!config_file) {
				fprintf(stderr, _("Cannot open config file '%s': %s\n"),
					config_arg, strerror(errno));
				exit(1);
			}
			config_line_num = 1;
			/* The next option will come from the file... */
			break;
		case OPT_COMPRESSION:
			assert_nonnull_config_arg("compression", config_arg);
			if (!strcmp(config_arg, "none") ||
			    !strcmp(config_arg, "off"))
				openconnect_set_compression_mode(vpninfo, OC_COMPRESSION_MODE_NONE);
			else if (!strcmp(config_arg, "all"))
				openconnect_set_compression_mode(vpninfo, OC_COMPRESSION_MODE_ALL);
			else if (!strcmp(config_arg, "stateless"))
				openconnect_set_compression_mode(vpninfo, OC_COMPRESSION_MODE_STATELESS);
			else {
				fprintf(stderr, _("Invalid compression mode '%s'\n"),
					config_arg);
				exit(1);
			}
			break;
		case OPT_CAFILE:
			openconnect_set_cafile(vpninfo, dup_config_arg());
			break;
#ifndef _WIN32
		case OPT_PIDFILE:
			pidfile = keep_config_arg();
			break;
#endif
		case OPT_PFS:
			openconnect_set_pfs(vpninfo, 1);
			break;
		case OPT_ALLOW_INSECURE_CRYPTO:
			if (openconnect_set_allow_insecure_crypto(vpninfo, 1)) {
				fprintf(stderr, _("Cannot enable insecure 3DES or RC4 ciphers, because the library\n"
						  "%s no longer supports them.\n"), openconnect_get_tls_library_version());
				exit(1);
			}
			break;
		case OPT_SERVERCERT:
			newcert = malloc(sizeof(*newcert));
			if (!newcert) {
				fprintf(stderr, _("Failed to allocate memory\n"));
				exit(1);
			}
			newcert->next = accepted_certs;
			accepted_certs = newcert;
			newcert->fingerprint = keep_config_arg();
			newcert->host = NULL;
			newcert->port = 0;

			openconnect_set_system_trust(vpninfo, 0);
			allowed_fingerprints++;
			break;
		case OPT_RESOLVE:
			assert_nonnull_config_arg("resolve", config_arg);
			ip = strchr(config_arg, ':');
			if (!ip) {
				fprintf(stderr, _("Missing colon in resolve option\n"));
				exit(1);
			}
			gai = malloc(sizeof(*gai) + strlen(config_arg) + 1);
			if (!gai) {
				fprintf(stderr, _("Failed to allocate memory\n"));
				exit(1);
			}
			gai->next = gai_overrides;
			gai_overrides = gai;
			gai->option = (void *)(gai + 1);
			memcpy(gai->option, config_arg, strlen(config_arg) + 1);
			gai->option[ip - config_arg] = 0;
			gai->value = gai->option + (ip - config_arg) + 1;
			break;
		case OPT_SNI:
			openconnect_set_sni(vpninfo, config_arg);
			break;
		case OPT_NO_DTLS:
			openconnect_disable_dtls(vpninfo);
			break;
		case OPT_COOKIEONLY:
			cookieonly = 1;
			break;
		case OPT_PRINTCOOKIE:
			cookieonly = 2;
			break;
		case OPT_AUTHENTICATE:
			cookieonly = 3;
			break;
		case OPT_COOKIE_ON_STDIN:
			read_stdin(&vpninfo->cookie, 0, 0);
			/* If the cookie is empty, ignore it */
			if (!*vpninfo->cookie)
				vpninfo->cookie = NULL;
			break;
		case OPT_PASSWORD_ON_STDIN:
			read_stdin(&password, 0, 0);
			allow_stdin_read = 1;
			break;
		case OPT_NO_PASSWD:
			vpninfo->nopasswd = 1;
			break;
		case OPT_NO_XMLPOST:
			openconnect_set_xmlpost(vpninfo, 0);
			break;
		case OPT_NON_INTER:
			non_inter = 1;
			break;
		case OPT_RECONNECT_TIMEOUT:
			assert_nonnull_config_arg("reconnect-timeout", config_arg);
			reconnect_timeout = atoi(config_arg);
			break;
		case OPT_DTLS_CIPHERS:
			vpninfo->dtls_ciphers = keep_config_arg();
			break;
		case OPT_DTLS12_CIPHERS:
			vpninfo->dtls12_ciphers = keep_config_arg();
			break;
		case OPT_AUTHGROUP:
			authgroup = keep_config_arg();
			vpninfo->authgroup = strdup(authgroup);
			break;
		case 'C':
			vpninfo->cookie = dup_config_arg();
			break;
		case 'c':
			vpninfo->certinfo[0].cert = dup_config_arg();
			break;
		case 'e':
			assert_nonnull_config_arg("e", config_arg);
			vpninfo->cert_expire_warning = 86400 * atoi(config_arg);
			break;
		case 'k':
			vpninfo->certinfo[0].key = dup_config_arg();
			break;
		case 'd':
			vpninfo->req_compr = COMPR_ALL;
			break;
		case 'D':
			vpninfo->req_compr = 0;
			break;
		case 'g':
			free(urlpath);
			urlpath = dup_config_arg();
			break;
		case 'h':
			usage();
			break;
		case 'i':
#if defined(__APPLE__)
			if (!strncmp(config_arg, "tun", 3))
				fprintf(stderr,
					_("WARNING: You are running on macOS and specified --interface='%s'\n"
					  "         This probably won't work since recent macOS versions use utun\n"
					  "         instead. Perhaps try --interface='u%s', or omit altogether.\n"),
					config_arg, config_arg);
#endif
			vpninfo->ifname = dup_config_arg();
			break;
		case 'm': {
			assert_nonnull_config_arg("m", config_arg);
			int mtu = atol(config_arg);
			if (mtu < 576) {
				fprintf(stderr, _("MTU %d too small\n"), mtu);
				mtu = 576;
			}
			openconnect_set_reqmtu(vpninfo, mtu);
			break;
		}
		case OPT_BASEMTU:
			assert_nonnull_config_arg("base-mtu", config_arg);
			vpninfo->basemtu = atol(config_arg);
			if (vpninfo->basemtu < 576) {
				fprintf(stderr, _("MTU %d too small\n"), vpninfo->basemtu);
				vpninfo->basemtu = 576;
			}
			break;
		case 'p':
			vpninfo->certinfo[0].password = dup_config_arg();
			break;
		case 'P':
			proxy = keep_config_arg();
			autoproxy = 0;
			break;
		case OPT_PROXY_AUTH:
			openconnect_set_proxy_auth(vpninfo, config_arg);
			break;
		case OPT_HTTP_AUTH:
			openconnect_set_http_auth(vpninfo, config_arg);
			break;
		case OPT_NO_PROXY:
			autoproxy = 0;
			proxy = NULL;
			break;
		case OPT_NO_SYSTEM_TRUST:
			openconnect_set_system_trust(vpninfo, 0);
			break;
		case OPT_LIBPROXY:
			autoproxy = 1;
			proxy = NULL;
			break;
		case OPT_NO_HTTP_KEEPALIVE:
			fprintf(stderr,
				_("Disabling all HTTP connection re-use due to --no-http-keepalive option.\n"
				  "If this helps, please report to <%s>.\n"),
				"openconnect-devel@lists.infradead.org");
			vpninfo->no_http_keepalive = 1;
			break;
		case OPT_NO_CERT_CHECK:
			fprintf(stderr,
				_("The --no-cert-check option was insecure and has been removed.\n"
				  "Fix your server's certificate or use --servercert to trust it.\n"));
			exit(1);
			break;
		case 's':
			vpnc_script = dup_config_arg();
			break;
		case OPT_EXT_BROWSER:
			vpninfo->external_browser = dup_config_arg();
			break;
		case OPT_NO_EXTERNAL_AUTH:
			/* XX: Is this a workaround for a server bug, or a "normal" authentication option? */
			vpninfo->no_external_auth = 1;
			break;
		case 'u':
			free(username);
			username = dup_config_arg();
			break;
		case OPT_DISABLE_IPV6:
			openconnect_disable_ipv6(vpninfo);
			break;
		case 'Q':
			assert_nonnull_config_arg("Q", config_arg);
			vpninfo->max_qlen = atol(config_arg);
			if (!vpninfo->max_qlen) {
				fprintf(stderr, _("Queue length zero not permitted; using 1\n"));
				vpninfo->max_qlen = 1;
			}
			break;
		case 'q':
			verbose = PRG_ERR;
			break;
		case OPT_DUMP_HTTP:
			vpninfo->dump_http_traffic = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'V':
			printf(_("OpenConnect version %s\n"), openconnect_version_str);
			print_build_opts();
			print_supported_protocols();
			print_default_vpncscript();
			exit(0);
		case 'x':
			vpninfo->xmlconfig = keep_config_arg();
			vpninfo->write_new_config = write_new_config;
			break;
		case OPT_KEY_PASSWORD_FROM_FSID:
			do_passphrase_from_fsid = 1;
			break;
		case OPT_USERAGENT:
			free(vpninfo->useragent);
			vpninfo->useragent = dup_config_arg();
			break;
		case OPT_VERSION:
			free(vpninfo->version_string);
			vpninfo->version_string = dup_config_arg();
			break;
		case OPT_LOCAL_HOSTNAME:
			openconnect_set_localname(vpninfo, config_arg);
			break;
		case OPT_FORCE_DPD:
			assert_nonnull_config_arg("force-dpd", config_arg);
			openconnect_set_dpd(vpninfo, atoi(config_arg));
			break;
		case OPT_FORCE_TROJAN:
			assert_nonnull_config_arg("force-trojan", config_arg);
			openconnect_set_trojan_interval(vpninfo, atoi(config_arg));
			break;
		case OPT_DTLS_LOCAL_PORT:
			assert_nonnull_config_arg("dtls-local-port", config_arg);
			vpninfo->dtls_local_port = atoi(config_arg);
			break;
		case OPT_TOKEN_MODE:
			assert_nonnull_config_arg("token-mode", config_arg);
			if (strcasecmp(config_arg, "rsa") == 0) {
				token_mode = OC_TOKEN_MODE_STOKEN;
			} else if (strcasecmp(config_arg, "totp") == 0) {
				token_mode = OC_TOKEN_MODE_TOTP;
			} else if (strcasecmp(config_arg, "hotp") == 0) {
				token_mode = OC_TOKEN_MODE_HOTP;
			} else if (strcasecmp(config_arg, "yubioath") == 0) {
				token_mode = OC_TOKEN_MODE_YUBIOATH;
			} else if (strcasecmp(config_arg, "oidc") == 0) {
				token_mode = OC_TOKEN_MODE_OIDC;
			} else {
				fprintf(stderr, _("Invalid software token mode \"%s\"\n"),
					config_arg);
				exit(1);
			}
			break;
		case OPT_TOKEN_SECRET:
			token_str = keep_config_arg();
			break;
		case OPT_OS:
			assert_nonnull_config_arg("os", config_arg);
			if (openconnect_set_reported_os(vpninfo, config_arg)) {
				fprintf(stderr, _("Invalid OS identity \"%s\"\n"
						  "Allowed values: linux, linux-64, win, mac-intel, android, apple-ios\n"),
					config_arg);
				exit(1);
			}
			if (!strcmp(config_arg, "android") || !strcmp(config_arg, "apple-ios")) {
				/* generic defaults */
				openconnect_set_mobile_info(vpninfo,
					"1.0",
					config_arg,
					"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
			}
			break;
		case OPT_PASSTOS:
			openconnect_set_pass_tos(vpninfo, 1);
			break;
		case OPT_TIMESTAMP:
			timestamp = 1;
			break;
#ifdef OPENCONNECT_GNUTLS
		case OPT_GNUTLS_DEBUG:
			assert_nonnull_config_arg("gnutls-debug", config_arg);
			gnutls_global_set_log_level(atoi(config_arg));
			gnutls_global_set_log_function(oc_gnutls_log_func);
			break;
#endif
		case OPT_CIPHERSUITES:
			fprintf(stderr,
			        _("WARNING: You specified %s. This should not be\n"
			          "         necessary; please report cases where a priority string\n"
			          "         override is necessary to connect to a server\n"
			          "         to <%s>.\n"),
#ifdef OPENCONNECT_GNUTLS
			        "--gnutls-priority",
#elif defined(OPENCONNECT_OPENSSL)
			        "--openssl-ciphers",
#endif
			        "openconnect-devel@lists.infradead.org");

			vpninfo->ciphersuite_config = dup_config_arg();
			break;
		case OPT_MULTICERT_CERT:
			free(vpninfo->certinfo[1].cert);
			vpninfo->certinfo[1].cert = dup_config_arg();
			break;
		case OPT_MULTICERT_KEY:
			free(vpninfo->certinfo[1].key);
			vpninfo->certinfo[1].key = dup_config_arg();
			break;
		case OPT_MULTICERT_KEY_PASSWORD:
			free(vpninfo->certinfo[1].password);
			vpninfo->certinfo[1].password = dup_config_arg();
			break;
		case OPT_SERVER:
			server_url = keep_config_arg();
			break;
		default:
			usage();
		}
	}

	if (gai_overrides)
		openconnect_override_getaddrinfo(vpninfo, gai_override_cb);

	if (!server_url) {
		if (optind >= argc) {
			fprintf(stderr, _("No server specified\n"));
			usage();
		}
		server_url = argv[optind++];
	}
	if (optind < argc) {
		fprintf(stderr, _("Too many arguments on command line\n"));
		usage();
	}

	if (!vpninfo->certinfo[0].key)
		vpninfo->certinfo[0].key = vpninfo->certinfo[0].cert;

	if (!vpninfo->certinfo[1].key)
		vpninfo->certinfo[1].key = vpninfo->certinfo[1].cert;

	if (vpninfo->dump_http_traffic && verbose < PRG_DEBUG)
		verbose = PRG_DEBUG;

	openconnect_set_loglevel(vpninfo, verbose);
	if (autoproxy) {
#ifdef LIBPROXY_HDR
		vpninfo->proxy_factory = px_proxy_factory_new();
#else
		fprintf(stderr, _("This version of OpenConnect was built without libproxy support\n"));
		exit(1);
#endif
	}

	if (token_mode != OC_TOKEN_MODE_NONE)
		init_token(vpninfo, token_mode, token_str);

	if (proxy && openconnect_set_http_proxy(vpninfo, strdup(proxy)))
		exit(1);

#ifndef _WIN32
	memset(&sa, 0, sizeof(sa));
	memset(&sa, 0, sizeof(sa_ignore));

	sa.sa_handler = handle_signal;
	checked_sigaction(SIGTERM, &sa, NULL);
	checked_sigaction(SIGINT, &sa, NULL);
	checked_sigaction(SIGHUP, &sa, NULL);
	checked_sigaction(SIGUSR1, &sa, NULL);
	checked_sigaction(SIGUSR2, &sa, NULL);

	sa_ignore.sa_handler = SIG_IGN;
	checked_sigaction(SIGPIPE, &sa_ignore, NULL);
#else /* _WIN32 */
	SetConsoleCtrlHandler(console_ctrl_handler, TRUE /* Add */);
#endif

	sig_vpninfo = vpninfo;
	sig_cmd_fd = openconnect_setup_cmd_pipe(vpninfo);
	if (sig_cmd_fd < 0) {
#ifdef _WIN32
		char *errstr = openconnect__win32_strerror(GetLastError());
#else
		const char *errstr = strerror(errno);
#endif /* _WIN32 */
		fprintf(stderr, _("Error opening cmd pipe: %s\n"), errstr);
#ifdef _WIN32
		free(errstr);
#endif /* _WIN32 */
		exit(1);
	}
	vpninfo->cmd_fd_internal = 1;

	if (vpninfo->certinfo[0].key && do_passphrase_from_fsid)
		openconnect_passphrase_from_fsid(vpninfo);

	if (config_lookup_host(vpninfo, server_url))
		exit(1);

	/* If config_lookup_host() didn't set it, it'd better be a URL */
	if (!vpninfo->hostname) {
		char *url = strdup(server_url);

		if (openconnect_parse_url(vpninfo, url))
			exit(1);

		free(url);
	}

	/* Historically, the path in the URL superseded the one in the
	 * --usergroup argument, just because of the order in which they
	 * were processed. Preserve that behaviour. */
	if (urlpath && !vpninfo->urlpath) {
		vpninfo->urlpath = urlpath;
		urlpath = NULL;
	}
	free(urlpath);

	if (!vpninfo->cookie && openconnect_obtain_cookie(vpninfo)) {
		if (vpninfo->csd_scriptname) {
			unlink(vpninfo->csd_scriptname);
			vpninfo->csd_scriptname = NULL;
		}
		fprintf(stderr, _("Failed to complete authentication\n"));
		exit(1);
	}

	if (cookieonly == 3) {
		/* --authenticate */
		printf("COOKIE='%s'\n", vpninfo->cookie);
		printf("HOST='%s'\n", openconnect_get_hostname(vpninfo));
		printf("CONNECT_URL='%s'\n", openconnect_get_connect_url(vpninfo));
		printf("FINGERPRINT='%s'\n",
		       openconnect_get_peer_cert_hash(vpninfo));
		if (vpninfo->unique_hostname) {
			char *p = vpninfo->unique_hostname;
			int l = strlen(p);

			if (vpninfo->unique_hostname[0] == '[' &&
			    vpninfo->unique_hostname[l-1] == ']') {
				p++;
				l -=2;
			}
			printf("RESOLVE='%s:%.*s'\n", vpninfo->hostname, l, p);
		} else
			printf("RESOLVE=");
		sig_vpninfo = NULL;
		openconnect_vpninfo_free(vpninfo);
		exit(0);
	} else if (cookieonly) {
		printf("%s\n", vpninfo->cookie);
		if (cookieonly == 1) {
			/* We use cookieonly=2 for 'print it and continue' */
			sig_vpninfo = NULL;
			openconnect_vpninfo_free(vpninfo);
			exit(0);
		}
	}
	if ((ret = openconnect_make_cstp_connection(vpninfo)) != 0) {
		fprintf(stderr, _("Creating SSL connection failed\n"));
		goto out;
	}

	if (!vpnc_script)
		vpnc_script = xstrdup(default_vpncscript);

	vpninfo->vpnc_script = vpnc_script;

	if (vpninfo->dtls_state != DTLS_DISABLED &&
	    openconnect_setup_dtls(vpninfo, 60)) {
		/* Disable DTLS if we cannot set it up, otherwise
		 * reconnects end up in infinite loop trying to connect
		 * to non existing DTLS */
		vpninfo->dtls_state = DTLS_DISABLED;
		fprintf(stderr, _("Set up UDP failed; using SSL instead\n"));
	}


	if (!vpninfo->vpnc_script) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("No --script argument provided; DNS and routing are not configured\n"));
		vpn_progress(vpninfo, PRG_INFO,
			     _("See %s\n"),
			     "https://www.infradead.org/openconnect/vpnc-script.html");
	}


	openconnect_set_setup_tun_handler(vpninfo, fully_up_cb);
	openconnect_set_stats_handler(vpninfo, print_connection_stats);

	while (1) {
		ret = openconnect_mainloop(vpninfo, reconnect_timeout, RECONNECT_INTERVAL_MIN);
		if (ret)
			break;

		vpn_progress(vpninfo, PRG_INFO, _("User requested reconnect\n"));
	}

#ifndef _WIN32
	if (wrote_pid)
		unlink(pidfile);
#endif

 out:
	switch (ret) {
	case -EPERM:
		vpn_progress(vpninfo, PRG_ERR, _("Cookie was rejected by server; exiting.\n"));
		ret = 2;
		break;
	case -EPIPE:
		vpn_progress(vpninfo, PRG_ERR, _("Session terminated by server; exiting.\n"));
		ret = 1;
		break;
	case -EINTR:
		vpn_progress(vpninfo, PRG_INFO, _("User cancelled (%s); exiting.\n"),
#ifdef INSECURE_DEBUGGING
			     "SIGTERM"
#else
			     "SIGINT/SIGTERM"
#endif
			     );
		ret = 0;
		break;
	case -ECONNABORTED:
		vpn_progress(vpninfo, PRG_INFO, _("User detached from session (%s); exiting.\n"),
#ifdef INSECURE_DEBUGGING
			     "SIGHUP/SIGINT"
#else
			     "SIGHUP"
#endif
			     );
		ret = 0;
		break;
	case -EIO:
		vpn_progress(vpninfo, PRG_INFO, _("Unrecoverable I/O error; exiting.\n"));
		ret = 1;
		break;
	default:
		if (vpninfo->quit_reason)
			vpn_progress(vpninfo, PRG_ERR, "%s; exiting\n", vpninfo->quit_reason);
		else
			vpn_progress(vpninfo, PRG_ERR, _("Unknown error; exiting.\n"));
		ret = 1;
		break;
	}

	sig_vpninfo = NULL;
	openconnect_vpninfo_free(vpninfo);
	exit(ret);
}

static int write_new_config(void *_vpninfo, const char *buf, int buflen)
{
	struct openconnect_info *vpninfo = _vpninfo;
	int config_fd;
	int err;

	config_fd = openconnect_open_utf8(vpninfo, vpninfo->xmlconfig,
					  O_WRONLY|O_TRUNC|O_CREAT|O_BINARY);
	if (config_fd < 0) {
		err = errno;
		fprintf(stderr, _("Failed to open %s for write: %s\n"),
			vpninfo->xmlconfig, strerror(err));
		return -err;
	}

	/* FIXME: We should actually write to a new tempfile, then rename */
	if (write(config_fd, buf, buflen) != buflen) {
		err = errno;
		fprintf(stderr, _("Failed to write config to %s: %s\n"),
			vpninfo->xmlconfig, strerror(err));
		close(config_fd);
		return -err;
	}

	close(config_fd);
	return 0;
}

static void __attribute__ ((format(printf, 3, 4)))
    write_progress(void *_vpninfo, int level, const char *fmt, ...)
{
	struct openconnect_info *vpninfo = _vpninfo;
	FILE *outf = level ? stdout : stderr;
	va_list args;

	if (cookieonly)
		outf = stderr;

	if (vpninfo->verbose >= level) {
		if (timestamp) {
			char ts[64];
			time_t t = time(NULL);
			struct tm *tm = localtime(&t);

			strftime(ts, 64, "[%Y-%m-%d %H:%M:%S] ", tm);
			fprintf(outf, "%s", ts);
		}
		va_start(args, fmt);
		vfprintf(outf, fmt, args);
		va_end(args);
		fflush(outf);
	}
}

static int validate_peer_cert(void *_vpninfo, const char *reason)
{
	struct openconnect_info *vpninfo = _vpninfo;
	const char *fingerprint;
	struct accepted_cert *this;

	fingerprint = openconnect_get_peer_cert_hash(vpninfo);

	for (this = accepted_certs; this; this = this->next) {
#ifdef INSECURE_DEBUGGING
		if (this->port == 0 && this->host == NULL && !strcasecmp(this->fingerprint, "ACCEPT")) {
			fprintf(stderr, _("Insecurely accepting certificate from VPN server \"%s\" because you ran with --servercert=ACCEPT.\n"),
			        vpninfo->hostname);
			return 0;
		} else
#endif
		/* XX: if set by --servercert argument (port 0 and host NULL), accept for any host/port */
		if ((this->host == NULL || !strcasecmp(this->host, vpninfo->hostname)) &&
		    (this->port == 0 || this->port == vpninfo->port)) {
			int err = openconnect_check_peer_cert_hash(vpninfo, this->fingerprint);
			if (!err)
				return 0;
			else if (err < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Could not check server's certificate against %s\n"),
					     this->fingerprint);
			}
		}
	}

	if (allowed_fingerprints) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("None of the %d fingerprint(s) specified via --servercert match server's certificate: %s\n"),
			     allowed_fingerprints, fingerprint);
		return -EINVAL;
	}

	while (1) {
		char *details;
		char *response = NULL;

		fprintf(stderr, _("\nCertificate from VPN server \"%s\" failed verification.\n"
			 "Reason: %s\n"), vpninfo->hostname, reason);

		fprintf(stderr, _("To trust this server in future, perhaps add this to your command line:\n"));
		fprintf(stderr, _("    --servercert %s\n"), fingerprint);

		if (non_inter)
			return -EINVAL;

		fprintf(stderr, _("Enter '%s' to accept, '%s' to abort; anything else to view: "),
		       _("yes"), _("no"));

		read_stdin(&response, 0, 0);
		if (!response)
			return -EINVAL;

		if (!strcasecmp(response, _("yes"))) {
			struct accepted_cert *newcert;
			newcert = malloc(sizeof(*newcert));
			if (newcert) {
				newcert->next = accepted_certs;
				accepted_certs = newcert;
				newcert->fingerprint = strdup(fingerprint);
				newcert->host = strdup(vpninfo->hostname);
				newcert->port = vpninfo->port;
			}
			free(response);
			return 0;
		}
		if (!strcasecmp(response, _("no"))) {
			free(response);
			return -EINVAL;
		}
		free(response);

		details = openconnect_get_peer_cert_details(vpninfo);
		fputs(details, stderr);
		openconnect_free_cert_info(vpninfo, details);
		fprintf(stderr, _("Server key hash: %s\n"), fingerprint);
	}
}

static int match_choice_label(struct openconnect_info *vpninfo,
			      struct oc_form_opt_select *select_opt,
			      char *label)
{
	int i, input_len, partial_matches = 0;
	char *match = NULL;

	input_len = strlen(label);
	if (input_len < 1)
		return -EINVAL;

	for (i = 0; i < select_opt->nr_choices; i++) {
		struct oc_choice *choice = select_opt->choices[i];

		if (!strncasecmp(label, choice->label, input_len)) {
			if (strlen(choice->label) == input_len) {
				select_opt->form._value = choice->name;
				return 0;
			} else {
				match = choice->name;
				partial_matches++;
			}
		}
	}

	if (partial_matches == 1) {
		select_opt->form._value = match;
		return 0;
	} else if (partial_matches > 1) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Auth choice \"%s\" matches multiple options\n"), label);
		return -EINVAL;
	} else {
		vpn_progress(vpninfo, PRG_ERR, _("Auth choice \"%s\" not available\n"), label);
		return -EINVAL;
	}
}

static char *prompt_for_input(const char *prompt,
			      struct openconnect_info *vpninfo,
			      int hidden)
{
	char *response = NULL;

	fprintf(stderr, "%s", prompt);
	fflush(stderr);

	if (non_inter) {
		if (allow_stdin_read) {
			read_stdin(&response, hidden, 1);
		}
		if (response == NULL) {
			fprintf(stderr, "***\n");
			vpn_progress(vpninfo, PRG_ERR,
			     _("User input required in non-interactive mode\n"));
		}
		return response;
	}

	read_stdin(&response, hidden, 0);
	return response;
}

static int prompt_opt_select(struct openconnect_info *vpninfo,
			     struct oc_form_opt_select *select_opt,
			     char **saved_response)
{
	int i;
	char *response;

	if (!select_opt->nr_choices)
		return -EINVAL;

retry:
	fprintf(stderr, "%s [", select_opt->form.label);
	for (i = 0; i < select_opt->nr_choices; i++) {
		struct oc_choice *choice = select_opt->choices[i];
		if (i)
			fprintf(stderr, "|");

		fprintf(stderr, "%s", choice->label);
	}
	fprintf(stderr, "]:");

	if (select_opt->nr_choices == 1) {
		response = strdup(select_opt->choices[0]->label);
		fprintf(stderr, "%s\n", response);
	} else
		response = prompt_for_input("", vpninfo, 0);

	if (!response)
		return -EINVAL;

	if (match_choice_label(vpninfo, select_opt, response) < 0) {
		free(response);
		goto retry;
	}

	if (saved_response)
		*saved_response = response;
	else
		free(response);

	return 0;
}
struct form_field {
	struct form_field *next;
	char *form_id;
	char *opt_id;
	char *value;
};
static struct form_field *form_fields; /* static variable initialised to NULL */

static void add_form_field(char *arg)
{
	struct form_field *ff;
	char *opt, *value = strchr(arg, '=');

	if (!value)
		value = NULL; /* Just override hiddenness of form field */
	else if (value == arg) {
	bad_field:
		fprintf(stderr, "Form field invalid. Use --form-entry=FORM_ID:OPT_NAME=VALUE\n");
		exit(1);
	} else
		*(value++) = 0;

	opt = strchr(arg, ':');
	if (!opt || opt == arg)
		goto bad_field;
	*(opt++) = 0;

	ff = malloc(sizeof(*ff));
	if (!ff) {
		fprintf(stderr, "Out of memory for form field\n");
		exit(1);
	}
	ff->form_id = arg;
	ff->opt_id = opt;
	ff->value = value;
	ff->next = form_fields;
	form_fields = ff;
}

static char *saved_form_field(struct openconnect_info *vpninfo, const char *form_id, const char *opt_id, int *found)
{
	struct form_field *ff = form_fields;

	while (ff) {
		if (!strcmp(form_id, ff->form_id) && !strcmp(ff->opt_id, opt_id)) {
			if (found) *found = 1;
			return ff->value ? strdup(ff->value) : NULL;
		}
		ff = ff->next;
	}
	if (found) *found = 0;
	return NULL;
}

/* Return value:
 *  < 0, on error
 *  = 0, when form was parsed and POST required
 *  = 1, when response was cancelled by user
 */
static int process_auth_form_cb(void *_vpninfo,
				struct oc_auth_form *form)
{
	struct openconnect_info *vpninfo = _vpninfo;
	struct oc_form_opt *opt;
	int empty = 1;

	if (!form->auth_id)
		return -EINVAL;

	if (form->banner && vpninfo->verbose > PRG_ERR)
		fprintf(stderr, "%s\n", form->banner);

	if (form->error)
		fprintf(stderr, "%s\n", form->error);

	if (form->message && vpninfo->verbose > PRG_ERR)
		fprintf(stderr, "%s\n", form->message);

	/* Special handling for GROUP: field if present, as different group
	   selections can make other fields disappear/reappear */
	if (form->authgroup_opt) {
		if (!authgroup)
			authgroup = saved_form_field(vpninfo, form->auth_id, form->authgroup_opt->form.name, NULL);
		if (!authgroup ||
		    match_choice_label(vpninfo, form->authgroup_opt, authgroup) != 0) {
			if (prompt_opt_select(vpninfo, form->authgroup_opt, &authgroup) < 0)
				goto err;
		}
		if (!authgroup_set) {
			authgroup_set = 1;
			return OC_FORM_RESULT_NEWGROUP;
		}
	}

	for (opt = form->opts; opt; opt = opt->next) {

		if (opt->flags & OC_FORM_OPT_IGNORE)
			continue;

		/* I haven't actually seen a non-authgroup dropdown in the wild, but
		   the Cisco clients do support them */
		if (opt->type == OC_FORM_OPT_SELECT) {
			struct oc_form_opt_select *select_opt = (void *)opt;
			char *opt_response;

			if (select_opt == form->authgroup_opt)
				continue;

			opt_response = saved_form_field(vpninfo, form->auth_id, select_opt->form.name, NULL);
			if (opt_response &&
			    match_choice_label(vpninfo, select_opt, opt_response) == 0) {
				free(opt_response);
				continue;
			}
			free(opt_response);
			if (prompt_opt_select(vpninfo, select_opt, NULL) < 0)
				goto err;
			empty = 0;

		} else if (opt->type == OC_FORM_OPT_TEXT) {
			if (username &&
			    (!strncasecmp(opt->name, "user", 4) ||
			     !strncasecmp(opt->name, "uname", 5))) {
				opt->_value = strdup(username);
			} else {
				opt->_value = saved_form_field(vpninfo, form->auth_id, opt->name, NULL);
				if (!opt->_value)
				prompt:
					opt->_value = prompt_for_input(opt->label, vpninfo, 0);
			}

			if (!opt->_value)
				goto err;
			empty = 0;

		} else if (opt->type == OC_FORM_OPT_PASSWORD) {
			if (password) {
				opt->_value = password;
				password = NULL;
			} else {
				opt->_value = saved_form_field(vpninfo, form->auth_id, opt->name, NULL);
				if (!opt->_value)
					opt->_value = prompt_for_input(opt->label, vpninfo, 1);
			}

			if (!opt->_value)
				goto err;
			empty = 0;
		} else if (opt->type == OC_FORM_OPT_TOKEN) {
			/* Nothing to do here, but if the tokencode is being
			 * automatically generated then don't treat it as an
			 * empty form for the purpose of loop avoidance. */
			empty = 0;
		} else if (opt->type == OC_FORM_OPT_HIDDEN) {
			int found;
			char *value = saved_form_field(vpninfo, form->auth_id, opt->name, &found);
			if (value) {
				vpn_progress(vpninfo, PRG_DEBUG, "Overriding value of hidden form field '%s' to '%s'\n", opt->name, value);
				opt->_value = value;
			} else if (found) {
				vpn_progress(vpninfo, PRG_DEBUG, "Treating hidden form field '%s' as text entry\n", opt->name);
				goto prompt;
			}
		}
	}

	/* prevent infinite loops if the authgroup requires certificate auth only */
	if (!empty)
		last_form_empty = 0;
	else if (++last_form_empty >= 3) {
		vpn_progress(vpninfo, PRG_ERR, "%d consecutive empty forms, aborting loop\n", last_form_empty);
		return OC_FORM_RESULT_CANCELLED;
	}

	return OC_FORM_RESULT_OK;

 err:
	return OC_FORM_RESULT_ERR;
}

static int lock_token(void *tokdata)
{
	struct openconnect_info *vpninfo = tokdata;
	char *file_token;
	int err;

	/* FIXME: Actually lock the file */
	err = openconnect_read_file(vpninfo, token_filename, &file_token);
	if (err < 0)
		return err;

	err = openconnect_set_token_mode(vpninfo, vpninfo->token_mode, file_token);
	free(file_token);

	return err;
}

static int unlock_token(void *tokdata, const char *new_tok)
{
	struct openconnect_info *vpninfo = tokdata;
	int tok_fd;
	int err;

	if (!new_tok)
		return 0;

	tok_fd = openconnect_open_utf8(vpninfo, token_filename,
				       O_WRONLY|O_TRUNC|O_CREAT|O_BINARY);
	if (tok_fd < 0) {
		err = errno;
		fprintf(stderr, _("Failed to open token file for write: %s\n"),
			strerror(err));
		return -err;
	}

	/* FIXME: We should actually write to a new tempfile, then rename */
	if (write(tok_fd, new_tok, strlen(new_tok)) != strlen(new_tok)) {
		err = errno;
		fprintf(stderr, _("Failed to write token: %s\n"),
			strerror(err));
		close(tok_fd);
		return -err;
	}

	close(tok_fd);
	return 0;
}

static void init_token(struct openconnect_info *vpninfo,
		       oc_token_mode_t token_mode, const char *token_str)
{
	int ret;
	char *file_token = NULL;

	if (token_str && (token_mode == OC_TOKEN_MODE_TOTP ||
			  token_mode == OC_TOKEN_MODE_HOTP)) {
		switch (token_str[0]) {
		case '@':
			token_str++;
			/* fall through... */
		case '/':
			if (openconnect_read_file(vpninfo, token_str,
						  &file_token) < 0)
				exit(1);
			break;
		default:
			/* Use token_str as raw data */
			break;
		}
	}

	ret = openconnect_set_token_mode(vpninfo, token_mode,
					 file_token ? : token_str);
	if (file_token) {
		token_filename = strdup(token_str);
		openconnect_set_token_callbacks(vpninfo, vpninfo,
						lock_token, unlock_token);
		free(file_token);
	}
	switch (token_mode) {
	case OC_TOKEN_MODE_STOKEN:
		switch (ret) {
		case 0:
			return;
		case -EINVAL:
			fprintf(stderr, _("Soft token string is invalid\n"));
			exit(1);
		case -ENOENT:
			if (token_str)
				fprintf(stderr, _("Can't open stoken file\n"));
			else
				fprintf(stderr, _("Can't open ~/.stokenrc file\n"));
			exit(1);
		case -EOPNOTSUPP:
			fprintf(stderr, _("OpenConnect was not built with libstoken support\n"));
			exit(1);
		default:
			fprintf(stderr, _("General failure in libstoken\n"));
			exit(1);
		}

		break;

	case OC_TOKEN_MODE_TOTP:
	case OC_TOKEN_MODE_HOTP:
		switch (ret) {
		case 0:
			return;
		case -EINVAL:
			fprintf(stderr, _("Soft token string is invalid\n"));
			exit(1);
		default:
			fprintf(stderr, _("General failure in TOTP/HOTP support\n"));
			exit(1);
		}

		break;

	case OC_TOKEN_MODE_YUBIOATH:
		switch (ret) {
		case 0:
			return;
		case -ENOENT:
			fprintf(stderr, _("Yubikey token not found\n"));
			exit(1);
		case -EOPNOTSUPP:
			fprintf(stderr, _("OpenConnect was not built with Yubikey support\n"));
			exit(1);
		default:
			fprintf(stderr, _("General Yubikey failure: %s\n"), strerror(-ret));
			exit(1);
		}

	case OC_TOKEN_MODE_OIDC:
		switch (ret) {
		case 0:
			return;
		case -ENOENT:
			fprintf(stderr, _("Can't open oidc file\n"));
			exit(1);
		default:
			fprintf(stderr, _("General failure in oidc token\n"));
			exit(1);
		}

		break;
	case OC_TOKEN_MODE_NONE:
		/* No-op */
		break;

	/* Option parsing already checked for invalid modes. */
	}
}
