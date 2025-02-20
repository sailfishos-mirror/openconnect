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

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef HAVE_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/ui.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#include <sys/types.h>

#include <errno.h>
#include <string.h>
#include <ctype.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_up_ref(x) CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_X509)
#define X509_get0_notAfter(x) X509_get_notAfter(x)
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#define X509_STORE_CTX_get0_chain(ctx) ((ctx)->chain)
#define X509_STORE_CTX_get0_untrusted(ctx) ((ctx)->untrusted)
#define X509_STORE_CTX_get0_cert(ctx) ((ctx)->cert)
typedef int (*X509_STORE_CTX_get_issuer_fn)(X509 **issuer,
					    X509_STORE_CTX *ctx, X509 *x);
#define X509_STORE_CTX_get_get_issuer(ctx) ((ctx)->get_issuer)
#define OpenSSL_version SSLeay_version
#define OPENSSL_VERSION SSLEAY_VERSION
#endif

static char tls_library_version[32] = "";

const char *openconnect_get_tls_library_version(void)
{
	if (!*tls_library_version) {
		strncpy(tls_library_version,
			OpenSSL_version(OPENSSL_VERSION),
			sizeof(tls_library_version));
		tls_library_version[sizeof(tls_library_version)-1]='\0';
	}
	return tls_library_version;
}

int can_enable_insecure_crypto(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (OSSL_PROVIDER_load(NULL, "legacy") == NULL ||
	    OSSL_PROVIDER_load(NULL, "default") == NULL)
		return -ENOENT;
#endif
	if (EVP_des_ede3_cbc() == NULL ||
	    EVP_rc4() == NULL)
		return -ENOENT;
	return 0;
}

int openconnect_sha1(unsigned char *result, void *data, int len)
{
	EVP_MD_CTX *c = EVP_MD_CTX_new();

	if (!c)
		return -ENOMEM;

	EVP_Digest(data, len, result, NULL, EVP_sha1(), NULL);
	EVP_MD_CTX_free(c);

	return 0;
}

int openconnect_sha256(unsigned char *result, void *data, int len)
{
	EVP_MD_CTX *c = EVP_MD_CTX_new();

	if (!c)
		return -ENOMEM;

	EVP_Digest(data, len, result, NULL, EVP_sha256(), NULL);
	EVP_MD_CTX_free(c);

	return 0;
}

int openconnect_md5(unsigned char *result, void *data, int len)
{
	EVP_MD_CTX *c = EVP_MD_CTX_new();

	if (!c)
		return -ENOMEM;

	EVP_Digest(data, len, result, NULL, EVP_md5(), NULL);
	EVP_MD_CTX_free(c);

	return 0;
}

int openconnect_get_peer_cert_DER(struct openconnect_info *vpninfo,
				  unsigned char **buf)
{
	BIO *bp = BIO_new(BIO_s_mem());
	BUF_MEM *certinfo;
	size_t l;

	if (!i2d_X509_bio(bp, vpninfo->peer_cert)) {
		BIO_free(bp);
		return -EIO;
	}

	BIO_get_mem_ptr(bp, &certinfo);
	l = certinfo->length;
	*buf = malloc(l);
	if (!*buf) {
		BIO_free(bp);
		return -ENOMEM;
	}
	memcpy(*buf, certinfo->data, l);
	BIO_free(bp);
	return l;
}

int openconnect_random(void *bytes, int len)
{
	if (RAND_bytes(bytes, len) != 1)
		return -EIO;
	return 0;
}

/* Helper functions for reading/writing lines over TLS/DTLS.
   We could use cURL for the HTTP stuff, but it's overkill */

static int _openconnect_openssl_write(SSL *ssl, int fd, struct openconnect_info *vpninfo, char *buf, size_t len)
{
	size_t orig_len = len;

	while (len) {
		int done = SSL_write(ssl, buf, len);

		if (done > 0)
			len -= done;
		else {
			int err = SSL_get_error(ssl, done);
			fd_set wr_set, rd_set;
			int maxfd = fd;

			FD_ZERO(&wr_set);
			FD_ZERO(&rd_set);

			if (err == SSL_ERROR_WANT_READ)
				FD_SET(fd, &rd_set);
			else if (err == SSL_ERROR_WANT_WRITE)
				FD_SET(fd, &wr_set);
			else {
				vpn_progress(vpninfo, PRG_ERR, _("Failed to write to TLS/DTLS socket\n"));
				openconnect_report_ssl_errors(vpninfo);
				return -EIO;
			}
			cmd_fd_set(vpninfo, &rd_set, &maxfd);
			while (select(maxfd + 1, &rd_set, &wr_set, NULL, NULL) < 0) {
				if (errno != EINTR) {
					vpn_perror(vpninfo, _("Failed select() for TLS/DTLS"));
					return -EIO;
				}
			}

			if (is_cancel_pending(vpninfo, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("TLS/DTLS write cancelled\n"));
				return -EINTR;
			}
		}
	}
	return orig_len;
}

static int openconnect_openssl_write(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	return _openconnect_openssl_write(vpninfo->https_ssl, vpninfo->ssl_fd, vpninfo, buf, len);
}

int openconnect_dtls_write(struct openconnect_info *vpninfo, void *buf, size_t len)
{
	return _openconnect_openssl_write(vpninfo->dtls_ssl, vpninfo->dtls_fd, vpninfo, buf, len);
}

/* set ms to zero for no timeout */
static int _openconnect_openssl_read(SSL *ssl, int fd, struct openconnect_info *vpninfo, char *buf, size_t len, unsigned ms)
{
	int done, ret;
	struct timeval timeout, *tv = NULL;

	if (ms) {
		timeout.tv_sec = ms/1000;
		timeout.tv_usec = (ms%1000)*1000;
		tv = &timeout;
	}

	while ((done = SSL_read(ssl, buf, len)) == -1) {
		int err = SSL_get_error(ssl, done);
		fd_set wr_set, rd_set;
		int maxfd = fd;

		FD_ZERO(&wr_set);
		FD_ZERO(&rd_set);

		if (err == SSL_ERROR_WANT_READ)
			FD_SET(fd, &rd_set);
		else if (err == SSL_ERROR_WANT_WRITE)
			FD_SET(fd, &wr_set);
		else {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to read from TLS/DTLS socket\n"));
			openconnect_report_ssl_errors(vpninfo);
			return -EIO;
		}
		cmd_fd_set(vpninfo, &rd_set, &maxfd);
		while ((ret = select(maxfd + 1, &rd_set, &wr_set, NULL, tv)) < 0) {
			if (errno != EINTR) {
				vpn_perror(vpninfo, _("Failed select() for TLS/DTLS"));
				return -EIO;
			}
		}
		if (is_cancel_pending(vpninfo, &rd_set)) {
			vpn_progress(vpninfo, PRG_ERR, _("TLS/DTLS read cancelled\n"));
			return -EINTR;
		}

		if (ret == 0) {
			return -ETIMEDOUT;
		}
	}
	return done;
}

static int openconnect_openssl_read(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	return _openconnect_openssl_read(vpninfo->https_ssl, vpninfo->ssl_fd, vpninfo, buf, len, 0);
}

int openconnect_dtls_read(struct openconnect_info *vpninfo, void *buf, size_t len, unsigned ms)
{
	return _openconnect_openssl_read(vpninfo->dtls_ssl, vpninfo->dtls_fd, vpninfo, buf, len, ms);
}

static int openconnect_openssl_gets(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	int i = 0;
	int ret;

	if (len < 2)
		return -EINVAL;

	while (1) {
		ret = SSL_read(vpninfo->https_ssl, buf + i, 1);
		if (ret == 1) {
			if (buf[i] == '\n') {
				buf[i] = 0;
				if (i && buf[i-1] == '\r') {
					buf[i-1] = 0;
					i--;
				}
				return i;
			}
			i++;

			if (i >= len - 1) {
				buf[i] = 0;
				return i;
			}
		} else {
			fd_set rd_set, wr_set;
			int maxfd = vpninfo->ssl_fd;

			FD_ZERO(&rd_set);
			FD_ZERO(&wr_set);

			ret = SSL_get_error(vpninfo->https_ssl, ret);
			if (ret == SSL_ERROR_WANT_READ)
				FD_SET(vpninfo->ssl_fd, &rd_set);
			else if (ret == SSL_ERROR_WANT_WRITE)
				FD_SET(vpninfo->ssl_fd, &wr_set);
			else {
				vpn_progress(vpninfo, PRG_ERR, _("Failed to read from TLS/DTLS socket\n"));
				openconnect_report_ssl_errors(vpninfo);
				ret = -EIO;
				break;
			}
			cmd_fd_set(vpninfo, &rd_set, &maxfd);
			while (select(maxfd + 1, &rd_set, &wr_set, NULL, NULL) < 0) {
				if (errno != EINTR) {
					vpn_perror(vpninfo, _("Failed select() for TLS/DTLS"));
					return -EIO;
				}
			}
			if (is_cancel_pending(vpninfo, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("TLS/DTLS read cancelled\n"));
				ret = -EINTR;
				break;
			}
		}
	}
	buf[i] = 0;
	return i ?: ret;
}

int ssl_nonblock_read(struct openconnect_info *vpninfo, int dtls, void *buf, int maxlen)
{
	SSL *ssl = dtls ? vpninfo->dtls_ssl : vpninfo->https_ssl;
	int len, ret;

	if (!ssl) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Attempted to read from non-existent %s session\n"),
			     dtls ? "DTLS" : "TLS");
		return -1;
	}

	len = SSL_read(ssl, buf, maxlen);
	if (len > 0)
		return len;

	ret = SSL_get_error(ssl, len);
	if (ret == SSL_ERROR_WANT_WRITE || ret == SSL_ERROR_WANT_READ)
		return 0;

	vpn_progress(vpninfo, PRG_ERR, _("Read error on %s session: %d\n"),
		       dtls ? "DTLS" : "TLS", ret);
	return -EIO;
}

int ssl_nonblock_write(struct openconnect_info *vpninfo, int dtls, void *buf, int buflen)
{
	SSL *ssl = dtls ? vpninfo->dtls_ssl : vpninfo->https_ssl;
	int ret;

	if (!ssl) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Attempted to write to non-existent %s session\n"),
			     dtls ? "DTLS" : "TLS");
		return -1;
	}

	ret = SSL_write(ssl, buf, buflen);
	if (ret > 0)
		return ret;

	ret = SSL_get_error(ssl, ret);
	switch (ret) {
	case SSL_ERROR_WANT_WRITE:
		/* Waiting for the socket to become writable -- it's
		   probably stalled, and/or the buffers are full */
		if (dtls)
			monitor_write_fd(vpninfo, dtls);
		else
			monitor_write_fd(vpninfo, ssl);
		/* Fall through */
	case SSL_ERROR_WANT_READ:
		return 0;

	default:
		vpn_progress(vpninfo, PRG_ERR, _("Write error on %s session: %d\n"),
			     dtls ? "DTLS" : "TLS", ret);
		openconnect_report_ssl_errors(vpninfo);
		return -1;
	}
}

/* UI handling. All this just to handle the PIN callback from the TPM ENGINE,
   and turn it into a call to our ->process_auth_form function */

struct ui_data {
	struct openconnect_info *vpninfo;
	struct oc_form_opt **last_opt;
	struct oc_auth_form form;
};

struct ui_form_opt {
	struct oc_form_opt opt;
	UI_STRING *uis;
};

#ifdef HAVE_ENGINE
static int ui_open(UI *ui)
{
	struct openconnect_info *vpninfo = UI_get0_user_data(ui);
	struct ui_data *ui_data;

	if (!vpninfo || !vpninfo->process_auth_form)
		return 0;

	ui_data = malloc(sizeof(*ui_data));
	if (!ui_data)
		return 0;

	memset(ui_data, 0, sizeof(*ui_data));
	ui_data->last_opt = &ui_data->form.opts;
	ui_data->vpninfo = vpninfo;
	ui_data->form.auth_id = (char *)"openssl_ui";

	UI_add_user_data(ui, ui_data);

	return 1;
}

static int ui_write(UI *ui, UI_STRING *uis)
{
	struct ui_data *ui_data = UI_get0_user_data(ui);
	struct ui_form_opt *opt;

	switch (UI_get_string_type(uis)) {
	case UIT_ERROR:
		ui_data->form.error = (char *)UI_get0_output_string(uis);
		break;
	case UIT_INFO:
		ui_data->form.message = (char *)UI_get0_output_string(uis);
		break;
	case UIT_PROMPT:
		opt = malloc(sizeof(*opt));
		if (!opt)
			return 1;
		memset(opt, 0, sizeof(*opt));
		opt->uis = uis;
		opt->opt.label = opt->opt.name = (char *)UI_get0_output_string(uis);
		if (UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO)
			opt->opt.type = OC_FORM_OPT_TEXT;
		else
			opt->opt.type = OC_FORM_OPT_PASSWORD;
		*(ui_data->last_opt) = &opt->opt;
		ui_data->last_opt = &opt->opt.next;
		break;

	default:
		vpn_progress(ui_data->vpninfo, PRG_ERR,
			     _("Unhandled SSL UI request type %d\n"),
			     UI_get_string_type(uis));
		return 0;
	}
	return 1;
}

static int ui_flush(UI *ui)
{
	struct ui_data *ui_data = UI_get0_user_data(ui);
	struct openconnect_info *vpninfo = ui_data->vpninfo;
	struct ui_form_opt *opt;
	int ret;

	ret = process_auth_form(vpninfo, &ui_data->form);
	if (ret)
		return 0;

	for (opt = (struct ui_form_opt *)ui_data->form.opts; opt;
	     opt = (struct ui_form_opt *)opt->opt.next) {
		if (opt->opt._value && opt->uis)
			UI_set_result(ui, opt->uis, opt->opt._value);
	}
	return 1;
}

static int ui_close(UI *ui)
{
	struct ui_data *ui_data = UI_get0_user_data(ui);
	struct ui_form_opt *opt, *next_opt;

	opt = (struct ui_form_opt *)ui_data->form.opts;
	while (opt) {
		next_opt = (struct ui_form_opt *)opt->opt.next;
		if (opt->opt._value)
			free(opt->opt._value);
		free(opt);
		opt = next_opt;
	}
	free(ui_data);
	UI_add_user_data(ui, NULL);

	return 1;
}

static UI_METHOD *create_openssl_ui(void)
{
	UI_METHOD *ui_method = UI_create_method((char *)"AnyConnect VPN UI");

	/* Set up a UI method of our own for password/passphrase requests */
	UI_method_set_opener(ui_method, ui_open);
	UI_method_set_writer(ui_method, ui_write);
	UI_method_set_flusher(ui_method, ui_flush);
	UI_method_set_closer(ui_method, ui_close);

	return ui_method;
}
#endif

static int pem_pw_cb(char *buf, int len, int w, void *ci)
{
	struct cert_info *certinfo = ci;
	struct openconnect_info *vpninfo = certinfo->vpninfo;
	char *pass = NULL;
	int plen;

	if (certinfo->password) {
		pass = certinfo->password;
		certinfo->password = NULL;
	} else if (request_passphrase(vpninfo,
				      certinfo_string(certinfo, "openconnect_pem", "openconnect_secondary_pem"),
				      &pass,
				      certinfo_string(certinfo, _("Enter PEM pass phrase:"),
						      _("Enter secondary PEM pass phrase:"))))
		return -1;

	plen = strlen(pass);

	if (len <= plen) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("PEM password too long (%d >= %d)\n"),
			     plen, len);
		free_pass(&pass);
		return -1;
	}

	memcpy(buf, pass, plen+1);
	free_pass(&pass);
	return plen;
}

struct ossl_cert_info {
	EVP_PKEY *key;
	X509 *cert;
	STACK_OF(X509) *extra_certs;
	const char *certs_from;
};

void unload_certificate(struct cert_info *certinfo, int finalize)
{
	(void) finalize;

	if (!certinfo)
		return;

	if (certinfo->priv_info) {
		struct ossl_cert_info *oci = certinfo->priv_info;

		certinfo->priv_info = NULL;
		if (oci->key)
			EVP_PKEY_free(oci->key);
		if (oci->cert)
			X509_free(oci->cert);
		if (oci->extra_certs)
			sk_X509_pop_free(oci->extra_certs, X509_free);
		free(oci);
	}
}

static int install_ssl_ctx_certs(struct openconnect_info *vpninfo, struct ossl_cert_info *oci)
{
	X509 *cert = oci->cert;
	int i;

	if (!cert || !oci->key) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Client certificate or key missing\n"));
		return -EINVAL;
	}

	if (!SSL_CTX_use_PrivateKey(vpninfo->https_ctx, oci->key)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Loading private key failed\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EIO;
	}

	if (!SSL_CTX_use_certificate(vpninfo->https_ctx, cert)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to install certificate in OpenSSL context\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EIO;
	}

	vpninfo->cert_x509 = cert;
	X509_up_ref(cert);

	if (!oci->extra_certs)
		return 0;
 next:
	for (i = 0; i < sk_X509_num(oci->extra_certs); i++) {
		X509 *cert2 = sk_X509_value(oci->extra_certs, i);
		if (X509_check_issued(cert2, cert) == X509_V_OK) {
			char buf[200];

			if (cert2 == cert)
				break;
			if (X509_check_issued(cert2, cert2) == X509_V_OK)
				break;

			X509_NAME_oneline(X509_get_subject_name(cert2),
					  buf, sizeof(buf));
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Extra cert from %s: '%s'\n"), oci->certs_from, buf);
			X509_up_ref(cert2);
			SSL_CTX_add_extra_chain_cert(vpninfo->https_ctx, cert2);
			cert = cert2;
			goto next;
		}
	}

	return 0;
}

static int load_pkcs12_certificate(struct openconnect_info *vpninfo, struct cert_info *certinfo,
				   struct ossl_cert_info *oci, PKCS12 *p12)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca;
	int ret = 0;
	char *pass;

	pass = certinfo->password;
	certinfo->password = NULL;
 retrypass:
	/* We do this every time round the loop, to work around a bug in
	   OpenSSL < 1.0.0-beta2 -- where the stack at *ca will be freed
	   when PKCS12_parse() returns an error, but *ca is left pointing
	   to the freed memory. */
	ca = NULL;
	if (!PKCS12_parse(p12, pass, &pkey, &cert, &ca)) {
		unsigned long err = ERR_peek_error();

		if (ERR_GET_LIB(err) == ERR_LIB_PKCS12 &&
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		    ERR_GET_FUNC(err) == PKCS12_F_PKCS12_PARSE &&
#endif
		    ERR_GET_REASON(err) == PKCS12_R_MAC_VERIFY_FAILURE) {
			if (pass)
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to decrypt PKCS#12 certificate file\n"));
			free_pass(&pass);
			if (request_passphrase(vpninfo,
					       certinfo_string(certinfo, "openconnect_pkcs12",
							       "openconnect_secondary_pkcs12"),
					       &pass,
					       certinfo_string(certinfo, _("Enter PKCS#12 pass phrase:"),
							       _("Enter secondary PKCS#12 pass phrase:"))) < 0) {
				PKCS12_free(p12);
				return -EINVAL;
			}

			goto retrypass;
		}

		openconnect_report_ssl_errors(vpninfo);

		vpn_progress(vpninfo, PRG_ERR,
			     certinfo_string(certinfo, _("Parse PKCS#12 failed (see above errors)\n"),
					     _("Parse secondary PKCS#12 failed (see above errors)\n")));
		PKCS12_free(p12);
		free_pass(&pass);
		return -EINVAL;
	}
	free_pass(&pass);

	if (cert) {
		char buf[200];

		X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
		vpn_progress(vpninfo, PRG_INFO,
			     certinfo_string(certinfo, _("Using client certificate '%s'\n"),
					     _("Using secondary certificate '%s'\n")), buf);

	} else {
		vpn_progress(vpninfo, PRG_ERR,
			     certinfo_string(certinfo, _("PKCS#12 contained no certificate!\n"),
					     _("Secondary PKCS#12 contained no certificate!\n")));
		ret = -EINVAL;
	}

	if (!pkey) {
		vpn_progress(vpninfo, PRG_ERR,
			     certinfo_string(certinfo, _("PKCS#12 contained no private key!\n"),
					     _("Secondary PKCS#12 contained no private key!\n")));
		ret = -EINVAL;
	}

	oci->key = pkey;
	oci->cert = cert;
	oci->extra_certs = ca;
	oci->certs_from = _("PKCS#12");

	PKCS12_free(p12);

	if (ret)
		unload_certificate(certinfo, 1);

	return ret;
}

#ifdef HAVE_ENGINE
static int load_tpm_certificate(struct openconnect_info *vpninfo, struct cert_info *certinfo,
				struct ossl_cert_info *oci, const char *engine)
{
	ENGINE *e;
	EVP_PKEY *key;
	UI_METHOD *meth = NULL;
	int ret = 0;

	ENGINE_load_builtin_engines();

	e = ENGINE_by_id(engine);
	if (!e && !strcmp(engine, "tpm2")) {
		ERR_clear_error();
		e = ENGINE_by_id("tpm2tss");
	}
	if (!e) {
		vpn_progress(vpninfo, PRG_ERR, _("Can't load TPM engine.\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}
	if (!ENGINE_init(e) || !ENGINE_set_default_RSA(e) ||
	    !ENGINE_set_default_RAND(e)) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to init TPM engine\n"));
		openconnect_report_ssl_errors(vpninfo);
		ENGINE_free(e);
		return -EINVAL;
	}

	if (certinfo->password) {
		if (!ENGINE_ctrl_cmd(e, "PIN", strlen(certinfo->password),
				     certinfo->password, NULL, 0)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to set TPM SRK password\n"));
			openconnect_report_ssl_errors(vpninfo);
		}
		free_pass(&certinfo->password);
	}

	/* Provide our own UI method to handle the PIN callback. */
	meth = create_openssl_ui();

	key = ENGINE_load_private_key(e, certinfo->key, meth, vpninfo);
	if (meth)
		UI_destroy_method(meth);
	if (!key) {
		vpn_progress(vpninfo, PRG_ERR,
			     certinfo_string(certinfo, _("Failed to load TPM private key\n"),
					     _("Failed to load secondary TPM private key\n")));
		openconnect_report_ssl_errors(vpninfo);
		ret = -EINVAL;
		goto out;
	}

	oci->key = key;
 out:
	ENGINE_finish(e);
	ENGINE_free(e);
	return ret;
}
#else
static int load_tpm_certificate(struct openconnect_info *vpninfo, struct cert_info *certinfo,
				struct ossl_cert_info *oci, const char *engine)
{
	vpn_progress(vpninfo, PRG_ERR,
		     _("This version of OpenConnect was built without TPM support\n"));
	return -EINVAL;
}
#endif

/* This is a reimplementation of SSL_CTX_use_certificate_chain_file().
 * We do this for three reasons:
 *
 * - Firstly, we have no way to obtain the primary X509 certificate
 *   after SSL_CTX_use_certificate_chain_file() has loaded it, and we
 *   need to inspect it to check for expiry and report its name etc.
 *   So in the past we've opened the cert file again and read the cert
 *   again in a reload_pem_cert() function which was a partial
 *   reimplementation anyway.
 *
 * - Secondly, on Windows, OpenSSL only partially handles UTF-8 filenames.
 *   Specifically, BIO_new_file() will convert UTF-8 to UTF-16 and attempt
 *   to use _wfopen() to open the file, but BIO_read_filename() will not.
 *   It is BIO_read_filename() which the SSL_CTX_*_file functions use, and
 *   thus they don't work with UTF-8 file names. This is filed as RT#3479:
 *   http://rt.openssl.org/Ticket/Display.html?id=3479
 *
 * - Finally, and least importantly, it does actually matter which supporting
 *   certs we offer on the wire because of RT#1942. Doing this for ourselves
 *   allows us to explicitly print the supporting certs that we're using,
 *   which may assist in diagnosing problems.
 */
static int load_cert_chain_file(struct openconnect_info *vpninfo, struct cert_info *certinfo,
				struct ossl_cert_info *oci)
{
	BIO *b;
	FILE *f = openconnect_fopen_utf8(vpninfo, certinfo->cert, "rb");
	STACK_OF(X509) *extra_certs = NULL;
	char buf[200];

	if (!f) {
		vpn_progress(vpninfo, PRG_ERR,
			     certinfo_string(certinfo, _("Failed to open certificate file %s: %s\n"),
					     _("Failed to open secondary certificate file %s: %s\n")),
			     certinfo->cert, strerror(errno));
		return -ENOENT;
	}

	b = BIO_new_fp(f, 1);
	if (!b) {
		fclose(f);
	err:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Loading certificate failed\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EIO;
	}
	oci->cert = PEM_read_bio_X509_AUX(b, NULL, NULL, NULL);
	if (!oci->cert) {
		BIO_free(b);
		goto err;
	}

	X509_NAME_oneline(X509_get_subject_name(oci->cert), buf, sizeof(buf));
	vpn_progress(vpninfo, PRG_INFO,
		     certinfo_string(certinfo, _("Using client certificate '%s'\n"),
				     _("Using secondary certificate '%s'\n")), buf);

	while (1) {
		X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);
		if (!x) {
			unsigned long err = ERR_peek_last_error();
			if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
			    ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
				ERR_clear_error();
			else
				goto err_extra;
			break;
		}
		if (!extra_certs)
			extra_certs = sk_X509_new_null();
		if (!extra_certs) {
		err_extra:
			vpn_progress(vpninfo, PRG_ERR,
				     certinfo_string(certinfo, _("Failed to process all supporting certs. Trying anyway...\n"),
						     _("Failed to process secondary supporting certs. Trying anyway...\n")));
			openconnect_report_ssl_errors(vpninfo);
			X509_free(x);
			/* It might work without... */
			break;
		}
		if (!sk_X509_push(extra_certs, x))
			goto err_extra;
	}

	BIO_free(b);

	oci->extra_certs = extra_certs;
	oci->certs_from = _("PEM file");

	return 0;
}

#ifdef ANDROID_KEYSTORE
static BIO *BIO_from_keystore(struct openconnect_info *vpninfo, const char *item)
{
	unsigned char *content;
	BIO *b;
	int len;
	const char *p = item + 9;

	/* Skip first two slashes if the user has given it as
	   keystore://foo ... */
	if (*p == '/')
		p++;
	if (*p == '/')
		p++;

	len = keystore_fetch(p, &content);
	if (len < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to load item '%s' from keystore: %s\n"),
			     p, keystore_strerror(len));
		return NULL;
	}
	if (!(b = BIO_new(BIO_s_mem())) || BIO_write(b, content, len) != len) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to create BIO for keystore item '%s'\n"),
			       p);
		free(content);
		BIO_free(b);
		return NULL;
	}
	free(content);
	return b;
}
#endif

static int is_pem_password_error(struct openconnect_info *vpninfo, struct cert_info *certinfo)
{
	unsigned long err = ERR_peek_error();

	openconnect_report_ssl_errors(vpninfo);

#ifndef EVP_F_EVP_DECRYPTFINAL_EX
#define EVP_F_EVP_DECRYPTFINAL_EX EVP_F_EVP_DECRYPTFINAL
#endif
	/* If the user fat-fingered the passphrase, try again */
	if (ERR_GET_LIB(err) == ERR_LIB_EVP &&
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	    ERR_GET_FUNC(err) == EVP_F_EVP_DECRYPTFINAL_EX &&
#endif
	    ERR_GET_REASON(err) == EVP_R_BAD_DECRYPT) {
		vpn_progress(vpninfo, PRG_ERR,
			     certinfo_string(certinfo, _("Loading private key failed (wrong passphrase?)\n"),
					     _("Loading secondary private key failed (wrong passphrase?)\n")));
		ERR_clear_error();
		return 1;
	}

	vpn_progress(vpninfo, PRG_ERR,
		     certinfo_string(certinfo, _("Loading private key failed (see above errors)\n"),
				     _("Loading secondary private key failed (see above errors)\n")));
	return 0;
}

static int xload_certificate(struct openconnect_info *vpninfo, struct cert_info *certinfo,
			    struct ossl_cert_info *oci)
{
	FILE *f;
	char buf[256];
	int ret;

	if (!strncmp(certinfo->cert, "pkcs11:", 7)) {
		int ret = load_pkcs11_certificate(vpninfo, certinfo, &oci->cert);
		if (ret)
			return ret;
		goto got_cert;
	}

	vpn_progress(vpninfo, PRG_DEBUG,
		     certinfo_string(certinfo, _("Using certificate file %s\n"),
				     _("Using secondary certificate file %s\n")),
				     certinfo->cert);

	if (strncmp(certinfo->cert, "keystore:", 9)) {
		PKCS12 *p12;

		f = openconnect_fopen_utf8(vpninfo, certinfo->cert, "rb");
		if (!f) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to open certificate file %s: %s\n"),
				     certinfo->cert, strerror(errno));
			return -ENOENT;
		}
		p12 = d2i_PKCS12_fp(f, NULL);
		fclose(f);
		if (p12)
			return load_pkcs12_certificate(vpninfo, certinfo, oci, p12);

		/* Not PKCS#12. Clear error and fall through to see if it's a PEM file... */
		ERR_clear_error();
	}

	/* It's PEM or TPM now, and either way we need to load the plain cert: */
#ifdef ANDROID_KEYSTORE
	if (!strncmp(certinfo->cert, "keystore:", 9)) {
		BIO *b = BIO_from_keystore(vpninfo, certinfo->cert);
		if (!b)
			return -EINVAL;
		oci->cert = PEM_read_bio_X509_AUX(b, NULL, pem_pw_cb, certinfo);
		BIO_free(b);
		if (!oci->cert) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to load X509 certificate from keystore\n"));
			openconnect_report_ssl_errors(vpninfo);
			return -EINVAL;
		}
	} else
#endif /* ANDROID_KEYSTORE */
	{
		int ret = load_cert_chain_file(vpninfo, certinfo, oci);
		if (ret)
			return ret;
	}

 got_cert:
#ifdef ANDROID_KEYSTORE
	if (!strncmp(certinfo->key, "keystore:", 9)) {
		BIO *b;

	again_android:
		b = BIO_from_keystore(vpninfo, certinfo->key);
		if (!b)
			return -EINVAL;
		oci->key = PEM_read_bio_PrivateKey(b, NULL, pem_pw_cb, certinfo);
		BIO_free(b);
		if (!oci->key) {
			if (is_pem_password_error(vpninfo, certinfo))
				goto again_android;
			return -EINVAL;
		}
		return 0;
	}
#endif /* ANDROID_KEYSTORE */
	if (!strncmp(certinfo->key, "pkcs11:", 7))
		return load_pkcs11_key(vpninfo, certinfo, &oci->key);

	f = openconnect_fopen_utf8(vpninfo, certinfo->key, "rb");
	if (!f) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open private key file %s: %s\n"),
			     certinfo->key, strerror(errno));
		return -ENOENT;
	}

	buf[255] = 0;
	while (fgets(buf, 255, f)) {
		if (!strcmp(buf, "-----BEGIN TSS KEY BLOB-----\n")) {
			fclose(f);
			return load_tpm_certificate(vpninfo, certinfo, oci, "tpm");
		} else if (!strcmp(buf, "-----BEGIN TSS2 KEY BLOB-----\n") ||
			   !strcmp(buf, "-----BEGIN TSS2 PRIVATE KEY-----\n")) {
			fclose(f);
			return load_tpm_certificate(vpninfo, certinfo, oci, "tpm2");
		} else if (!strcmp(buf, "-----BEGIN RSA PRIVATE KEY-----\n") ||
			   !strcmp(buf, "-----BEGIN DSA PRIVATE KEY-----\n") ||
			   !strcmp(buf, "-----BEGIN EC PRIVATE KEY-----\n") ||
			   !strcmp(buf, "-----BEGIN ENCRYPTED PRIVATE KEY-----\n") ||
			   !strcmp(buf, "-----BEGIN PRIVATE KEY-----\n")) {
			BIO *b = BIO_new_fp(f, BIO_CLOSE);

			if (!b) {
				fclose(f);
				vpn_progress(vpninfo, PRG_ERR,
					     certinfo_string(certinfo, _("Loading private key failed\n"),
							     _("Loading secondary private key failed\n")));
				openconnect_report_ssl_errors(vpninfo);
				return -EINVAL;
			}
		again:
			fseek(f, 0, SEEK_SET);
			oci->key = PEM_read_bio_PrivateKey(b, NULL, pem_pw_cb, certinfo);
			if (!oci->key) {
				if (is_pem_password_error(vpninfo, certinfo))
					goto again;
				BIO_free(b);
				return -EINVAL;
			}
			ret = 0;
			BIO_free(b);
			return ret;
		}
	}

	/* Not PEM? Try DER... */
	fseek(f, 0, SEEK_SET);

	/* This will catch PKCS#1 and unencrypted PKCS#8
	 * (except in OpenSSL 0.9.8 where it doesn't handle
	 * the latter but nobody cares about 0.9.8 any more. */
	oci->key = d2i_PrivateKey_fp(f, NULL);
	if (oci->key) {
		ret = 0;
		fclose(f);
		return ret;
	} else {
		/* Encrypted PKCS#8 DER */
		X509_SIG *p8;

		fseek(f, 0, SEEK_SET);
		p8 = d2i_PKCS8_fp(f, NULL);

		if (p8) {
			PKCS8_PRIV_KEY_INFO *p8inf;
			char *pass = certinfo->password;

			fclose(f);

			while (!(p8inf = PKCS8_decrypt(p8, pass ? : "", pass ? strlen(pass) : 0))) {
				unsigned long err = ERR_peek_error();

				if (ERR_GET_LIB(err) == ERR_LIB_EVP &&
#if OPENSSL_VERSION_NUMBER < 0x30000000L
				    ERR_GET_FUNC(err) == EVP_F_EVP_DECRYPTFINAL_EX &&
#endif
				    ERR_GET_REASON(err) == EVP_R_BAD_DECRYPT) {
					ERR_clear_error();

					if (pass) {
						vpn_progress(vpninfo, PRG_ERR,
							     certinfo_string(certinfo, _("Failed to decrypt PKCS#8 certificate file\n"),
									     _("Failed to decrypt secondary PKCS#8 certificate file\n")));
						free_pass(&pass);
						pass = NULL;
					}

					if (request_passphrase(vpninfo,
							       certinfo_string(certinfo, "openconnect_pkcs8",
									       "openconnect_secondary_pkcs8"),
							       &pass,
							       certinfo_string(certinfo, _("Enter PKCS#8 pass phrase:"),
									       _("Enter PKCS#8 secondary pass phrase:"))) >= 0)
						continue;
				} else {
					vpn_progress(vpninfo, PRG_ERR,
						     certinfo_string(certinfo, _("Failed to decrypt PKCS#8 certificate file\n"),
								     _("Failed to decrypt secondary PKCS#8 certificate file\n")));
					openconnect_report_ssl_errors(vpninfo);
				}

				free_pass(&pass);
				certinfo->password = NULL;

				X509_SIG_free(p8);
				return -EINVAL;
			}
			free_pass(&pass);
			certinfo->password = NULL;

			oci->key = EVP_PKCS82PKEY(p8inf);

			PKCS8_PRIV_KEY_INFO_free(p8inf);
			X509_SIG_free(p8);

			if (oci->key == NULL) {
				vpn_progress(vpninfo, PRG_ERR,
					     certinfo_string(certinfo, _("Failed to convert PKCS#8 to OpenSSL EVP_PKEY\n"),
							     _("Failed to convert secondary PKCS#8 to OpenSSL EVP_PKEY\n")));
				return -EIO;
			}
			ret = 0;
			return ret;
		}
	}

	fclose(f);
	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to identify private key type in '%s'\n"),
		     certinfo->key);
	return -EINVAL;
}

int load_certificate(struct openconnect_info *vpninfo, struct cert_info *certinfo, int flags)
{
	struct ossl_cert_info *oci;
	int ret;

	(void) flags;

	certinfo->priv_info = oci = calloc(1, sizeof(*oci));
	if (!oci) {
		ret = -ENOMEM;
		goto done;
	}
	certinfo->vpninfo = vpninfo;

	ret = xload_certificate(vpninfo, certinfo, oci);

done:
	if (ret)
		unload_certificate(certinfo, 1);

	return ret;
}

static int get_cert_fingerprint(struct openconnect_info *vpninfo,
				X509 *cert, const EVP_MD *type,
				char *buf)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int i, n;

	if (!X509_digest(cert, type, md, &n))
		return -ENOMEM;

	for (i = 0; i < n; i++)
		sprintf(&buf[i*2], "%02X", md[i]);

	return 0;
}

int get_cert_md5_fingerprint(struct openconnect_info *vpninfo,
			     void *cert, char *buf)
{
	return get_cert_fingerprint(vpninfo, cert, EVP_md5(), buf);
}

static int set_peer_cert_hash(struct openconnect_info *vpninfo)
{
	EVP_PKEY *pkey;
	BIO *bp = BIO_new(BIO_s_mem());
	BUF_MEM *keyinfo;

	/* We can't use X509_pubkey_digest() because it only hashes the
	   subjectPublicKey BIT STRING, and not the whole of the
	   SubjectPublicKeyInfo SEQUENCE. */
	pkey = X509_get_pubkey(vpninfo->peer_cert);

	if (!i2d_PUBKEY_bio(bp, pkey)) {
		EVP_PKEY_free(pkey);
		BIO_free(bp);
		return -ENOMEM;
	}
	EVP_PKEY_free(pkey);

	BIO_get_mem_ptr(bp, &keyinfo);

	openconnect_sha256(vpninfo->peer_cert_sha256_raw, keyinfo->data, keyinfo->length);
	openconnect_sha1(vpninfo->peer_cert_sha1_raw, keyinfo->data, keyinfo->length);

	BIO_free(bp);

	return 0;
}

#if OPENSSL_VERSION_NUMBER < 0x10002000L
static int match_hostname_elem(const char *hostname, int helem_len,
			       const char *match, int melem_len)
{
	if (!helem_len && !melem_len)
		return 0;

	if (!helem_len || !melem_len)
		return -1;


	if (match[0] == '*') {
		int i;

		for (i = 1 ; i <= helem_len; i++) {
			if (!match_hostname_elem(hostname + i, helem_len - i,
						 match + 1, melem_len - 1))
				return 0;
		}
		return -1;
	}

	/* From the NetBSD (5.1) man page for ctype(3):
	   Values of type char or signed char must first be cast to unsigned char,
	   to ensure that the values are within the correct range.  The result
	   should then be cast to int to avoid warnings from some compilers.
	   We do indeed get warning "array subscript has type 'char'" without
	   the casts. Ick. */
	if (toupper((int)(unsigned char)hostname[0]) ==
	    toupper((int)(unsigned char)match[0]))
		return match_hostname_elem(hostname + 1, helem_len - 1,
					   match + 1, melem_len - 1);

	return -1;
}

static int match_hostname(const char *hostname, const char *match)
{
	while (*match) {
		const char *h_dot, *m_dot;
		int helem_len, melem_len;

		h_dot = strchr(hostname, '.');
		m_dot = strchr(match, '.');

		if (h_dot && m_dot) {
			helem_len = h_dot - hostname + 1;
			melem_len = m_dot - match + 1;
		} else if (!h_dot && !m_dot) {
			helem_len = strlen(hostname);
			melem_len = strlen(match);
		} else
			return -1;


		if (match_hostname_elem(hostname, helem_len,
					match, melem_len))
			return -1;

		hostname += helem_len;
		match += melem_len;
	}
	if (*hostname)
		return -1;

	return 0;
}

/* cf. RFC2818 and RFC2459 */
static int match_cert_hostname_or_ip(struct openconnect_info *vpninfo, X509 *peer_cert,
				     char *hostname)
{
	STACK_OF(GENERAL_NAME) *altnames;
	X509_NAME *subjname;
	ASN1_STRING *subjasn1;
	char *subjstr = NULL;
	int i, altdns = 0;
	int ret;

	unsigned char ipaddr[sizeof(struct in6_addr)];
	int ipaddrlen = 0;
	if (inet_pton(AF_INET, hostname, ipaddr) > 0)
		ipaddrlen = 4;
	else if (inet_pton(AF_INET6, hostname, ipaddr) > 0)
		ipaddrlen = 16;
	else if (hostname[0] == '[' &&
		 hostname[strlen(hostname)-1] == ']') {
		char *p = &hostname[strlen(hostname)-1];
		*p = 0;
		if (inet_pton(AF_INET6, hostname + 1, ipaddr) > 0)
			ipaddrlen = 16;
		*p = ']';
	}

	altnames = X509_get_ext_d2i(peer_cert, NID_subject_alt_name,
				    NULL, NULL);
	for (i = 0; i < sk_GENERAL_NAME_num(altnames); i++) {
		const GENERAL_NAME *this = sk_GENERAL_NAME_value(altnames, i);

		if (this->type == GEN_DNS) {
			char *str;

			int len = ASN1_STRING_to_UTF8((void *)&str, this->d.ia5);
			if (len < 0)
				continue;

			altdns = 1;

			/* We don't like names with embedded NUL */
			if (strlen(str) != len)
				continue;

			if (!match_hostname(hostname, str)) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Matched DNS altname '%s'\n"),
					     str);
				GENERAL_NAMES_free(altnames);
				OPENSSL_free(str);
				return 0;
			} else {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("No match for altname '%s'\n"),
					     str);
			}
			OPENSSL_free(str);
		} else if (this->type == GEN_IPADD && ipaddrlen) {
			char host[80];
			int family;

			if (this->d.ip->length == 4) {
				family = AF_INET;
			} else if (this->d.ip->length == 16) {
				family = AF_INET6;
			} else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Certificate has GEN_IPADD altname with bogus length %d\n"),
					     this->d.ip->length);
				continue;
			}

			/* We only do this for the debug messages */
			inet_ntop(family, this->d.ip->data, host, sizeof(host));

			if (this->d.ip->length == ipaddrlen &&
			    !memcmp(ipaddr, this->d.ip->data, ipaddrlen)) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Matched %s address '%s'\n"),
					     (family == AF_INET6) ? "IPv6" : "IPv4",
					     host);
				GENERAL_NAMES_free(altnames);
				return 0;
			} else {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("No match for %s address '%s'\n"),
					     (family == AF_INET6) ? "IPv6" : "IPv4",
					     host);
			}
		} else if (this->type == GEN_URI) {
			char *str;
			char *url_proto, *url_host, *url_path, *url_host2;
			int url_port;
			int len = ASN1_STRING_to_UTF8((void *)&str, this->d.ia5);

			if (len < 0)
				continue;

			/* We don't like names with embedded NUL */
			if (strlen(str) != len)
				continue;

			if (internal_parse_url(str, &url_proto, &url_host, &url_port, &url_path, 0)) {
				OPENSSL_free(str);
				continue;
			}

			if (!url_proto || strcasecmp(url_proto, "https"))
				goto no_uri_match;

			if (url_port != vpninfo->port)
				goto no_uri_match;

			/* Leave url_host as it was so that it can be freed */
			url_host2 = url_host;
			if (ipaddrlen == 16 && hostname[0] != '[' &&
			    url_host[0] == '[' && url_host[strlen(url_host)-1] == ']') {
				/* Cope with https://[IPv6]/ when the hostname is bare IPv6 */
				url_host[strlen(url_host)-1] = 0;
				url_host2++;
			}

			if (strcasecmp(hostname, url_host2))
				goto no_uri_match;

			if (url_path) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("URI '%s' has non-empty path; ignoring\n"),
					     str);
				goto no_uri_match_silent;
			}
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Matched URI '%s'\n"),
				     str);
			free(url_proto);
			free(url_host);
			free(url_path);
			OPENSSL_free(str);
			GENERAL_NAMES_free(altnames);
			return 0;

		no_uri_match:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("No match for URI '%s'\n"),
				     str);
		no_uri_match_silent:
			free(url_proto);
			free(url_host);
			free(url_path);
			OPENSSL_free(str);
		}
	}
	GENERAL_NAMES_free(altnames);

	/* According to RFC2818, we don't use the legacy subject name if
	   there was an altname with DNS type. */
	if (altdns) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No altname in peer cert matched '%s'\n"),
			     hostname);
		return -EINVAL;
	}

	subjname = X509_get_subject_name(peer_cert);
	if (!subjname) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No subject name in peer cert!\n"));
		return -EINVAL;
	}

	/* Find the _last_ (most specific) commonName */
	i = -1;
	while (1) {
		int j = X509_NAME_get_index_by_NID(subjname, NID_commonName, i);
		if (j >= 0)
			i = j;
		else
			break;
	}

	subjasn1 = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subjname, i));

	i = ASN1_STRING_to_UTF8((void *)&subjstr, subjasn1);

	if (!subjstr || strlen(subjstr) != i) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse subject name in peer cert\n"));
		return -EINVAL;
	}
	ret = 0;

	if (match_hostname(vpninfo->hostname, subjstr)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Peer cert subject mismatch ('%s' != '%s')\n"),
			     subjstr, vpninfo->hostname);
		ret = -EINVAL;
	} else {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Matched peer certificate subject name '%s'\n"),
			     subjstr);
	}

	OPENSSL_free(subjstr);
	return ret;
}
#else
static int match_cert_hostname_or_ip(struct openconnect_info *vpninfo, X509 *peer_cert,
				     char *hostname)
{
	char *matched = NULL;

	unsigned char ipaddr[sizeof(struct in6_addr)];
	int ipaddrlen = 0;
	if (inet_pton(AF_INET, hostname, ipaddr) > 0)
		ipaddrlen = 4;
	else if (inet_pton(AF_INET6, hostname, ipaddr) > 0)
		ipaddrlen = 16;
	else if (hostname[0] == '[' &&
		 hostname[strlen(hostname)-1] == ']') {
		char *p = &hostname[strlen(hostname)-1];
		*p = 0;
		if (inet_pton(AF_INET6, hostname + 1, ipaddr) > 0)
			ipaddrlen = 16;
		*p = ']';
	}

	if (ipaddrlen && X509_check_ip(peer_cert, ipaddr, ipaddrlen, 0) == 1) {
		if (vpninfo->verbose >= PRG_DEBUG) {
			char host[80];
			int family;

			if (ipaddrlen == 4)
				family = AF_INET;
			else
				family = AF_INET6;

			/* In Windows, the 'src' argument of inet_ntop() isn't const */
			inet_ntop(family, (void *)ipaddr, host, sizeof(host));
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Matched %s address '%s'\n"),
				     (family == AF_INET6) ? "IPv6" : "IPv4",
				     host);
		}
		return 0;
	}
	if (X509_check_host(peer_cert, hostname, 0, 0, &matched) == 1) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Matched peer certificate subject name '%s'\n"),
			     matched);
		OPENSSL_free(matched);
		return 0;
	}

	/* We do it like this because these two strings are already
	 * translated in gnutls.c */
	vpn_progress(vpninfo, PRG_INFO,
		     _("Server certificate verify failed: %s\n"),
		     _("certificate does not match hostname"));

	return -EINVAL;
}
#endif /* OpenSSL < 1.0.2 */

/* Before OpenSSL 1.1 we could do this directly. And needed to. */
#ifndef SSL_CTX_get_extra_chain_certs_only
#define SSL_CTX_get_extra_chain_certs_only(ctx, st) \
	(void)(*(st) = (ctx)->extra_certs)
#endif

static void workaround_openssl_certchain_bug(struct openconnect_info *vpninfo,
					     SSL *ssl)
{
	/* OpenSSL has problems with certificate chains -- if there are
	   multiple certs with the same name, it doesn't necessarily
	   choose the _right_ one. (RT#1942)
	   Pick the right ones for ourselves and add them manually. */
	X509 *cert = SSL_get_certificate(ssl);
	X509 *cert2;
	X509_STORE *store = SSL_CTX_get_cert_store(vpninfo->https_ctx);
	X509_STORE_CTX *ctx;
	void *extra_certs;
	X509_STORE_CTX_get_issuer_fn issuer_fn;

	if (!cert || !store)
		return;

	/* If we already have 'supporting' certs, don't add them again */
	SSL_CTX_get_extra_chain_certs_only(vpninfo->https_ctx, &extra_certs);
	if (extra_certs)
		return;

	ctx = X509_STORE_CTX_new();
	if (!ctx)
		return;
	if (X509_STORE_CTX_init(ctx, store, NULL, NULL))
		goto out;

	issuer_fn = X509_STORE_CTX_get_get_issuer(ctx);

	while (issuer_fn(&cert2, ctx, cert) == 1) {
		char buf[200];
		if (cert2 == cert)
			break;
		if (X509_check_issued(cert2, cert2) == X509_V_OK)
			break;
		cert = cert2;
		X509_NAME_oneline(X509_get_subject_name(cert),
				  buf, sizeof(buf));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Extra cert from cafile: '%s'\n"), buf);
		SSL_CTX_add_extra_chain_cert(vpninfo->https_ctx, cert);
	}
 out:
	X509_STORE_CTX_free(ctx);
}

int openconnect_get_peer_cert_chain(struct openconnect_info *vpninfo,
				    struct oc_cert **chainp)
{
	struct oc_cert *chain, *p;
	X509_STORE_CTX *ctx = vpninfo->cert_list_handle;
	STACK_OF(X509) *untrusted;
	int i, cert_list_size;

	if (!ctx)
		return -EINVAL;

	untrusted = X509_STORE_CTX_get0_untrusted(ctx);
	if (!untrusted)
		return -EINVAL;

	cert_list_size = sk_X509_num(untrusted);
	if (!cert_list_size)
		return -EIO;

	p = chain = calloc(cert_list_size, sizeof(struct oc_cert));
	if (!chain)
		return -ENOMEM;

	for (i = 0; i < cert_list_size; i++, p++) {
		X509 *cert = sk_X509_value(untrusted, i);

		p->der_len = i2d_X509(cert, &p->der_data);
		if (p->der_len < 0) {
			openconnect_free_peer_cert_chain(vpninfo, chain);
			return -ENOMEM;
		}
	}

	*chainp = chain;
	return cert_list_size;
}

void openconnect_free_peer_cert_chain(struct openconnect_info *vpninfo,
				      struct oc_cert *chain)
{
	int i;

	for (i = 0; i < vpninfo->cert_list_size; i++)
		OPENSSL_free(chain[i].der_data);
	free(chain);
}

static int ssl_app_verify_callback(X509_STORE_CTX *ctx, void *arg)
{
	struct openconnect_info *vpninfo = arg;
	const char *err_string = NULL;
	X509 *cert = X509_STORE_CTX_get0_cert(ctx);
#ifdef X509_V_FLAG_PARTIAL_CHAIN
	X509_VERIFY_PARAM *param;
#endif

	if (vpninfo->peer_cert) {
		/* This is a *rehandshake*. Require that the server
		 * presents exactly the same certificate as the
		 * first time. */
		if (X509_cmp(cert, vpninfo->peer_cert)) {
			vpn_progress(vpninfo, PRG_ERR, _("Server presented different cert on rehandshake\n"));
			return 0;
		}
		vpn_progress(vpninfo, PRG_TRACE, _("Server presented identical cert on rehandshake\n"));
		return 1;
	}
	vpninfo->peer_cert = cert;
	X509_up_ref(cert);

	set_peer_cert_hash(vpninfo);

#ifdef X509_V_FLAG_PARTIAL_CHAIN
	param = X509_STORE_CTX_get0_param(ctx);
	if (param)
		X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN);
#endif
	if (!X509_verify_cert(ctx)) {
		err_string = X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
	} else {
		if (vpninfo->sni && vpninfo->sni[0]) {
			if (match_cert_hostname_or_ip(vpninfo, vpninfo->peer_cert, vpninfo->sni))
				err_string = _("certificate does not match SNI");
			else
				return 1;
		} else if (match_cert_hostname_or_ip(vpninfo, vpninfo->peer_cert, vpninfo->hostname))
			err_string = _("certificate does not match hostname");
		else
			return 1;
	}

	vpn_progress(vpninfo, PRG_INFO,
		     _("Server certificate verify failed: %s\n"),
		     err_string);

	if (vpninfo->validate_peer_cert) {
		int ret;

		vpninfo->cert_list_handle = ctx;
		ret = vpninfo->validate_peer_cert(vpninfo->cbdata, err_string);
		vpninfo->cert_list_handle = NULL;

		if (!ret)
			return 1;
	}

	return 0;
}

static int check_certificate_expiry(struct openconnect_info *vpninfo, struct cert_info *certinfo,
				    struct ossl_cert_info *oci)
{
	const ASN1_TIME *notAfter;
	const char *reason = NULL;
	time_t t;
	int i;

	if (!oci->cert)
		return 0;

	t = time(NULL);
	notAfter = X509_get0_notAfter(oci->cert);
	i = X509_cmp_time(notAfter, &t);
	if (!i) {
		vpn_progress(vpninfo, PRG_ERR,
			     certinfo_string(certinfo, _("Error in client cert notAfter field\n"),
					     _("Error in secondary client cert notAfter field\n")));
		return -EINVAL;
	} else if (i < 0) {
		reason = certinfo_string(certinfo, _("Client certificate has expired at"),
					 _("Secondary client certificate has expired at"));
	} else {
		t += vpninfo->cert_expire_warning;
		i = X509_cmp_time(notAfter, &t);
		if (i < 0)
			reason = certinfo_string(certinfo, _("Client certificate expires soon at"),
						 _("Secondary client certificate expires soon at"));
	}
	if (reason) {
		BIO *bp = BIO_new(BIO_s_mem());
		BUF_MEM *bm;
		const char *expiry = _("<error>");
		char zero = 0;

		if (bp) {
			ASN1_TIME_print(bp, notAfter);
			BIO_write(bp, &zero, 1);
			BIO_get_mem_ptr(bp, &bm);
			expiry = bm->data;
		}
		vpn_progress(vpninfo, PRG_ERR, "%s: %s\n", reason, expiry);
		if (bp)
			BIO_free(bp);
	}
	return 0;
}

static int load_primary_certificate(struct openconnect_info *vpninfo)
{
	struct cert_info *certinfo = &vpninfo->certinfo[0];
	struct ossl_cert_info *oci;

	int ret = load_certificate(vpninfo, certinfo, 0);
	oci = certinfo->priv_info;
	if (!ret)
		ret = install_ssl_ctx_certs(vpninfo, oci);

	if (!ret && !SSL_CTX_check_private_key(vpninfo->https_ctx)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("SSL certificate and key do not match\n"));
		ret = -EINVAL;
	}
	if (!ret)
		check_certificate_expiry(vpninfo, &vpninfo->certinfo[0], oci);

	unload_certificate(certinfo, 1);
	return ret;
}

int openconnect_install_ctx_verify(struct openconnect_info *vpninfo, SSL_CTX *ctx)
{
	/* We've seen certificates in the wild which don't have the
	   purpose fields filled in correctly */
	SSL_CTX_set_purpose(ctx, X509_PURPOSE_ANY);
	SSL_CTX_set_cert_verify_callback(ctx, ssl_app_verify_callback,
					 vpninfo);

	if (!vpninfo->no_system_trust)
		SSL_CTX_set_default_verify_paths(ctx);

#ifdef ANDROID_KEYSTORE
	if (vpninfo->cafile && !strncmp(vpninfo->cafile, "keystore:", 9)) {
		STACK_OF(X509_INFO) *stack;
		X509_STORE *store;
		X509_INFO *info;
		BIO *b = BIO_from_keystore(vpninfo, vpninfo->cafile);

		if (!b)
			return -EINVAL;

		stack = PEM_X509_INFO_read_bio(b, NULL, NULL, NULL);
		BIO_free(b);

		if (!stack) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to read certs from CA file '%s'\n"),
				     vpninfo->cafile);
			openconnect_report_ssl_errors(vpninfo);
			return -ENOENT;
		}

		store = SSL_CTX_get_cert_store(ctx);

		while ((info = sk_X509_INFO_pop(stack))) {
			if (info->x509)
				X509_STORE_add_cert(store, info->x509);
			if (info->crl)
				X509_STORE_add_crl(store, info->crl);
			X509_INFO_free(info);
		}
		sk_X509_INFO_free(stack);
	} else
#endif
	if (vpninfo->cafile) {
		/* OpenSSL does actually manage to cope with UTF-8 for
		   this one, under Windows. So only convert for legacy
		   UNIX. */
		char *cafile = openconnect_utf8_to_legacy(vpninfo,
							  vpninfo->cafile);
		int err = SSL_CTX_load_verify_locations(ctx, cafile, NULL);

		if (cafile != vpninfo->cafile)
			free(cafile);
		if (!err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to open CA file '%s'\n"),
				     vpninfo->cafile);
			openconnect_report_ssl_errors(vpninfo);
			return -EINVAL;
		}
	}

	return 0;
}

int openconnect_open_https(struct openconnect_info *vpninfo)
{
	SSL *https_ssl;
	BIO *https_bio;
	int ssl_sock;
	int err;

	if (vpninfo->https_ssl)
		return 0;

	if (vpninfo->peer_cert) {
		X509_free(vpninfo->peer_cert);
		vpninfo->peer_cert = NULL;
	}
	free(vpninfo->peer_cert_hash);
	vpninfo->peer_cert_hash = NULL;
	free(vpninfo->cstp_cipher);
	vpninfo->cstp_cipher = NULL;

	ssl_sock = connect_https_socket(vpninfo);
	if (ssl_sock < 0)
		return ssl_sock;

	if (!vpninfo->https_ctx) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		vpninfo->https_ctx = SSL_CTX_new(SSLv23_client_method());
		if (vpninfo->https_ctx)
			SSL_CTX_set_options(vpninfo->https_ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
#else
		vpninfo->https_ctx = SSL_CTX_new(TLS_client_method());
		if (vpninfo->https_ctx &&
		    !SSL_CTX_set_min_proto_version(vpninfo->https_ctx, TLS1_VERSION)) {
			SSL_CTX_free(vpninfo->https_ctx);
			vpninfo->https_ctx = NULL;
		}
#endif
		if (!vpninfo->https_ctx) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Create TLSv1 CTX failed\n"));
			openconnect_report_ssl_errors(vpninfo);
			return -EINVAL;
		}

		/* Try to work around the broken firewalls which reject ClientHello
		 * packets in certain size ranges. If we have SSL_OP_TLSEXT_PADDING
		 * use it, else fall back to SSL_OP_NO_TICKET which mostly worked for
		 * a long time. */
#if defined(SSL_OP_TLSEXT_PADDING)
		SSL_CTX_set_options(vpninfo->https_ctx, SSL_OP_TLSEXT_PADDING);
#elif defined(SSL_OP_NO_TICKET)
		SSL_CTX_set_options(vpninfo->https_ctx, SSL_OP_NO_TICKET);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x010100000L
		if (vpninfo->allow_insecure_crypto) {
			/* OpenSSL versions after 1.1.0 added the notion of a "security level"
			 * that enforces checks on certificates and ciphers.
			 * These security levels overlap in functionality with the ciphersuite
			 * priority/allow-strings.
			 *
			 * For now we will set the security level to 0, thus reverting
			 * to the functionality seen in versions before 1.1.0. */
			SSL_CTX_set_security_level(vpninfo->https_ctx, 0);

			/* OpenSSL 3.0.0 refuses legacy renegotiation by default.
			 * Current versions of the Cisco ASA doesn't seem to cope */
			SSL_CTX_set_options(vpninfo->https_ctx, SSL_OP_LEGACY_SERVER_CONNECT);
		}
#endif

		if (vpninfo->certinfo[0].cert) {
			err = load_primary_certificate(vpninfo);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Loading certificate failed. Aborting.\n"));
				SSL_CTX_free(vpninfo->https_ctx);
				vpninfo->https_ctx = NULL;
				closesocket(ssl_sock);
				return err;
			}
		}

		if (!vpninfo->ciphersuite_config) {
			struct oc_text_buf *buf = buf_alloc();
			if (vpninfo->pfs)
				buf_append(buf, "HIGH:!aNULL:!eNULL:-RSA");
			else if (vpninfo->allow_insecure_crypto)
				buf_append(buf, "ALL");
			else
				buf_append(buf, "DEFAULT:-3DES:-RC4");

			if (buf_error(buf)) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to construct OpenSSL cipher list\n"));
				return buf_free(buf);
			}

			vpninfo->ciphersuite_config = buf->data;
			buf->data = NULL;
			buf_free(buf);
		}

		if (!SSL_CTX_set_cipher_list(vpninfo->https_ctx, vpninfo->ciphersuite_config)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to set OpenSSL cipher list (\"%s\")\n"),
				     vpninfo->ciphersuite_config);
			openconnect_report_ssl_errors(vpninfo);
			SSL_CTX_free(vpninfo->https_ctx);
			vpninfo->https_ctx = NULL;
			closesocket(ssl_sock);
			return -EIO;
		}

		err = openconnect_install_ctx_verify(vpninfo, vpninfo->https_ctx);
		if (err) {
			SSL_CTX_free(vpninfo->https_ctx);
			vpninfo->https_ctx = NULL;
			closesocket(ssl_sock);
			return err;
		}
	}
	https_ssl = SSL_new(vpninfo->https_ctx);
	workaround_openssl_certchain_bug(vpninfo, https_ssl);

	https_bio = BIO_new_socket(ssl_sock, BIO_NOCLOSE);
	BIO_set_nbio(https_bio, 1);
	SSL_set_bio(https_ssl, https_bio, https_bio);
	/*
	 * If a ClientHello is between 256 and 511 bytes, the
	 * server cannot distinguish between a SSLv2 formatted
	 * packet and a SSLv3 formatted packet.
	 *
	 * F5 BIG-IP reverse proxies in particular will
	 * silently drop an ambiguous ClientHello.
	 *
	 * OpenSSL fixes this in v1.0.1g+ by padding ClientHello
	 * packets to at least 512 bytes.
	 *
	 * For older versions of OpenSSL, we try to avoid long
	 * packets by silently disabling extensions such as SNI.
	 *
	 * Discussion:
	 * https://www.ietf.org/mail-archive/web/tls/current/msg10423.html
	 *
	 * OpenSSL commits:
	 * 4fcdd66fff5fea0cfa1055c6680a76a4303f28a2
	 * cd6bd5ffda616822b52104fee0c4c7d623fd4f53
	 */
#if OPENSSL_VERSION_NUMBER >= 0x10001070L
	if (vpninfo->sni)
		SSL_set_tlsext_host_name(https_ssl, vpninfo->sni);
	else if (string_is_hostname(vpninfo->hostname))
		SSL_set_tlsext_host_name(https_ssl, vpninfo->hostname);
#endif
	SSL_set_verify(https_ssl, SSL_VERIFY_PEER, NULL);

	vpn_progress(vpninfo, PRG_INFO, _("SSL negotiation with %s\n"),
		     vpninfo->hostname);

	while ((err = SSL_connect(https_ssl)) <= 0) {
		fd_set wr_set, rd_set;
		int maxfd = ssl_sock;

		FD_ZERO(&wr_set);
		FD_ZERO(&rd_set);

		err = SSL_get_error(https_ssl, err);
		if (err == SSL_ERROR_WANT_READ)
			FD_SET(ssl_sock, &rd_set);
		else if (err == SSL_ERROR_WANT_WRITE)
			FD_SET(ssl_sock, &wr_set);
		else {
			vpn_progress(vpninfo, PRG_ERR, _("SSL connection failure\n"));
			openconnect_report_ssl_errors(vpninfo);
			SSL_free(https_ssl);
			closesocket(ssl_sock);
			return -EINVAL;
		}

		cmd_fd_set(vpninfo, &rd_set, &maxfd);
		select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
		if (is_cancel_pending(vpninfo, &rd_set)) {
			vpn_progress(vpninfo, PRG_ERR, _("SSL connection cancelled\n"));
			SSL_free(https_ssl);
			closesocket(ssl_sock);
			return -EINVAL;
		}
	}

	if (asprintf(&vpninfo->cstp_cipher, "%s-%s",
		     SSL_get_version(https_ssl), SSL_get_cipher_name(https_ssl)) < 0) {
		SSL_free(https_ssl);
		closesocket(ssl_sock);
		return -ENOMEM;
	}

	vpninfo->ssl_fd = ssl_sock;
	vpninfo->https_ssl = https_ssl;

	vpninfo->ssl_read = openconnect_openssl_read;
	vpninfo->ssl_write = openconnect_openssl_write;
	vpninfo->ssl_gets = openconnect_openssl_gets;


	vpn_progress(vpninfo, PRG_INFO, _("Connected to HTTPS on %s with ciphersuite %s\n"),
		     vpninfo->hostname, vpninfo->cstp_cipher);

	return 0;
}

int cstp_handshake(struct openconnect_info *vpninfo, unsigned init)
{
	return -EOPNOTSUPP;
}

void openconnect_close_https(struct openconnect_info *vpninfo, int final)
{
	if (vpninfo->https_ssl) {
		SSL_free(vpninfo->https_ssl);
		vpninfo->https_ssl = NULL;
	}
	if (vpninfo->ssl_fd != -1) {
		unmonitor_fd(vpninfo, ssl);
		closesocket(vpninfo->ssl_fd);
		vpninfo->ssl_fd = -1;
	}
	if (final) {
		if (vpninfo->https_ctx) {
			SSL_CTX_free(vpninfo->https_ctx);
			vpninfo->https_ctx = NULL;
		}
		if (vpninfo->cert_x509) {
			X509_free(vpninfo->cert_x509);
			vpninfo->cert_x509 = NULL;
		}
	}
}

int openconnect_init_ssl(void)
{
#ifdef _WIN32
	int ret = openconnect__win32_sock_init();
	if (ret)
		return ret;
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_library_init();
	ERR_clear_error();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#endif
	return 0;
}

char *openconnect_get_peer_cert_details(struct openconnect_info *vpninfo)
{
	BIO *bp = BIO_new(BIO_s_mem());
	BUF_MEM *certinfo;
	char zero = 0;
	char *ret;

	X509_print_ex(bp, vpninfo->peer_cert, 0, 0);
	BIO_write(bp, &zero, 1);
	BIO_get_mem_ptr(bp, &certinfo);

	ret = strdup(certinfo->data);
	BIO_free(bp);
	return ret;
}

void openconnect_free_cert_info(struct openconnect_info *vpninfo,
				void *buf)
{
	free(buf);
}

int openconnect_local_cert_md5(struct openconnect_info *vpninfo,
			       char *buf)
{
	buf[0] = 0;

	if (!vpninfo->cert_x509)
		return -EIO;

	if (get_cert_md5_fingerprint(vpninfo, vpninfo->cert_x509, buf))
		return -EIO;

	return 0;
}

#ifdef HAVE_LIBPCSCLITE
int openconnect_hash_yubikey_password(struct openconnect_info *vpninfo,
				      const char *password, int pwlen,
				      const void *ident, int id_len)
{
	if (!PKCS5_PBKDF2_HMAC_SHA1(password, pwlen, ident, id_len, 1000, 16,
				    vpninfo->yubikey_pwhash))
		return -EIO;

	return 0;
}

int openconnect_yubikey_chalresp(struct openconnect_info *vpninfo,
				  const void *challenge, int chall_len, void *result)
{
	unsigned int mdlen = SHA1_SIZE;

	if (!HMAC(EVP_sha1(), vpninfo->yubikey_pwhash, 16, challenge, chall_len, result, &mdlen))
		return -EIO;

	return 0;
}
#endif

int hotp_hmac(struct openconnect_info *vpninfo, const void *challenge)
{
	unsigned char hash[64]; /* Enough for a SHA256 */
	unsigned int hashlen = sizeof(hash);
	const EVP_MD *alg;

	switch (vpninfo->oath_hmac_alg) {
	case OATH_ALG_HMAC_SHA1:
		alg = EVP_sha1();
		break;
	case OATH_ALG_HMAC_SHA256:
		alg = EVP_sha256();
		break;
	case OATH_ALG_HMAC_SHA512:
		alg = EVP_sha512();
		break;
	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unsupported OATH HMAC algorithm\n"));
		return -EINVAL;
	}
	if (!HMAC(alg, vpninfo->oath_secret, vpninfo->oath_secret_len,
		  challenge, 8, hash, &hashlen)) {
		vpninfo->progress(vpninfo, PRG_ERR,
				  _("Failed to calculate OATH HMAC\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	hashlen = hash[hashlen - 1] & 15;
	return load_be32(&hash[hashlen]) & 0x7fffffff;
}

static long ttls_ctrl_func(BIO *b, int cmd, long larg, void *iarg);
static int ttls_pull_func(BIO *b, char *buf, int len);
static int ttls_push_func(BIO *b, const char *buf, int len);

#ifdef HAVE_BIO_METH_FREE
static BIO_METHOD *eap_ttls_method(void)
{
	BIO_METHOD *meth = BIO_meth_new(BIO_get_new_index(), "EAP-TTLS");

	BIO_meth_set_write(meth, ttls_push_func);
	BIO_meth_set_read(meth, ttls_pull_func);
	BIO_meth_set_ctrl(meth, ttls_ctrl_func);
	return meth;
}
#else /* !HAVE_BIO_METH_FREE */
#define BIO_TYPE_EAP_TTLS 0x80

static BIO_METHOD ttls_bio_meth = {
	.type = BIO_TYPE_EAP_TTLS,
	.name = "EAP-TTLS",
	.bwrite = ttls_push_func,
	.bread = ttls_pull_func,
	.ctrl = ttls_ctrl_func,
};
static BIO_METHOD *eap_ttls_method(void)
{
	return &ttls_bio_meth;
}

static inline void BIO_set_data(BIO *b, void *p)
{
	b->ptr = p;
}

static inline void *BIO_get_data(BIO *b)
{
	return b->ptr;
}

static void BIO_set_init(BIO *b, int i)
{
	b->init = i;
}
#endif /* !HAVE_BIO_METH_FREE */

static int ttls_push_func(BIO *b, const char *buf, int len)
{
	struct openconnect_info *vpninfo = BIO_get_data(b);
	int ret = pulse_eap_ttls_send(vpninfo, buf, len);
	if (ret >= 0)
		return ret;

	return 0;
}

static int ttls_pull_func(BIO *b, char *buf, int len)
{
	struct openconnect_info *vpninfo = BIO_get_data(b);
	int ret = pulse_eap_ttls_recv(vpninfo, buf, len);
	if (ret >= 0)
		return ret;

	return 0;
}

static long ttls_ctrl_func(BIO *b, int cmd, long larg, void *iarg)
{
	switch (cmd) {
	case BIO_CTRL_FLUSH:
		return 1;
	default:
		return 0;
	}
}

void *establish_eap_ttls(struct openconnect_info *vpninfo)
{
	SSL *ttls_ssl = NULL;
	BIO *bio;
	int err;

	if (!vpninfo->ttls_bio_meth)
		vpninfo->ttls_bio_meth = eap_ttls_method();

	bio = BIO_new(vpninfo->ttls_bio_meth);
	BIO_set_data(bio, vpninfo);
	BIO_set_init(bio, 1);
	ttls_ssl = SSL_new(vpninfo->https_ctx);
	workaround_openssl_certchain_bug(vpninfo, ttls_ssl);

	SSL_set_bio(ttls_ssl, bio, bio);

	SSL_set_verify(ttls_ssl, SSL_VERIFY_PEER, NULL);

	vpn_progress(vpninfo, PRG_INFO, _("EAP-TTLS negotiation with %s\n"),
		     vpninfo->hostname);

	err = SSL_connect(ttls_ssl);
	if (err == 1) {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Established EAP-TTLS session\n"));
		return ttls_ssl;
	}

	err = SSL_get_error(ttls_ssl, err);
	vpn_progress(vpninfo, PRG_ERR, _("EAP-TTLS connection failure %d\n"), err);
	openconnect_report_ssl_errors(vpninfo);
	SSL_free(ttls_ssl);
	return NULL;
}

void destroy_eap_ttls(struct openconnect_info *vpninfo, void *ttls)
{
	SSL_free(ttls);
	/* Leave the BIO_METH for now. It may get reused and we don't want to
	 * have to call BIO_get_new_index() more times than is necessary */
}

#ifdef HAVE_HPKE_SUPPORT
static int generate_strap_key(EC_KEY **key, char **pubkey,
			      unsigned char *privder_in, int privderlen,
			      unsigned char **pubder, int *pubderlen)
{
	EC_KEY *lkey;
	struct oc_text_buf *buf = NULL;
	unsigned char *der = NULL;
	int len;

	if (privder_in) {
		lkey = d2i_ECPrivateKey(NULL, (const unsigned char **)&privder_in, privderlen);
		if (!lkey)
			return -EIO;
	} else {
		lkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		if (!lkey)
			return -EIO;

		if (!EC_KEY_generate_key(lkey)) {
			EC_KEY_free(lkey);
			return -EIO;
		}
	}

	len = i2d_EC_PUBKEY(lkey, &der);
	buf = buf_alloc();
	buf_append_base64(buf, der, len, 0);
	if (buf_error(buf)) {
		EC_KEY_free(lkey);
		free(der);
		return buf_free(buf);
	}

	/* All done. There are no failure modes from here on, so
	 * install the resulting key/pubkey/etc. where the caller
	 * asked us to, freeing the previous ones if needed. */
	EC_KEY_free(*key);
	*key = lkey;

	free(*pubkey);
	*pubkey = buf->data;

	/* If the caller wants the DER, give it to them */
	if (pubder && pubderlen) {
		*pubder = der;
		*pubderlen = len;
	} else {
		free(der);
	}

	buf->data = NULL;
	buf_free(buf);
	return 0;
}

int generate_strap_keys(struct openconnect_info *vpninfo)
{
	int err;

	err = generate_strap_key(&vpninfo->strap_key, &vpninfo->strap_pubkey,
				 NULL, 0, NULL, NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to generate STRAP key"));
		openconnect_report_ssl_errors(vpninfo);
		free_strap_keys(vpninfo);
		return -EIO;
	}

	err = generate_strap_key(&vpninfo->strap_dh_key, &vpninfo->strap_dh_pubkey,
				 NULL, 0, NULL, NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to generate STRAP DH key\n"));
		openconnect_report_ssl_errors(vpninfo);
		free_strap_keys(vpninfo);
		return -EIO;
	}
	return 0;
}

void free_strap_keys(struct openconnect_info *vpninfo)
{
	if (vpninfo->strap_key)
		EC_KEY_free(vpninfo->strap_key);
	if (vpninfo->strap_dh_key)
		EC_KEY_free(vpninfo->strap_dh_key);

	vpninfo->strap_key = vpninfo->strap_dh_key = NULL;
}

int ingest_strap_privkey(struct openconnect_info *vpninfo, unsigned char *der, int len)
{
	if (generate_strap_key(&vpninfo->strap_key,
			       &vpninfo->strap_pubkey, der, len, NULL, 0)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to decode STRAP key\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EIO;
	}
	return 0;
}

void append_strap_privkey(struct openconnect_info *vpninfo,
			  struct oc_text_buf *buf)
{
	unsigned char *der = NULL;
	int derlen = i2d_ECPrivateKey(vpninfo->strap_key, &der);
	if (derlen > 0)
		buf_append_base64(buf, der, derlen, 0);
}

#include <openssl/kdf.h>

int ecdh_compute_secp256r1(struct openconnect_info *vpninfo, const unsigned char *pubkey,
			   int pubkey_len, unsigned char *secret)
{
	const EC_POINT *point;
	EC_KEY *pkey;
	int ret = 0;

	if (!(pkey = d2i_EC_PUBKEY(NULL, &pubkey, pubkey_len)) ||
	    !(point = EC_KEY_get0_public_key(pkey))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to decode server DH key\n"));
		openconnect_report_ssl_errors(vpninfo);
		ret = -EIO;
		goto out;

	}

	/* Perform the DH secret derivation from our STRAP-DH key
	 * and the one the server returned to us in the payload. */
	if (ECDH_compute_key(secret, 32, point, vpninfo->strap_dh_key, NULL) <= 0) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to compute DH secret\n"));
		openconnect_report_ssl_errors(vpninfo);
		ret = -EIO;
	}
 out:
	EC_KEY_free(pkey);
	return ret;
}

int hkdf_sha256_extract_expand(struct openconnect_info *vpninfo, unsigned char *buf,
			       const unsigned char *info, int infolen)
{
	size_t buflen = 32;
	int ret = 0;

	/* Next, use HKDF to generate the actual key used for encryption. */
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ctx || !EVP_PKEY_derive_init(ctx) ||
	    !EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) ||
	    !EVP_PKEY_CTX_set1_hkdf_key(ctx, buf, buflen) ||
	    !EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) ||
	    !EVP_PKEY_CTX_add1_hkdf_info(ctx, info, infolen) ||
	    EVP_PKEY_derive(ctx, buf, &buflen) != 1) {
		vpn_progress(vpninfo, PRG_ERR, _("HKDF key derivation failed\n"));
		openconnect_report_ssl_errors(vpninfo);
		ret = -EINVAL;
	}
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

int aes_256_gcm_decrypt(struct openconnect_info *vpninfo, unsigned char *key,
			unsigned char *data, int len,
			unsigned char *iv, unsigned char *tag)
{
	/* Finally, we actually decrypt the sso-token */
	EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
	int ret = 0, i = 0;

	if (!cctx ||
	    !EVP_DecryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, key, iv) ||
	    !EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, 12, tag) ||
	    !EVP_DecryptUpdate(cctx, data, &len, data, len) ||
	    !EVP_DecryptFinal(cctx, NULL, &i)) {
		vpn_progress(vpninfo, PRG_ERR, _("SSO token decryption failed\n"));
		openconnect_report_ssl_errors(vpninfo);
		ret = -EINVAL;
	}
	EVP_CIPHER_CTX_free(cctx);
	return ret;
}

void append_strap_verify(struct openconnect_info *vpninfo,
			 struct oc_text_buf *buf, int rekey)
{
	unsigned char finished[64];
	size_t flen;

	if (SSL_SESSION_get_protocol_version(SSL_get_session(vpninfo->https_ssl)) <= TLS1_2_VERSION) {
		/* For TLSv1.2 and earlier, use RFC5929 'tls-unique' channel binding */
		flen = SSL_get_finished(vpninfo->https_ssl, finished, sizeof(finished));
		if (flen > sizeof(finished)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL Finished message too large (%zu bytes)\n"), flen);
			if (!buf_error(buf))
				buf->error = -EIO;
			return;
		}
	} else {
		/* For TLSv1.3 use RFC9266 'tls-exporter' channel binding */
		if (!SSL_export_keying_material(vpninfo->https_ssl,
						finished, TLS_EXPORTER_KEY_SIZE,
						TLS_EXPORTER_LABEL, TLS_EXPORTER_LABEL_SIZE,
						NULL, 0, 0)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to generate channel bindings for STRAP key\n"));
			openconnect_report_ssl_errors(vpninfo);
			return;
		}
		flen = TLS_EXPORTER_KEY_SIZE;
	}

	/* If we're rekeying, we need to sign the Verify header with the *old* key. */
	EVP_PKEY *evpkey = EVP_PKEY_new();
	if (!evpkey || EVP_PKEY_set1_EC_KEY(evpkey, vpninfo->strap_key) <= 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("STRAP signature failed\n"));
	fail_errors:
		openconnect_report_ssl_errors(vpninfo);
	fail_pkey:
		if (!buf_error(buf))
			buf->error = -EIO;
		EVP_PKEY_free(evpkey);
		return;
	}

	unsigned char *pubkey_der = NULL;
	int pubkey_derlen = 0;
	if (rekey) {
		if (generate_strap_key(&vpninfo->strap_key, &vpninfo->strap_pubkey,
				       NULL, 0, &pubkey_der, &pubkey_derlen)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to regenerate STRAP key\n"));
			goto fail_errors;
		}
	} else {
		pubkey_der = openconnect_base64_decode(&pubkey_derlen, vpninfo->strap_pubkey);
		if (!pubkey_der) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to generate STRAP key DER\n"));
			goto fail_pkey;
		}
	}

	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_sha256(); /* We only support prime256v1 for now */

	unsigned char signature_bin[128];
	size_t siglen = sizeof(signature_bin);
	int ok = (mdctx &&
		  EVP_DigestSignInit(mdctx, NULL, md, NULL, evpkey) > 0 &&
		  EVP_DigestSignUpdate(mdctx, finished, flen) > 0 &&
		  EVP_DigestSignUpdate(mdctx, pubkey_der, pubkey_derlen) > 0 &&
		  EVP_DigestSignFinal(mdctx, (void *)signature_bin, &siglen) > 0);

	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(evpkey);
	free(pubkey_der);

	if (!ok) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("STRAP signature failed\n"));
		goto fail_errors;
	}

	buf_append_base64(buf, signature_bin, siglen, 0);
}
#endif /* HAVE_HPKE_SUPPORT */

int export_certificate_pkcs7(struct openconnect_info *vpninfo,
			     struct cert_info *certinfo,
			     cert_format_t format,
			     struct oc_text_buf **pp7b)
{
	struct ossl_cert_info *oci;
	PKCS7 *p7 = NULL;
	BIO *bio = NULL;
	BUF_MEM *bptr = NULL;
	struct oc_text_buf *p7b = NULL;
	int ret, ok;

	if (!(certinfo && (oci = certinfo->priv_info) && pp7b))
		return -EINVAL;

	/* We have the client certificate in 'oci.cert' and *optionally*
	 * a stack of intermediate certs in oci.extra_certs. For the TLS
	 * connection those would be used by SSL_CTX_use_certificate() and
	 * SSL_CTX_add_extra_chain_cert() respectively. For PKCS7_sign()
	 * we need the actual cert at the head of the stack, so *create*
	 * one if needed, and insert oci.cert at position zero. */

	if (!oci->extra_certs)
		oci->extra_certs = sk_X509_new_null();
	if (!oci->extra_certs)
		goto err;
	if (!sk_X509_insert(oci->extra_certs, oci->cert, 0))
		goto err;
	X509_up_ref(oci->cert);

	bio = BIO_new(BIO_s_mem());
	if (!bio) {
		ret = -ENOMEM;
		goto pkcs7_error;
	}

	p7 = PKCS7_sign(NULL, NULL, oci->extra_certs, bio, PKCS7_DETACHED);
	if (!p7) {
	err:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to create PKCS#7 structure\n"));
		ret = -EIO;
		goto out;
	}

	ret = 0;

	if (format == CERT_FORMAT_ASN1) {
		ok = i2d_PKCS7_bio(bio, p7);
	} else if (format == CERT_FORMAT_PEM) {
		ok = PEM_write_bio_PKCS7(bio, p7);
	} else {
		ret = -EINVAL;
		goto pkcs7_error;
	}

	if (!ok) {
		ret = -EIO;
		goto pkcs7_error;
	}

	BIO_get_mem_ptr(bio, &bptr);

	p7b = buf_alloc();
	if (!p7b)
		ret = -ENOMEM;

	if (ret < 0) {
pkcs7_error:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to output PKCS#7 structure\n"));
		goto out;
	}

	BIO_set_close(bio, BIO_NOCLOSE);

	p7b->data = bptr->data;
	p7b->pos = bptr->length;

	*pp7b = p7b;
	p7b = NULL;

out:
	buf_free(p7b);
	BIO_free(bio);
	if (p7)
		PKCS7_free(p7);
	return ret;
}

int multicert_sign_data(struct openconnect_info *vpninfo,
			struct cert_info *certinfo,
			unsigned int hashes,
			const void *chdata, size_t chdata_len,
			struct oc_text_buf **psignature)
{
	struct table_entry {
		openconnect_hash_type id;
		const EVP_MD *(*evp_md_fn)(void);
	};
	static struct table_entry table[] = {
		{ OPENCONNECT_HASH_SHA512, &EVP_sha512 },
		{ OPENCONNECT_HASH_SHA384, &EVP_sha384 },
		{ OPENCONNECT_HASH_SHA256, &EVP_sha256 },
		{ OPENCONNECT_HASH_UNKNOWN },
	};
	struct ossl_cert_info *oci;
	struct oc_text_buf *signature;
	openconnect_hash_type hash;
	int ret;

	/**
	 * Check preconditions...
	 */
	if (!(certinfo && (oci = certinfo->priv_info)
	      && hashes && chdata && chdata_len && psignature))
		return -EINVAL;

	*psignature = NULL;

	signature = buf_alloc();
	if (!signature)
		goto out_of_memory;

	for (const struct table_entry *entry = table;
	     (hash = entry->id) != OPENCONNECT_HASH_UNKNOWN;
	     entry++) {
		if ((hashes & MULTICERT_HASH_FLAG(hash)) == 0)
			continue;

		EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
		if (!mdctx)
			goto out_of_memory;

		const EVP_MD *md = (*entry->evp_md_fn)();

		size_t siglen = 0;
		int ok = (EVP_DigestSignInit(mdctx, NULL, md, NULL, oci->key) > 0 &&
			  EVP_DigestSignUpdate(mdctx, chdata, chdata_len) > 0 &&
			  EVP_DigestSignFinal(mdctx, NULL, &siglen) > 0 &&
			  !buf_ensure_space(signature, siglen) &&
			  EVP_DigestSignFinal(mdctx, (void *)signature->data, &siglen) > 0);

		EVP_MD_CTX_free(mdctx);

		if (ok) {
			signature->pos = siglen;
			*psignature = signature;
			return hash;
		}
	}

	/** Error path */

	ret = -EIO;

	if (buf_error(signature)) {
out_of_memory:
		ret = -ENOMEM;
	}

	buf_free(signature);

	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to generate signature for multiple certificate authentication\n"));
	openconnect_report_ssl_errors(vpninfo);

	return ret;
}

