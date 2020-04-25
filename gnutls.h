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

#ifndef __OPENCONNECT_GNUTLS_H__
#define __OPENCONNECT_GNUTLS_H__

#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>
#include <gnutls/abstract.h>

#include "openconnect-internal.h"

int load_tpm1_key(struct openconnect_info *vpninfo, gnutls_datum_t *fdata,
		  const char *password,
		  gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig);
void release_tpm1_ctx(struct openconnect_info *info);

int load_tpm2_key(struct openconnect_info *vpninfo, gnutls_datum_t *fdata,
		 gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig);
void release_tpm2_ctx(struct openconnect_info *info);
int install_tpm2_key(struct openconnect_info *vpninfo, gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig,
		     unsigned int parent, int emptyauth, int legacy,
		     gnutls_datum_t *privdata, gnutls_datum_t *pubdata);

int tpm2_rsa_sign_hash_fn(gnutls_privkey_t key, gnutls_sign_algorithm_t algo,
			  void *_vpninfo, unsigned int flags,
			  const gnutls_datum_t *data, gnutls_datum_t *sig);
int tpm2_ec_sign_hash_fn(gnutls_privkey_t key, gnutls_sign_algorithm_t algo,
			 void *_vpninfo, unsigned int flags,
			 const gnutls_datum_t *data, gnutls_datum_t *sig);
int oc_pkcs1_pad(struct openconnect_info *vpninfo,
		 unsigned char *buf, int size, const gnutls_datum_t *data);

/* GnuTLS 3.6.0+ provides this. We have our own for older GnuTLS. There is
 * also _gnutls_encode_ber_rs_raw() in some older versions, but there were
 * zero-padding bugs in that, and some of the... less diligently maintained
 * distributions (like Ubuntu even in 18.04) don't have the fix yet, two
 * years later. */
#if GNUTLS_VERSION_NUMBER < 0x030600
#define gnutls_encode_rs_value oc_gnutls_encode_rs_value
int oc_gnutls_encode_rs_value(gnutls_datum_t *sig_value, const gnutls_datum_t *r, const gnutls_datum_t *s);
#endif

char *get_gnutls_cipher(gnutls_session_t session);

/* Compile-time optimisable GnuTLS version check. We should never be
 * run against a version of GnuTLS which is *older* than the one we
 * were built again, but we might be run against a version which is
 * newer. So some ancient compatibility code *can* be dropped at
 * compile time. Likewise, if building against GnuTLS 2.x then we
 * can never be running agsinst a 3.x library — the soname changed.
 *
 * This macro was added upstream, gnutls_check_version_numeric,
 * in 3.5.0 (see https://gitlab.com/gnutls/gnutls/commit/c8b40aeb) */
#define gtls_ver(a,b,c) ( GNUTLS_VERSION_MAJOR >= (a) &&		\
	(GNUTLS_VERSION_NUMBER >= ( ((a) << 16) + ((b) << 8) + (c) ) || \
	 gnutls_check_version(#a "." #b "." #c)))
#ifndef gnutls_check_version_numeric
#define gnutls_check_version_numeric gtls_ver
#endif

/**
 * rcstring is a simple referenced counted string. This was added to
 * simplify password passing and to reduce the number of times the
 * password needs to be copied.
 */

typedef char rcstring;

struct rcstring_st {
	int refcount;
	struct {
		size_t len;
		char data[1];
	} str;
};

#define RCSTRING(p) \
	((struct rcstring_st *)((char *)(p) - offsetof(struct rcstring_st, str.    data)))

const rcstring *rcstring_new_len(const char *s, size_t n);

const rcstring *rcstring_new(const char *s);

/**
 * Acquire a reference to string
 */
static inline const char *
rcstring_acquire(const rcstring *str)
{
	if (str == NULL) return NULL;
	++RCSTRING(str)->refcount;
	return str;
}
/**
 * Release a reference to the string
 */
void rcstring_release_zero(const rcstring *str,
	void (*zero_func)(char *,size_t));

static inline void
rcstring_release(const rcstring *str)
{
	return rcstring_release_zero(str, NULL);
}
/**
 * Length of string
 */
static inline size_t
rcstring_length(const rcstring *str)
{
	if (str == NULL) return 0;
	return RCSTRING(str)->str.len;
}
/**
 * passwords are zeroed when the refcount <= 0
 */
#define password_new(s) rcstring_new(s)

#define password_acquire(s) rcstring_acquire(s)

void zero_password(char *s, size_t n);

static inline void
password_free(const rcstring **password)
{
	rcstring_release_zero(*password, zero_password);
	*password = NULL;
}
/**
 * ask_password is similar request_passphrase Instead of a
 * char **, it expects const rcstring **
 */
int __attribute__((format(printf, 4, 5)))
ask_password(struct openconnect_info *, const char *label,
	const rcstring **password, const char *fmt, ...);

#endif /* __OPENCONNECT_GNUTLS_H__ */
