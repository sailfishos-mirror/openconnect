#include <config.h>

#include "openconnect-internal.h"

#define NELEM(array)	(sizeof(array)/sizeof(array[0]))

static const struct {
	multicert_signhash_algorithm_t id;
	const char *name;
} digest_table[MULTICERT_SIGNHASH_MAX + 1] = {
	[ MULTICERT_SIGNHASH_SHA256 ] = { MULTICERT_SIGNHASH_SHA256, "sha256" },
	[ MULTICERT_SIGNHASH_SHA384 ] = { MULTICERT_SIGNHASH_SHA384, "sha384" },
	[ MULTICERT_SIGNHASH_SHA512 ] = { MULTICERT_SIGNHASH_SHA512, "sha512" },
};

static const struct {
	multicert_cert_format_t id;
	const char *name;
} cert_format_table[MULTICERT_CERT_FORMAT_MAX + 1] = {
	[ MULTICERT_CERT_FORMAT_PKCS7 ] = { MULTICERT_CERT_FORMAT_PKCS7, "pkcs7" },
};

const char *multicert_signhash_get_name(int id)
{
	size_t i;

	if (id > 0 && (size_t) id < NELEM(digest_table)) {
		i = (size_t) id;
		if (digest_table[i].id)
			return digest_table[i].name;
	}
	return NULL;
}

multicert_signhash_algorithm_t multicert_signhash_get_id(const char *name)
{
	size_t i;

	if (name) {
		for (i = 1; i < NELEM(digest_table); i++) {
			if (digest_table[i].name &&
			    !strcmp(digest_table[i].name, name))
				return digest_table[i].id;
		}
	}
	return MULTICERT_SIGNHASH_UNKNOWN;
}

const char *multicert_cert_format_get_name(int id)
{
	size_t i;

	if (id > 0 && (size_t) id < NELEM(cert_format_table)) {
		i = (size_t) id;
		if (cert_format_table[i].id)
			return cert_format_table[i].name;
	}
	return NULL;
}

multicert_cert_format_t multicert_cert_format_get_id(const char *name)
{
	size_t i;

	if (name) {
		for (i = 1; i < NELEM(cert_format_table); i++) {
			const char *format_name = cert_format_table[i].name;
			if (format_name && !strcmp(format_name, name))
				return cert_format_table[i].id;
		}
	}
	return MULTICERT_CERT_FORMAT_UNKNOWN;
}
