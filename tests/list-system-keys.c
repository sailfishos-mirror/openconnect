/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2022 David Woodhouse <dwmw2@infradead.org>
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

#include <stdlib.h>
#include <stdio.h>

#include <gnutls/system-keys.h>

int main(void)
{
        gnutls_system_key_iter_t iter = NULL;
	char *cert, *key, *label;
	int err;

	while ((err = gnutls_system_key_iter_get_info(&iter, GNUTLS_CRT_X509,
						      &cert, &key, &label, NULL, 0)) >= 0)
		printf("Label: %s\nCert: %s\nKey: %s\n\n", label, cert, key);

	if (err == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
		err = 0;

	if (err < 0)
		fprintf(stderr, "Error listing keys: %s\n", gnutls_strerror(err));

        gnutls_system_key_iter_deinit(iter);

	return !!err;
}
