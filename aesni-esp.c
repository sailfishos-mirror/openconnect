/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2019 David Woodhouse
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
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "openconnect-internal.h"

#include "aesni-esp.h"

uint64_t OPENCONNECT_ia32cap_P[2];

int aesni_init_esp_ciphers(struct openconnect_info *vpninfo,
			   struct esp *esp_out, struct esp *esp_in)
{
	if (!(OPENCONNECT_ia32cap_P[0] & (1<<10))) {
		uint64_t cap = OPENCONNECT_ia32_cpuid(OPENCONNECT_ia32cap_P);

		OPENCONNECT_ia32cap_P[0] = cap | (1<<10);

		vpn_progress(vpninfo, PRG_DEBUG,
			     _("CPU capabilities: %08lx %08lx %08lx %08lx\n"),
			     OPENCONNECT_ia32cap_P[0] & 0xffffffff,
			     OPENCONNECT_ia32cap_P[0] >> 32,
			     OPENCONNECT_ia32cap_P[1] & 0xffffffff,
			     OPENCONNECT_ia32cap_P[1] >> 32);
	}

	return -EINVAL;
}
