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

#ifndef __AESNI_ESP_H__
#define __AESNI_ESP_H__

/* ABI definitions for the CRYPTOGAMS routines */

#define AES_MAXKEYBITS 256
#define AES_MAXROUNDS 14
#define AES_BLOCK 16

struct aesni_key {
	uint32_t rd_key[4 * (AES_MAXROUNDS + 1)];
	int rounds;
};

/* Not literally AES-NI but we are only using this in the context of the
   stitched AES-NI + SHA1 routines. */

#define SHA1_BLOCK 64

struct aesni_sha1 {
	uint32_t h0, h1, h2, h3, h4;
	uint64_t N; /* The CRYPTOGAMS routines don't touch this */
};


int aesni_set_encrypt_key (const unsigned char *userKey, int bits,
			   struct aesni_key *key);
int aesni_set_decrypt_key (const unsigned char *userKey, int bits,
			   struct aesni_key *key);

void aesni_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const struct aesni_key *key,
		       unsigned char *ivec, int enc);

void aesni_cbc_sha1_enc(const void *inp, void *out, size_t blocks,
                        const struct aesni_key *key, unsigned char iv[16],
                        const struct aesni_sha1 *ctx, const void *in0);

void sha1_block_data_order(struct aesni_sha1 *ctx, const void *p,
			   size_t n_blocks);

uint64_t OPENCONNECT_ia32_cpuid(uint64_t *cap);

#endif /* AESNI_ESP_H__ */
