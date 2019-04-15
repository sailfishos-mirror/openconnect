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

static inline void store_be64(void *p, uint64_t val)
{
	*(uint64_t *)p = __builtin_bswap64(val);
}


#if 0
static void X_sha1_block_data_order(struct aesni_sha1 *sha, unsigned char *data, int len)
{
	int i, j;

	for (j = 0; j < len; j++) {
		printf("%p(%d):", sha, sha->N + (j * SHA1_BLOCK));
		for (i=0; i < SHA1_BLOCK; i++)
			printf(" %02x", data[(j * SHA1_BLOCK + i)]);
		printf("\n");
	}
	sha1_block_data_order(sha, data, len);
}
#define sha1_block_data_order X_sha1_block_data_order
#endif
static inline void aesni_sha1_init(struct aesni_sha1 *ctx, uint64_t len)
{
	ctx->h0 = 0x67452301UL;
	ctx->h1 = 0xefcdab89UL;
	ctx->h2 = 0x98badcfeUL;
	ctx->h3 = 0x10325476UL;
	ctx->h4 = 0xc3d2e1f0UL;
	ctx->N = len;
}

static void setup_sha1_hmac(struct esp *esp,
			    unsigned char *key, int len)
{
        unsigned char opad[64];
        unsigned char ipad[64];
        int i;

        aesni_sha1_init(&esp->aesni_hmac.o, SHA1_BLOCK);
        aesni_sha1_init(&esp->aesni_hmac.i, SHA1_BLOCK);

        if (len == 64) {
                memcpy(opad, key, len);
        } else if (len < 64) {
                memcpy(opad, key, len);
                memset(opad + len, 0, 64 - len);
        } else {
                openconnect_sha1(opad, key, len);
                memset(opad + 20, 0, 44);
        }
        memcpy(ipad, opad, 64);

        for (i = 0; i < 64; i++) {
                opad[i] ^= 0x5c;
                ipad[i] ^= 0x36;
        }

	sha1_block_data_order(&esp->aesni_hmac.o, opad, 1);
	sha1_block_data_order(&esp->aesni_hmac.i, ipad, 1);
}

static void aesni_sha1_final(struct aesni_sha1 *sha, unsigned char *out, unsigned char *data, unsigned int len)
{
	unsigned char buf[SHA1_BLOCK];

	sha->N += len;

	if (len > SHA1_BLOCK) {
		sha1_block_data_order(sha, data, len / SHA1_BLOCK);
		data += len & ~(SHA1_BLOCK - 1);
		len &= (SHA1_BLOCK - 1);
	}
	if (len)
		memcpy(buf, data, len);
	buf[len++] = 0x80;

	if (len > SHA1_BLOCK - 8) {
		memset(buf + len, 0, SHA1_BLOCK - len);
		sha1_block_data_order(sha, buf, 1);
		len = 0;
	}
	memset(buf + len, 0, SHA1_BLOCK - len - 8);
	store_be64(&buf[SHA1_BLOCK - 8], sha->N << 3);
	sha1_block_data_order(sha, buf, 1);

	store_be32(out, sha->h0);
	store_be32(out + 4, sha->h1);
	store_be32(out + 8, sha->h2);
	store_be32(out + 12, sha->h3);
	store_be32(out + 16, sha->h4);
}

static void complete_sha1_hmac(struct aesni_hmac *hmac, unsigned char *out, unsigned char *data, int len)
{
        aesni_sha1_final(&hmac->i, out, data, len);
        aesni_sha1_final(&hmac->o, out, out, 20);
}

static void aesni_destroy_esp_ciphers(struct esp *esp)
{
	clear_mem(&esp->aesni_hmac.o, sizeof(esp->aesni_hmac.o));
	clear_mem(&esp->aesni_hmac.i, sizeof(esp->aesni_hmac.i));
	clear_mem(&esp->aesni_key, sizeof(esp->aesni_key));
	if (esp->aesni_hmac_block) {
		clear_mem(esp->aesni_hmac_block, SHA1_BLOCK);
		free(esp->aesni_hmac_block);
		esp->aesni_hmac_block = NULL;
	}
}

static int aesni_decrypt_esp_packet(struct openconnect_info *vpninfo, struct esp *esp, struct pkt *pkt)
{
	struct aesni_hmac hmac = esp->aesni_hmac;
	unsigned char hmac_buf[20];

	complete_sha1_hmac(&hmac, hmac_buf, (void *)&pkt->esp, sizeof(pkt->esp) + pkt->len);
	if (memcmp(hmac_buf, pkt->data + pkt->len, 12)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received ESP packet with invalid HMAC\n"));
		return -EINVAL;
	}

	if (verify_packet_seqno(vpninfo, esp, ntohl(pkt->esp.seq)))
		return -EINVAL;

	aesni_cbc_encrypt(pkt->data, pkt->data, pkt->len,
			  &esp->aesni_key, (unsigned char *)&pkt->esp.iv, 0);
	return 0;
}

static int aesni_encrypt_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt, int crypt_len)
{
	struct esp *esp = &vpninfo->esp_out;
	struct aesni_hmac hmac = esp->aesni_hmac;
	unsigned char *esp_p = (unsigned char *)&pkt->esp;
	unsigned char *data_p = pkt->data;
	int shablk_end;
	int stitched = 0;

#define PRECBC 64
#define BLK 64

	/* Encrypt the first block */
	if (crypt_len >= PRECBC + BLK) {
		aesni_cbc_encrypt(data_p, data_p, PRECBC, &esp->aesni_key,
				  esp->iv, 1);

		/* Then the stitched part */
		stitched = (crypt_len - PRECBC) / BLK;
		aesni_cbc_sha1_enc(data_p + PRECBC, data_p + PRECBC, stitched, &esp->aesni_key,
				   esp->iv, &hmac.i, &pkt->esp);
		hmac.i.N += (stitched * BLK);

		stitched *= BLK;

		/* Now encrypt anything remaining */
		if (crypt_len > stitched + PRECBC)
			aesni_cbc_encrypt(data_p + stitched + PRECBC, data_p + stitched + PRECBC,
					  crypt_len - stitched - PRECBC,
					  &esp->aesni_key, esp->iv, 1);
	} else {
		aesni_cbc_encrypt(data_p + stitched, data_p + stitched,
				  crypt_len - stitched, &esp->aesni_key, esp->iv, 1);
	}

	/* And now fold in the final part of the HMAC, which is two blocks plus the ESP header behind */

	/* The 0x80 end marker will always fit into the hash block with the encrypted packet,
	 * as the crypto block size is 16 bytes and the ESP header is only 24. */
	*(uint64_t *)(data_p + crypt_len) = 0x80;

	/* Calculate and clear the end of the SHA1 block (64 bytes), bearing in mind
	 * that it starts at the ESP header, but is referenced via the data pointer. */
	shablk_end = ((crypt_len + sizeof(pkt->esp) + 8 + (SHA1_BLOCK-1)) & ~(SHA1_BLOCK-1)) - sizeof(pkt->esp);
	memset(data_p + crypt_len + 8, 0, shablk_end - crypt_len - 8);

	if (shablk_end > crypt_len + 8) {
		/* SHA1 count also happens to fit into this hash block. Include it, and we're done. */
		store_be64(data_p + shablk_end - 8, (crypt_len + sizeof(pkt->esp) + SHA1_BLOCK) << 3);
		sha1_block_data_order(&hmac.i, esp_p + stitched, ((shablk_end + sizeof(pkt->esp) - stitched) / SHA1_BLOCK));
	} else {
		/* Include last data block (from the packet), trailed with zeroes. */
		sha1_block_data_order(&hmac.i, esp_p + stitched, (shablk_end + sizeof(pkt->esp) - stitched) / SHA1_BLOCK);

		/* We need a new, mostly-zero, hash block for the length. */
		memset(esp->aesni_hmac_block, 0, 21);
		store_be64(&esp->aesni_hmac_block[SHA1_BLOCK - 8], (crypt_len + sizeof(pkt->esp) + SHA1_BLOCK) << 3);
		sha1_block_data_order(&hmac.i, esp->aesni_hmac_block, 1);
	}

	/* Now calculate the outer hash of the HMAC */
	store_be32(esp->aesni_hmac_block, hmac.i.h0);
	store_be32(esp->aesni_hmac_block + 4, hmac.i.h1);
	store_be32(esp->aesni_hmac_block + 8, hmac.i.h2);
	store_be32(esp->aesni_hmac_block + 12, hmac.i.h3);
	store_be32(esp->aesni_hmac_block + 16, hmac.i.h4);

	/* Outer SHA1 completion */
	esp->aesni_hmac_block[20] = 0x80;
	store_be64(&esp->aesni_hmac_block[SHA1_BLOCK - 8], (SHA1_BLOCK + 20) << 3);
	sha1_block_data_order(&hmac.o, esp->aesni_hmac_block, 1);

	store_be32(data_p + crypt_len, hmac.o.h0);
	store_be32(data_p + crypt_len + 4, hmac.o.h1);
	store_be32(data_p + crypt_len + 8, hmac.o.h2);

	/* Generate IV for next packet */
	aesni_cbc_encrypt(data_p + crypt_len + 8, esp->iv, 16, &esp->aesni_key, esp->iv, 1);

 	return sizeof(pkt->esp) + crypt_len + 12;
}

static int aesni_init_esp_cipher(struct openconnect_info *vpninfo, struct esp *esp,
			    int bits, int decrypt)
{
	int ret;

	aesni_destroy_esp_ciphers(esp);

	if (decrypt)
		ret = aesni_set_decrypt_key(esp->enc_key, bits, &esp->aesni_key);
	else {
		ret = aesni_set_encrypt_key(esp->enc_key, bits, &esp->aesni_key);
		if (!ret)
			ret = openconnect_random(&esp->iv, sizeof(esp->iv));
	}

	if (ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialise ESP cipher\n"));
		return -EIO;
	}

	setup_sha1_hmac(esp, esp->hmac_key, 20 /*esp->hmac_key_len*/);

	if (!esp->aesni_hmac_block) {
		esp->aesni_hmac_block = calloc(1, SHA1_BLOCK);
		if (!esp->aesni_hmac_block)
			return -ENOMEM;
	}

	vpninfo->pkt_trailer = 17 + 16 + 20 + 64; /* 17 for pad, 16 for IV, 64 for HMAC blocking */
	return 0;
}

#define AESNI_AND_SSSE3 ( (1UL << 41) | (1UL << 57) )
int aesni_init_esp_ciphers(struct openconnect_info *vpninfo,
			   struct esp *esp_out, struct esp *esp_in)
{
	int bits;
	int ret;

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

	if ((OPENCONNECT_ia32cap_P[0] & AESNI_AND_SSSE3) != AESNI_AND_SSSE3) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("CPU does not have AES-NI and SSSE3; not using AES-NI optimised code\n"));
		return -EINVAL;
	}

	/* This code only supports SHA1 */
	if (vpninfo->esp_hmac != HMAC_SHA1)
		return -EINVAL;

	if (vpninfo->esp_enc == ENC_AES_128_CBC)
		bits = 128;
	else if (vpninfo->esp_enc == ENC_AES_256_CBC)
		bits = 256;
	else
		return -EINVAL;

	ret = aesni_init_esp_cipher(vpninfo, esp_out, bits, 0);
	if (ret)
		return ret;

	ret = aesni_init_esp_cipher(vpninfo, esp_in, bits, 1);
	if (ret) {
		aesni_destroy_esp_ciphers(esp_out);
		return ret;
	}

	vpninfo->decrypt_esp_packet = aesni_decrypt_esp_packet;
	vpninfo->encrypt_esp_packet = aesni_encrypt_esp_packet;
	vpninfo->destroy_esp_ciphers = aesni_destroy_esp_ciphers;

	return 0;
}

