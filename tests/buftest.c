/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2021 David Woodhouse.
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

#include <stdint.h>
#include <stdio.h>
#ifdef _WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#define __OPENCONNECT_INTERNAL_H__

/* I always coded as if it worked like this. Now it does. */
#define realloc_inplace(p, size) do {			\
		void *__realloc_old = p;		\
		p = realloc(p, size);			\
		if (size && !p)				\
			free(__realloc_old);		\
	} while (0)

struct oc_packed_uint32_t {
	uint32_t d;
} __attribute__((packed));
struct oc_packed_uint16_t {
	uint16_t d;
} __attribute__((packed));

static inline uint32_t load_be32(const void *_p)
{
	const struct oc_packed_uint32_t *p = _p;
	return ntohl(p->d);
}

static inline uint16_t load_be16(const void *_p)
{
	const struct oc_packed_uint16_t *p = _p;
	return ntohs(p->d);
}

static inline void store_be32(void *_p, uint32_t d)
{
	struct oc_packed_uint32_t *p = _p;
	p->d = htonl(d);
}

static inline void store_be16(void *_p, uint16_t d)
{
	struct oc_packed_uint16_t *p = _p;
	p->d = htons(d);
}

static inline uint32_t load_le32(const void *_p)
{
	const unsigned char *p = _p;
	return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static inline uint16_t load_le16(const void *_p)
{
	const unsigned char *p = _p;
	return p[0] | (p[1] << 8);
}

static inline void store_le16(void *_p, uint16_t d)
{
	unsigned char *p = _p;
	p[0] = d;
	p[1] = d >> 8;
}

static inline void store_le32(void *_p, uint32_t d)
{
	unsigned char *p = _p;
	p[0] = d;
	p[1] = d >> 8;
	p[2] = d >> 16;
	p[3] = d >> 24;
}

struct oc_text_buf {
	char *data;
	char *alloc;
	int pos;
	int alloc_len;
	int error;
};

#define BUFTEST
#include "../textbuf.c"

#define assert(x) do {							\
		if (!(x)) {						\
			fprintf(stderr,					\
			        "assert(%s) failed at line %d\n",	\
			        #x, __LINE__);				\
			exit(1);					\
		}							\
	} while (0)


static char testbytes[OC_BUF_MAX];

int main(void)
{
	struct oc_text_buf *buf = NULL;

	assert(buf_error(buf) == -ENOMEM);

	buf = buf_alloc();
	assert(!buf_error(buf));

	int len = (OC_BUF_MAX - 1) / 4 * 3;
	buf_append_base64(buf, testbytes, len, 0);
	assert(!buf_error(buf));
	assert(buf->pos == OC_BUF_MAX - 4);

	buf_truncate(buf);
	len++;
	buf_append_base64(buf, testbytes, len, 0);
	assert(buf_error(buf) == -E2BIG);

	buf->error = 0;
	buf_append_base64(buf, testbytes, -1, 0);
	assert(buf_error(buf) == -EINVAL);

	buf->error = 0;
	buf_truncate(buf);

	int ll;

	for (ll = 0; ll < 128; ll += 4) {
		for (len = 0; len < 16384; len++) {
			buf_truncate(buf);
			buf_append_base64(buf, testbytes, len, ll);
			assert(!buf_error(buf));
			if (len > 128)
				len += len/2;
		}
	}
	buf_free(buf);

	/* Regression test for #851: buf_append() infinite loop when
	 * vsnprintf output exactly fills remaining space (ret == max_len).
	 * BUF_CHUNK_SIZE is 4096, so a buffer at pos 4048 with buf_len 4096
	 * has max_len=48. A format producing exactly 48 chars triggers the
	 * boundary condition. */
	buf = buf_alloc();
	assert(!buf_error(buf));

	/* Fill to 48 bytes short of a 4096 boundary */
	while (buf->pos < 4096 - 48)
		buf_append(buf, "AAAAAAAAAAAAAAAA");
	/* Trim to exactly the target position */
	buf->pos = 4096 - 48;

	/* This format produces exactly 48 chars (would have looped forever) */
	buf_append(buf, "%048d", 0);
	assert(!buf_error(buf));
	assert(buf->pos == 4096);

	buf_free(buf);

	/* Test buf_steal() */
	buf = buf_alloc();
	buf_append(buf, "hello world");
	assert(!buf_error(buf));
	{
		char *stolen = buf_steal(buf);
		assert(stolen != NULL);
		assert(strcmp(stolen, "hello world") == 0);
		assert(buf->data == NULL);
		assert(buf->alloc == NULL);
		assert(buf->pos == 0);
		free(stolen);
	}
	buf_free(buf);

	/* Test buf_consume_bytes() basic operation */
	buf = buf_alloc();
	buf_append(buf, "ABCDEFGHIJ");
	assert(buf->pos == 10);
	{
		void *p = buf_consume_bytes(buf, 4);
		assert(p != NULL);
		assert(memcmp(p, "ABCD", 4) == 0);
		assert(buf->pos == 6);
		assert(memcmp(buf->data, "EFGHIJ", 6) == 0);
	}
	/* Consume the rest */
	{
		void *p = buf_consume_bytes(buf, 6);
		assert(p != NULL);
		assert(memcmp(p, "EFGHIJ", 6) == 0);
		assert(buf->pos == 0);
	}
	/* Consume from empty returns NULL */
	assert(buf_consume_bytes(buf, 1) == NULL);
	buf_free(buf);

	/* Test that buf_truncate resets head after consume */
	buf = buf_alloc();
	buf_append(buf, "1234567890");
	buf_consume_bytes(buf, 5);
	assert(buf->pos == 5);
	assert(buf->data != buf->alloc);
	buf_truncate(buf);
	assert(buf->data == buf->alloc);
	assert(buf->pos == 0);
	buf_free(buf);

	/* Test that appending after consume compacts correctly */
	buf = buf_alloc();
	/* Fill most of a 4096 chunk */
	for (int i = 0; i < 250; i++)
		buf_append(buf, "0123456789ABCDEF");
	assert(!buf_error(buf));
	assert(buf->pos == 4000);
	/* Consume 3000 bytes (head advances) */
	buf_consume_bytes(buf, 3000);
	assert(buf->pos == 1000);
	assert(buf->data - buf->alloc == 3000);
	/* Append more — should compact and not need to grow past 4096 */
	buf_append(buf, "%02000d", 0);
	assert(!buf_error(buf));
	assert(buf->pos == 3000);
	assert(buf->data == buf->alloc); /* compacted */
	assert(buf->alloc_len == 4096); /* didn't grow */
	buf_free(buf);

	/* Test buf_consume_bytes with len > pos returns NULL */
	buf = buf_alloc();
	buf_append(buf, "short");
	assert(buf_consume_bytes(buf, 100) == NULL);
	assert(buf->pos == 5); /* unchanged */
	buf_free(buf);

	/* Test vsnprintf boundary: NUL fits inside page, no consume */
	buf = buf_alloc();
	buf_append(buf, "%04000d", 0);
	assert(!buf_error(buf));
	assert(buf->pos == 4000);
	/* 4095 bytes used (4000 + 95 below), NUL at 4095 — fits in 4096 */
	buf_append(buf, "%095d", 0);
	assert(!buf_error(buf));
	assert(buf->pos == 4095);
	assert(buf->alloc_len == 4096);
	buf_free(buf);

	/* Test vsnprintf boundary: NUL would land on next page, no consume */
	buf = buf_alloc();
	buf_append(buf, "%04000d", 0);
	assert(!buf_error(buf));
	/* 4096 bytes needed + NUL = 4097 — must grow to 8192 */
	buf_append(buf, "%096d", 0);
	assert(!buf_error(buf));
	assert(buf->pos == 4096);
	assert(buf->alloc_len == 8192);
	buf_free(buf);

	/* Test vsnprintf boundary: NUL fits inside page, after consume */
	buf = buf_alloc();
	buf_append(buf, "%04000d", 0);
	assert(!buf_error(buf));
	buf_consume_bytes(buf, 100);
	assert(buf->pos == 3900);
	/* head=100, pos=3900, append 95 → head+pos+95=4095, NUL at alloc[4095] — fits */
	buf_append(buf, "%095d", 0);
	assert(!buf_error(buf));
	assert(buf->pos == 3995);
	assert(buf->alloc_len == 4096);
	assert(buf->data != buf->alloc); /* head still advanced, no compaction needed */
	buf_free(buf);

	/* Test vsnprintf boundary: NUL on next page, after consume — compacts instead of growing */
	buf = buf_alloc();
	buf_append(buf, "%04000d", 0);
	assert(!buf_error(buf));
	buf_consume_bytes(buf, 100);
	assert(buf->pos == 3900);
	/* head=100, pos=3900, append 96 → head+pos+96=4096+NUL=4097 > 4096.
	 * But after compaction: pos+96=3996+NUL=3997 < 4096. So compacts, doesn't grow. */
	buf_append(buf, "%096d", 0);
	assert(!buf_error(buf));
	assert(buf->pos == 3996);
	assert(buf->alloc_len == 4096);
	assert(buf->data == buf->alloc); /* compacted */
	buf_free(buf);

	/* Test buf_consume_be32 success */
	buf = buf_alloc();
	buf_append_be32(buf, 0xDEADBEEF);
	buf_append_be32(buf, 0x12345678);
	assert(!buf_error(buf));
	{
		uint32_t val;
		assert(buf_consume_be32(buf, &val) == 0);
		assert(val == 0xDEADBEEF);
		assert(buf->pos == 4);
		assert(buf_consume_be32(buf, &val) == 0);
		assert(val == 0x12345678);
		assert(buf->pos == 0);
	}
	buf_free(buf);

	/* Test buf_consume_be32 failure (not enough bytes) */
	buf = buf_alloc();
	buf_append_bytes(buf, "AB", 2);
	{
		uint32_t val = 0x11111111;
		assert(buf_consume_be32(buf, &val) != 0);
		assert(val == 0x11111111);
		assert(buf->pos == 2);
	}
	buf_free(buf);

	return 0;
}
