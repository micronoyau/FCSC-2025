/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "hpack.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

void string_del(struct string *str)
{
	free(str->data);

	str->size = 0;
	str->data = (void*)0xDEADBEEF;
}

static bool string_dup(struct string *dst, const struct string *src)
{
	const size_t size = src->size > 4096 ? 4096 : src->size;
	void *ptr = malloc(size);
	if(NULL == ptr)
		return false;

	memcpy(ptr, src->data, size);

	dst->data = ptr;
	dst->size = size;

	return true;
}

bool string_eq(const struct string *str, size_t n, const char data[static n])
{
	return str->size == n && 0 == memcmp(str->data, data, n);
}

// https://www.rfc-editor.org/rfc/rfc7541#appendix-A {{{
#define STR(x) {__builtin_strlen(x), x}
static const struct header headers[61] = {
	{STR(":authority"),                  {}},
	{STR(":method"),                     STR("GET")},
	{STR(":method"),                     STR("POST")},
	{STR(":path"),                       STR("/")},
	{STR(":path"),                       STR("/index.html")},
	{STR(":scheme"),                     STR("http")},
	{STR(":scheme"),                     STR("https")},
	{STR(":status"),                     STR("200")},
	{STR(":status"),                     STR("204")},
	{STR(":status"),                     STR("206")},
	{STR(":status"),                     STR("304")},
	{STR(":status"),                     STR("400")},
	{STR(":status"),                     STR("404")},
	{STR(":status"),                     STR("500")},
	{STR("accept-charset"),              {}},
	{STR("accept-encoding"),             STR("gzip, deflate")},
	{STR("accept-language"),             {}},
	{STR("accept-ranges"),               {}},
	{STR("accept"),                      {}},
	{STR("access-control-allow-origin"), {}},
	{STR("age"),                         {}},
	{STR("allow"),                       {}},
	{STR("authorization"),               {}},
	{STR("cache-control"),               {}},
	{STR("content-disposition"),         {}},
	{STR("content-encoding"),            {}},
	{STR("content-language"),            {}},
	{STR("content-length"),              {}},
	{STR("content-location"),            {}},
	{STR("content-range"),               {}},
	{STR("content-type"),                {}},
	{STR("cookie"),                      {}},
	{STR("date"),                        {}},
	{STR("etag"),                        {}},
	{STR("expect"),                      {}},
	{STR("expires"),                     {}},
	{STR("from"),                        {}},
	{STR("host"),                        {}},
	{STR("if-match"),                    {}},
	{STR("if-modified-since"),           {}},
	{STR("if-none-match"),               {}},
	{STR("if-range"),                    {}},
	{STR("if-unmodified-since"),         {}},
	{STR("last-modified"),               {}},
	{STR("link"),                        {}},
	{STR("location"),                    {}},
	{STR("max-forwards"),                {}},
	{STR("proxy-authenticate"),          {}},
	{STR("proxy-authorization"),         {}},
	{STR("range"),                       {}},
	{STR("referer"),                     {}},
	{STR("refresh"),                     {}},
	{STR("retry-after"),                 {}},
	{STR("server"),                      {}},
	{STR("set-cookie"),                  {}},
	{STR("strict-transport-security"),   {}},
	{STR("transfer-encoding"),           {}},
	{STR("user-agent"),                  {}},
	{STR("vary"),                        {}},
	{STR("via"),                         {}},
	{STR("www-authenticate"),            {}},
};
// }}}

void headers_del(struct headers *hdrs)
{
	for(size_t i = 0; i < hdrs->count; i++) {
		string_del(&hdrs->headers[i].key);
		string_del(&hdrs->headers[i].value);
	}

	free(hdrs);
}

static struct headers* headers_push(struct headers *headers, struct header *h)
{
	const size_t s = sizeof(*headers) + (1 + headers->count) * sizeof(*h);
	struct headers *ret = realloc(headers, s);

	if(NULL != ret)
		ret->headers[ret->count++] = *h;

	return ret;
}

struct state {
	const char *data;
	size_t size;
	size_t pos;
};

// Parse a bit
static bool getBit(struct state *state, bool *b)
{
	const size_t idx   = state->pos / 8;
	const size_t shift = state->pos % 8;

	if(state->pos >= state->size)
		return false;

	*b = 1 & (state->data[idx] >> (7 - shift));
	state->pos++;

	return true;
}

// Parse a byte
static bool getByte(struct state *state, unsigned char *c)
{
	// Always aligned
	assert(0 == (state->pos % 8));

	if(state->pos >= state->size)
		return false;

	*c = state->data[state->pos / 8];
	state->pos += 8;

	return true;
}

// Parse a variable integer
static bool getVarint(struct state *state, size_t *n)
{
	// The prefix size, N, is always between 1 and 8 bits
	size_t prefix = 8 - (state->pos % 8);
	assert(prefix >= 1 && prefix <= 8);

	// Get all remaining bits
	size_t r = state->data[state->pos / 8];
	r &= 0xFF >> (state->pos % 8);

	// Align position
	state->pos += prefix;

	// Check if not all 1
	if(0 != (r + 1) >> prefix) {
		size_t shift = 0;
		unsigned char c;

		do {
			if(!getByte(state, &c))
				return false;

			r += (size_t)(c & 0x7F) << shift;
			shift += 7;
		} while(c & 0x80);
	}

	// To allow for optimized processing, an integer
	// representation always finishes at the end of an octet.
	assert(0 == (state->pos % 8));

	*n = r;

	return true;
}
// https://www.rfc-editor.org/rfc/rfc7541#appendix-C.1
static void test_varint(void) // {{{
{
	// https://www.rfc-editor.org/rfc/rfc7541#appendix-C.1.1
	for(size_t i = 0b000; i <= 0b111; i++) {
		char c = (i << 5) | 0b01010;
		struct state s = {
			.data = &c,
			.size = 8 * sizeof(c),
			.pos  = 3,
		};

		size_t n = -1;
		bool ret = getVarint(&s, &n);

		assert(ret);
		assert(10 == n);
	}

	// https://www.rfc-editor.org/rfc/rfc7541#appendix-C.1.2
	for(size_t i = 0b000; i <= 0b111; i++) {
		char c[] = {
			(i << 5) | 0b11111,
			0b10011010,
			0b00001010,
		};
		struct state s = {
			.data = c,
			.size = 8 * sizeof(c),
			.pos  = 3,
		};

		size_t n = -1;
		bool ret = getVarint(&s, &n);

		assert(ret);
		assert(1337 == n);
	}

	// https://www.rfc-editor.org/rfc/rfc7541#appendix-C.1.3
	{
		char c = 0b00101010;
		struct state s = {
			.data = &c,
			.size = 8 * sizeof(c),
			.pos  = 0,
		};

		size_t n = -1;
		bool ret = getVarint(&s, &n);

		assert(ret);
		assert(42 == n);
	}

	printf("varInt ok\n");
} // }}}

static bool huffmanDecode(struct string *dst, const struct string *src)
{
	// https://www.rfc-editor.org/rfc/rfc7541#appendix-B {{{
	static const uint32_t huff_val[0x100 + 1] = {
		0b1111111111000,                  0b11111111111111111011000,
		0b1111111111111111111111100010,   0b1111111111111111111111100011,
		0b1111111111111111111111100100,   0b1111111111111111111111100101,
		0b1111111111111111111111100110,   0b1111111111111111111111100111,
		0b1111111111111111111111101000,   0b111111111111111111101010,
		0b111111111111111111111111111100, 0b1111111111111111111111101001,
		0b1111111111111111111111101010,   0b111111111111111111111111111101,
		0b1111111111111111111111101011,   0b1111111111111111111111101100,
		0b1111111111111111111111101101,   0b1111111111111111111111101110,
		0b1111111111111111111111101111,   0b1111111111111111111111110000,
		0b1111111111111111111111110001,   0b1111111111111111111111110010,
		0b111111111111111111111111111110, 0b1111111111111111111111110011,
		0b1111111111111111111111110100,   0b1111111111111111111111110101,
		0b1111111111111111111111110110,   0b1111111111111111111111110111,
		0b1111111111111111111111111000,   0b1111111111111111111111111001,
		0b1111111111111111111111111010,   0b1111111111111111111111111011,
		0b010100,                         0b1111111000,
		0b1111111001,                     0b111111111010,
		0b1111111111001,                  0b010101,
		0b11111000,                       0b11111111010,
		0b1111111010,                     0b1111111011,
		0b11111001,                       0b11111111011,
		0b11111010,                       0b010110,
		0b010111,                         0b011000,
		0b00000,                          0b00001,
		0b00010,                          0b011001,
		0b011010,                         0b011011,
		0b011100,                         0b011101,
		0b011110,                         0b011111,
		0b1011100,                        0b11111011,
		0b111111111111100,                0b100000,
		0b111111111011,                   0b1111111100,
		0b1111111111010,                  0b100001,
		0b1011101,                        0b1011110,
		0b1011111,                        0b1100000,
		0b1100001,                        0b1100010,
		0b1100011,                        0b1100100,
		0b1100101,                        0b1100110,
		0b1100111,                        0b1101000,
		0b1101001,                        0b1101010,
		0b1101011,                        0b1101100,
		0b1101101,                        0b1101110,
		0b1101111,                        0b1110000,
		0b1110001,                        0b1110010,
		0b11111100,                       0b1110011,
		0b11111101,                       0b1111111111011,
		0b1111111111111110000,            0b1111111111100,
		0b11111111111100,                 0b100010,
		0b111111111111101,                0b00011,
		0b100011,                         0b00100,
		0b100100,                         0b00101,
		0b100101,                         0b100110,
		0b100111,                         0b00110,
		0b1110100,                        0b1110101,
		0b101000,                         0b101001,
		0b101010,                         0b00111,
		0b101011,                         0b1110110,
		0b101100,                         0b01000,
		0b01001,                          0b101101,
		0b1110111,                        0b1111000,
		0b1111001,                        0b1111010,
		0b1111011,                        0b111111111111110,
		0b11111111100,                    0b11111111111101,
		0b1111111111101,                  0b1111111111111111111111111100,
		0b11111111111111100110,           0b1111111111111111010010,
		0b11111111111111100111,           0b11111111111111101000,
		0b1111111111111111010011,         0b1111111111111111010100,
		0b1111111111111111010101,         0b11111111111111111011001,
		0b1111111111111111010110,         0b11111111111111111011010,
		0b11111111111111111011011,        0b11111111111111111011100,
		0b11111111111111111011101,        0b11111111111111111011110,
		0b111111111111111111101011,       0b11111111111111111011111,
		0b111111111111111111101100,       0b111111111111111111101101,
		0b1111111111111111010111,         0b11111111111111111100000,
		0b111111111111111111101110,       0b11111111111111111100001,
		0b11111111111111111100010,        0b11111111111111111100011,
		0b11111111111111111100100,        0b111111111111111011100,
		0b1111111111111111011000,         0b11111111111111111100101,
		0b1111111111111111011001,         0b11111111111111111100110,
		0b11111111111111111100111,        0b111111111111111111101111,
		0b1111111111111111011010,         0b111111111111111011101,
		0b11111111111111101001,           0b1111111111111111011011,
		0b1111111111111111011100,         0b11111111111111111101000,
		0b11111111111111111101001,        0b111111111111111011110,
		0b11111111111111111101010,        0b1111111111111111011101,
		0b1111111111111111011110,         0b111111111111111111110000,
		0b111111111111111011111,          0b1111111111111111011111,
		0b11111111111111111101011,        0b11111111111111111101100,
		0b111111111111111100000,          0b111111111111111100001,
		0b1111111111111111100000,         0b111111111111111100010,
		0b11111111111111111101101,        0b1111111111111111100001,
		0b11111111111111111101110,        0b11111111111111111101111,
		0b11111111111111101010,           0b1111111111111111100010,
		0b1111111111111111100011,         0b1111111111111111100100,
		0b11111111111111111110000,        0b1111111111111111100101,
		0b1111111111111111100110,         0b11111111111111111110001,
		0b11111111111111111111100000,     0b11111111111111111111100001,
		0b11111111111111101011,           0b1111111111111110001,
		0b1111111111111111100111,         0b11111111111111111110010,
		0b1111111111111111101000,         0b1111111111111111111101100,
		0b11111111111111111111100010,     0b11111111111111111111100011,
		0b11111111111111111111100100,     0b111111111111111111111011110,
		0b111111111111111111111011111,    0b11111111111111111111100101,
		0b111111111111111111110001,       0b1111111111111111111101101,
		0b1111111111111110010,            0b111111111111111100011,
		0b11111111111111111111100110,     0b111111111111111111111100000,
		0b111111111111111111111100001,    0b11111111111111111111100111,
		0b111111111111111111111100010,    0b111111111111111111110010,
		0b111111111111111100100,          0b111111111111111100101,
		0b11111111111111111111101000,     0b11111111111111111111101001,
		0b1111111111111111111111111101,   0b111111111111111111111100011,
		0b111111111111111111111100100,    0b111111111111111111111100101,
		0b11111111111111101100,           0b111111111111111111110011,
		0b11111111111111101101,           0b111111111111111100110,
		0b1111111111111111101001,         0b111111111111111100111,
		0b111111111111111101000,          0b11111111111111111110011,
		0b1111111111111111101010,         0b1111111111111111101011,
		0b1111111111111111111101110,      0b1111111111111111111101111,
		0b111111111111111111110100,       0b111111111111111111110101,
		0b11111111111111111111101010,     0b11111111111111111110100,
		0b11111111111111111111101011,     0b111111111111111111111100110,
		0b11111111111111111111101100,     0b11111111111111111111101101,
		0b111111111111111111111100111,    0b111111111111111111111101000,
		0b111111111111111111111101001,    0b111111111111111111111101010,
		0b111111111111111111111101011,    0b1111111111111111111111111110,
		0b111111111111111111111101100,    0b111111111111111111111101101,
		0b111111111111111111111101110,    0b111111111111111111111101111,
		0b111111111111111111111110000,    0b11111111111111111111101110,
		0b111111111111111111111111111111,
	};

	static const uint8_t huff_size[0x100 + 1] = {
		13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
		28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		 6, 10, 10, 12, 13,  6,  8, 11, 10, 10,  8, 11,  8,  6,  6,  6,
		 5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8, 15,  6, 12, 10,
		13,  6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
		 7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8, 13, 19, 13, 14,  6,
		15,  5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
		 6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7, 15, 11, 14, 13, 28,
		20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
		24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
		22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
		21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
		26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
		19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
		20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
		26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
		30,
	};
	// }}}

	struct state state = {
		.data = src->data,
		.size = 8 * src->size,
	};

	struct string ret = {
		.data = NULL,
		.size = 0,
	};

	size_t n = 0;
	size_t x = 0;

	bool b;
	while(getBit(&state, &b)) {
		n++;
		x = (x << 1) | b;

		for(size_t i = 0; i < 0x101; i++) {
			if(n != huff_size[i])
				continue;

			if(x != huff_val[i])
				continue;

			// A Huffman-encoded string literal containing the EOS
			// symbol MUST be treated as a decoding error.
			if(0x101 == i) {
				free(ret.data);
				return false;
			}

			ret.data = realloc(ret.data, ret.size + 1);
			ret.data[ret.size] = i;
			ret.size++;

			n = x = 0;
		}
	}

	*dst = ret;

	return true;
}

// https://www.rfc-editor.org/rfc/rfc7541#appendix-C.4
static void test_huffman(void) // {{{
{
	// https://www.rfc-editor.org/rfc/rfc7541#appendix-C.4.1
	{
		const struct string s = {
			.data = "\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4"
				"\xff",
			.size = 12,
		};

		struct string t;
		bool ret = huffmanDecode(&t, &s);

		assert(ret);
		assert(string_eq(&t, 15, "www.example.com"));
		string_del(&t);
	}

	// https://www.rfc-editor.org/rfc/rfc7541#appendix-C.4.2
	{
		const struct string s = {
			.data = "\xa8\xeb\x10\x64\x9c\xbf",
			.size = 6,
		};

		struct string t;
		bool ret = huffmanDecode(&t, &s);

		assert(ret);
		assert(string_eq(&t, 8, "no-cache"));
		string_del(&t);
	}

	// https://www.rfc-editor.org/rfc/rfc7541#appendix-C.4.3
	{
		const struct string s = {
			.data = "\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f",
			.size = 8,
		};

		struct string t;
		bool ret = huffmanDecode(&t, &s);

		assert(ret);
		assert(string_eq(&t, 10, "custom-key"));
		string_del(&t);
	}

	{
		const struct string s = {
			.data = "\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf",
			.size = 9,
		};

		struct string t;
		bool ret = huffmanDecode(&t, &s);

		assert(ret);
		assert(string_eq(&t, 12, "custom-value"));
		string_del(&t);
	}

	printf("huffman ok\n");
} // }}}

static bool getString(struct state *state, struct string *str)
{
	assert(0 == (state->pos % 8));

	// Read the huffman bit
	bool h;
	if(!getBit(state, &h))
		return false;

	size_t s;
	if(!getVarint(state, &s))
		return false;

	assert(0 == (state->pos % 8));

	if(state->pos + 8 * s > state->size)
		return false;

	char *data = malloc(s);
	if(NULL == data)
		return false;

	// Data is not null-terminated
	memcpy(data, &state->data[state->pos / 8], s);
	state->pos += 8 * s;

	struct string ret = {
		.data = data,
		.size = s,
	};

	if(h) {
		struct string r2;

		if(!huffmanDecode(&r2, &ret))
			return false;

		string_del(&ret);
		*str = r2;
	} else {
		*str = ret;
	}

	return true;
}

static void test_literal(void) // {{{
{
	{
		struct state s = {
			.data = "\x04" "test",
			.size = 8 * (1 + 4),
		};

		struct string str;
		bool ret = getString(&s, &str);

		assert(ret);
		assert(4 == str.size);
		assert(0 == memcmp("test", str.data, str.size));

		if(ret)
			free(str.data);
	}

	printf("literal ok\n");
} // }}}

static const struct header* getIndexed(const struct header *table, size_t idx)
{
	if(0 == idx)
		return NULL;

	const size_t s = sizeof(headers) / sizeof(*headers);

	if(idx - 1 < s)
		return &headers[idx - 1];

	// Overflow here??? WTF Returns pointer in heap
	return &table[idx - 1 - s];
}

struct headers*
parse(struct header *table, size_t size, const char data[static size])
{
	struct state state = {
		.data = data,
		.size = 8 * size,
	};

	struct headers *ret = malloc(sizeof(*ret));
	if(NULL == ret)
		return NULL;
	ret->count = 0;

	while(state.pos < state.size) {
		// Determine the type
		size_t type;

		// 0: Indexed Header Field Representation
		// 1: Literal Header Field with Incremental Indexing
		// 2: Dynamic Table Size Update
		// 3: Literal Header Field Never Indexed
		// 4: Literal Header Field without Indexing
		for(type = 0; type < 4; type++) {
			bool b;

			if(!getBit(&state, &b))
				goto err;

			if(b)
				break;
		}

		// Indexed Header Field Representation
		// https://www.rfc-editor.org/rfc/rfc7541#section-6.1
		if(0 == type) {
			size_t n;
			if(!getVarint(&state, &n))
				goto err;

			// The index value of 0 is not used.  It MUST be treated as a
			// decoding error if found in an indexed header field
			// representation.
			if(0 == n)
				goto err;


			struct header h = *getIndexed(table, n);

			if(!string_dup(&h.key, &h.key))
				goto err;

			if(!string_dup(&h.value, &h.value))
				goto err;

			ret = headers_push(ret, &h);
			if(NULL == ret)
				return NULL;
		}

		// Not implemented, will just parse a variable int
		// Dynamic Table Size Update
		// https://www.rfc-editor.org/rfc/rfc7541#section-6.3
		// TODO: the actual update
		else if(2 == type) {
			size_t maxSize;
			if(!getVarint(&state, &maxSize))
				goto err;
		}

		// 3 and 4 is the same thing
		// Literal Header Field with Incremental Indexing
		// https://www.rfc-editor.org/rfc/rfc7541#section-6.2.1
		// Literal Header Field without Indexing
		// https://www.rfc-editor.org/rfc/rfc7541#section-6.2.2
		// Literal Header Field Never Indexed
		// https://www.rfc-editor.org/rfc/rfc7541#section-6.2.3
		else {
			size_t index;
			if(!getVarint(&state, &index))
				goto err;

			struct header h;

			if(0 == index) {
				if(!getString(&state, &h.key))
					return false;
			} else {
				h.key = getIndexed(table, index)->key;
				if(!string_dup(&h.key, &h.key))
					goto err;
			}

			if(!getString(&state, &h.value))
				goto err;

			ret = headers_push(ret, &h);
			if(NULL == ret)
				return NULL;

			// Update the table
			if(1 == type) {
				// Moves 4095 BYTES, not HEADERS!
				memmove(table + 1, table, 4096 - 1);

				if(!string_dup(&table[0].key, &h.key))
					goto err;

				if(!string_dup(&table[0].value, &h.value))
					goto err;
			}
		}
	}

	return ret;

err:
	free(ret);
	return NULL;
}

// https://www.rfc-editor.org/rfc/rfc7541#appendix-C.2
static void test_binary(void)
{
	// https://www.rfc-editor.org/rfc/rfc7541#appendix-C.2.4
	{
		struct state s = {
			.data = "\x82",
			.size = 8 * 1,
		};

		struct header *table = calloc(4096, sizeof(*table));
		struct headers *hdrs = parse(table, s.size / 8, s.data);
		free(table);

		assert(NULL != hdrs);
		assert(1 == hdrs->count);

		assert(string_eq(&hdrs->headers[0].key,   7, ":method"));
		assert(string_eq(&hdrs->headers[0].value, 3, "GET"));

		headers_del(hdrs);
	}

	// https://www.rfc-editor.org/rfc/rfc7541#appendix-C.2.1
	{
		struct state s = {
			.data = "@"
				"\x0A" "custom-key"
				"\x0D" "custom-header",
			.size = 8 * (1 + 1 + 0x0A + 1 + 0x0D),
		};

		struct header *table = calloc(4096, sizeof(*table));
		struct headers *hdrs = parse(table, s.size / 8, s.data);
		free(table);

		assert(NULL != hdrs);
		assert(1 == hdrs->count);

		assert(string_eq(&hdrs->headers[0].key,   10, "custom-key"));
		assert(string_eq(&hdrs->headers[0].value, 13, "custom-header"));

		headers_del(hdrs);
	}

	printf("binary ok\n");
}

static void test_curl(void)
{
	struct state state = {
		.size = 8 * 36,
		.data = "\x82\x86\x41\x8a\x08\x9d\x5c\x0b\x81\x70\xdc\x78\x0f"
			"\x03\x04\x85\x62\x59\x91\x2c\x88\x7a\x88\x25\xb6\x50"
			"\xc3\xcb\x85\x95\xc1\x53\x03\x2a\x2f\x2a",
	};

	struct header *table = calloc(4096, sizeof(*table));
	struct headers *hdrs = parse(table, state.size / 8, state.data);
	free(table);

	assert(NULL != hdrs);
	assert(6 == hdrs->count);

	assert(string_eq(&hdrs->headers[0].key,    7, ":method"));
	assert(string_eq(&hdrs->headers[0].value,  3, "GET"));

	assert(string_eq(&hdrs->headers[1].key,    7, ":scheme"));
	assert(string_eq(&hdrs->headers[1].value,  4, "http"));

	assert(string_eq(&hdrs->headers[2].key,   10, ":authority"));
	assert(string_eq(&hdrs->headers[2].value, 14, "127.0.0.1:8080"));

	assert(string_eq(&hdrs->headers[3].key,    5, ":path"));
	assert(string_eq(&hdrs->headers[3].value,  7, "/fgsfds"));

	assert(string_eq(&hdrs->headers[4].key,   10, "user-agent"));
	assert(string_eq(&hdrs->headers[4].value, 11, "curl/8.13.0"));

	assert(string_eq(&hdrs->headers[5].key,    6, "accept"));
	assert(string_eq(&hdrs->headers[5].value,  3, "*/*"));

	headers_del(hdrs);
}

__attribute__((weak))
int main(void)
{
	test_varint();
	test_literal();
	test_binary();
	test_huffman();
	test_curl();

	return EXIT_SUCCESS;
}
