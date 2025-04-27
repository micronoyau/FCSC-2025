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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <fcntl.h>

#include "hpack.h"

// https://www.rfc-editor.org/rfc/rfc7540#section-11.2
enum frame_type {
	DATA          = 0x00,
	HEADERS       = 0x01,
	PRIORITY      = 0x02,
	RST_STREAM    = 0x03,
	SETTINGS      = 0x04,
	PUSH_PROMISE  = 0x05,
	PING          = 0x06,
	GOAWAY        = 0x07,
	WINDOW_UPDATE = 0x08,
	CONTINUATION  = 0x09,
};

// https://www.rfc-editor.org/rfc/rfc7540#section-11.3
enum settings_type {
	HEADER_TABLE_SIZE      = 0x1,
	ENABLE_PUSH            = 0x2,
	MAX_CONCURRENT_STREAMS = 0x3,
	INITIAL_WINDOW_SIZE    = 0x4,
	MAX_FRAME_SIZE         = 0x5,
	MAX_HEADER_LIST_SIZE   = 0x6,
};

struct frame {
	size_t size;
	enum frame_type type;
	uint8_t flags;
	size_t id;
};

static bool read_n(int fd, void *data, size_t size)
{
	while(size > 0) {
		ssize_t s = read(fd, data, size);

		if(s <= 0)
			return false;

		data += s;
		size -= s;
	}

	return true;
}

static bool preface(int fd)
{
	static const char expected[24] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	char buffer[sizeof(expected)];

	if(!read_n(fd, buffer, sizeof(buffer)))
		return false;

	return 0 == memcmp(expected, buffer, sizeof(expected));
}

static bool frameHeader(int fd, struct frame *frame)
{
	char data[3 + 1 + 1 + 4];

	if(!read_n(fd, data, sizeof(data)))
		return false;

	data[5] &= 0x7F;

	frame->size  = data[0] << 16 | data[1] << 8 | data[2];
	frame->type  = data[3];
	frame->flags = data[4];
	frame->id    = data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];

	return true;
}

static bool sendFrame(int fd,
	size_t id, enum frame_type type, uint8_t flags,
	size_t size, const char data[size])
{
	const unsigned char header[] = {
		size >> 16, size >> 8, size >> 0,
		type,
		flags,
		id >> 24, id >> 16, id >> 8, id >> 0,
	};

	const ssize_t len = sizeof(header) + size;

	const struct iovec iov[] = {
		{(void*)header, sizeof(header)},
		{(void*)data, size},
	};

	if(len != writev(fd, iov, sizeof(iov) / sizeof(*iov)))
		return false;

	return true;
}

static bool sendSettings(int fd)
{
	char data[6 * 3];

	*(uint16_t*)(&data[6 * 0 + 0]) = ntohs(MAX_CONCURRENT_STREAMS);
	*(uint32_t*)(&data[6 * 0 + 2]) = ntohl(8);

	*(uint16_t*)(&data[6 * 1 + 0]) = ntohs(INITIAL_WINDOW_SIZE);
	*(uint32_t*)(&data[6 * 1 + 2]) = ntohl(1 << 16);

	*(uint16_t*)(&data[6 * 2 + 0]) = ntohs(ENABLE_PUSH);
	*(uint32_t*)(&data[6 * 2 + 2]) = ntohl(0);

	return sendFrame(fd, 0, SETTINGS, 0, sizeof(data), data);
}

static bool handshake(int rx, int tx)
{
	// https://www.rfc-editor.org/rfc/rfc7540#section-3.5
	if(!preface(rx)) {
		fprintf(stderr, "Client did not send a valid preface\n");
		return false;
	}

	// Then we send a settings frame
	if(!sendSettings(tx)) {
		fprintf(stderr, "Could not send default settings\n");
		return false;
	}

	// XXX
	int x = 0xFFFF0000;
	sendFrame(tx, 0, WINDOW_UPDATE, 0, sizeof(x), (void*)&x);

	// We expect the client to send a settings frame right after the preface
	struct frame frame = {};
	if(!frameHeader(rx, &frame)) {
		fprintf(stderr, "Could not read first frame\n");
		return false;
	}

	if(SETTINGS != frame.type) {
		fprintf(stderr, "First frame is not a SETTINGS\n");
		return false;
	}

	// Acknowledge the settings
	if(!sendFrame(tx, 0, SETTINGS, 1, 0, NULL)) {
		perror("sendFrame(SETTINGS): ack");
		return false;
	}

	// Does not check that it is really settings.
	// Could be useful later.
	void *p = malloc(frame.size);
	read_n(rx, p, frame.size);
	free(p);

	return true;
}

static bool isPrintable(const struct string *str)
{
	for(size_t i = 0; i < str->size; i++)
		if(str->data[i] < 0x20 || str->data[i] > 0x7E)
			return false;

	return true;
}

static void err400(int tx, size_t id, size_t size, const char body[size])
{
	static const char hdr[] = {
		0x8C, // :status = 400

		0x40 | 31, // "content-type"
		0x0A, 't', 'e', 'x', 't', '/',
			'p', 'l', 'a', 'i', 'n',
	};
	sendFrame(tx, id, HEADERS, 4, sizeof(hdr), hdr);
	sendFrame(tx, id, DATA, 1, size, body);
}

static bool handleHeaders(int tx, const char *flag,
	size_t id, const struct headers *headers)
{
	const struct string *method = NULL;
	const struct string *path   = NULL;
	const struct string *xflag  = NULL;

	for(size_t i = 0; i < headers->count; i++) {
		const struct string *key = &headers->headers[i].key;

		// Non-printable headers
		if(!isPrintable(key)) {
			char body[0x100];

			ssize_t size = snprintf(body, sizeof(body),
				"Invalid header name: %.*s",
				(int)key->size, key->data);

			err400(tx, id, size, body);
			return false;
		}

		// Duplicate headers
		for(size_t j = 0; j < i; j++) {
			if(string_eq(&headers->headers[j].key,
				key->size, key->data)) {
				char body[0x100];

				ssize_t size = snprintf(body, sizeof(body),
					"Duplicate header: %.*s",
					(int)key->size, key->data);

				err400(tx, id, size, body);
				return false;
			}
		}

		if(string_eq(key, 7, ":method"))
			method = &headers->headers[i].value;
		else if(string_eq(key, 5, ":path"))
			path = &headers->headers[i].value;
		else if(string_eq(key, 6, "x-flag"))
			xflag = &headers->headers[i].value;
	}

#define E400(str) err400(tx, id, __builtin_strlen(str), str)
	if(NULL == method) {
		E400("Missing :method");
		return false;
	}

	if(!string_eq(method, 3, "GET")) {
		E400(":method is not GET");
		return false;
	}

	if(NULL == path) {
		E400("Missing :path");
		return false;
	}

	if(!string_eq(path, 6, "/check")) {
		E400(":path is not /check");
		return false;
	}

	if(NULL == xflag) {
		E400("Missing x-flag");
		return false;
	}

	// Check whether the flag is correct or not
	if(string_eq(xflag, strlen(flag), flag)) {
		static const char hdr[] = {
			0x88, // :status = 200

			0x40 | 31, // "content-type"
			0x0A, 't', 'e', 'x', 't', '/',
				'p', 'l', 'a', 'i', 'n',
		};
		sendFrame(tx, id, HEADERS, 4, sizeof(hdr), hdr);

		static const char resp[] = "Correct flag";
		sendFrame(tx, id, DATA, 1, strlen(resp), resp);
	} else {
		static const char hdr[] = {
			0x40 | 8, // :status
			0x03, '4', '0', '3',

			0x40 | 31, // "content-type"
			0x0A, 't', 'e', 'x', 't', '/',
				'p', 'l', 'a', 'i', 'n',
		};
		sendFrame(tx, id, HEADERS, 4, sizeof(hdr), hdr);

		static const char resp[] = "Access denied";
		sendFrame(tx, id, DATA, 1, strlen(resp), resp);
	}

	return true;
}

static char *getFlag(const char *path)
{
	int fd = open(path, O_RDONLY);

	if(fd < 0)
		return NULL;

	char *ret = malloc(0x80); // big enough
	if(NULL == ret) {
		close(fd);
		return NULL;
	}

	ssize_t s = read(fd, ret, 0x80 - 1);
	if(s <= 0) {
		perror("read");

		free(ret);
		return NULL;
	}

	close(fd);

	ret[s] = 0;
	ret[strcspn(ret, "\n")] = 0;

	return ret;
}

int main(void)
{
	setbuf(stderr, NULL);

	char *flag = getFlag("flag.txt");
	if(NULL == flag) {
		fputs("Could not open flag", stderr);
		return EXIT_FAILURE;
	}

	const int rx = STDIN_FILENO;
	const int tx = STDOUT_FILENO;

	if(!handshake(rx, tx))
		return EXIT_FAILURE;

	// Default size is 4096
	// https://www.rfc-editor.org/rfc/rfc7541#section-6.2.1
	struct header *table = calloc(4096, sizeof(*table));

	while(1) {
		struct frame frame = {};
		if(!frameHeader(rx, &frame)) {
			fprintf(stderr, "Could not read frame\n");
			break;
		}

		void *p = malloc(frame.size);
		if(!read_n(rx, p, frame.size)) {
			free(p);
			free(table);
			return EXIT_FAILURE;
		}

		if(HEADERS == frame.type) {
			// Pointer in heap, might be overflowed
			struct headers *headers = parse(table, frame.size, p);

			if(NULL == headers)
				break;

			handleHeaders(tx, flag, frame.id, headers);
			headers_del(headers);
		}

		free(p);
	}

	for(size_t i = 0; i < 4096; i++) {
		string_del(&table[i].key);
		string_del(&table[i].value);
	}
	free(table);

	return EXIT_SUCCESS;
}
