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
#pragma once
#include <stddef.h>
#include <stdbool.h>

// 0x10 bytes
struct string {
	size_t size;
	char *data;
};

void string_del(struct string *str);
bool string_eq(const struct string *str, size_t n, const char data[static n]);

// 0x20 bytes
struct header {
	struct string key;
	struct string value;
};

// 8 bytes
struct headers {
	size_t count;
	struct header headers[];
};

struct headers* parse(struct header *table, size_t size, const char data[static size]);
void headers_del(struct headers *hdrs);
