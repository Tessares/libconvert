/**
 * Copyright(c) 2019, Tessares S.A.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and / or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *        SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *        OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _CONVERT_H_
#define _CONVERT_H_

/* based on draft-ietf-tcpm-converts-05 */

#include <stdint.h>
#include <netinet/in.h>

#define CONVERT_VERSION 1

enum {
	CONVERT_INFO			= 0x1,
	CONVERT_CONNECT			= 0xa,
	CONVERT_EXTENDED_TCP_HDR	= 0x14,
	CONVERT_SUPPORTED_TCP_EXT	= 0x15,
	CONVERT_COOKIE			= 0x16,
	CONVERT_ERROR			= 0x1e,
};

struct convert_header {
	uint8_t		version;
	uint8_t		total_length;
	uint16_t	unassigned;
} __attribute__((packed));

struct convert_tlv {
	uint8_t type;
	uint8_t length;
} __attribute__((packed));

struct convert_connect {
	uint8_t		type;
	uint8_t		length;
	uint16_t	remote_port;
	struct in6_addr remote_addr;
	uint8_t		options[0];
} __attribute__((packed));

struct convert_info {
	uint8_t		type;
	uint8_t		length;
	uint16_t	reserved;
} __attribute__((packed));

struct convert_supported_opts {
	uint8_t		type;
	uint8_t		length;
	uint16_t	reserved;
	uint8_t		options_kind[0];
} __attribute__((packed));

struct convert_cookie {
	uint8_t		type;
	uint8_t		length;
	uint16_t	reserved;
	uint32_t	opaque[0];
} __attribute__((packed));

struct convert_error {
	uint8_t type;
	uint8_t length;
	uint8_t error_code;
	uint8_t value[0];
} __attribute__((packed));

struct convert_extended_header {
	uint8_t		type;
	uint8_t		length;
	uint16_t	unassigned;
	uint8_t		tcp_hdr[0];
} __attribute__((packed));

#endif
