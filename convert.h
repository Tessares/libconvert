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
#define CONVERT_MAGIC_NO 0x2263

enum {
	CONVERT_INFO			= 0x1,
	CONVERT_CONNECT			= 0xa,
	CONVERT_EXTENDED_TCP_HDR	= 0x14,
	CONVERT_SUPPORTED_TCP_EXT	= 0x15,
	CONVERT_COOKIE			= 0x16,
	CONVERT_ERROR			= 0x1e,
};

enum {
	CONVERT_ERROR_UNSUPPORTED_VERSION	= 0,
	CONVERT_ERROR_MALFORMED_MSG		= 1,
	CONVERT_ERROR_UNSUPPORTED_MSG		= 2,
	CONVERT_ERROR_MISSING_COOKIE		= 3,
	CONVERT_ERROR_UNAUTHORIZED		= 32,
	CONVERT_ERROR_UNSUPPORTED_TCP_OPT	= 33,
	CONVERT_ERROR_RESOURCE_EXCEEDED		= 64,
	CONVERT_ERROR_NETWORK_FAILURE		= 65,
	CONVERT_ERROR_CONN_RESET		= 96,
	CONVERT_ERROR_DEST_UNREACH		= 97,
};

struct convert_header {
	uint8_t		version;
	uint8_t		total_length;
	uint16_t	magic_no;
} __attribute__((packed));

struct convert_tlv {
	uint8_t type;
	uint8_t length;
} __attribute__((packed));

struct convert_connect {
	struct convert_tlv	tlv_hdr;
	uint16_t		remote_port;
	struct in6_addr		remote_addr;
	uint8_t			options[0];
} __attribute__((packed));

struct convert_info {
	struct convert_tlv	tlv_hdr;
	uint16_t		reserved;
} __attribute__((packed));

struct convert_supported_opts {
	struct convert_tlv	tlv_hdr;
	uint16_t		reserved;
	uint8_t			options_kind[0];
} __attribute__((packed));

struct convert_cookie {
	struct convert_tlv	tlv_hdr;
	uint16_t		reserved;
	uint8_t			opaque[0];
} __attribute__((packed));

struct convert_error {
	struct convert_tlv	tlv_hdr;
	uint8_t			error_code;
	uint8_t			value[0];
} __attribute__((packed));

struct convert_extended_tcp_hdr {
	struct convert_tlv	tlv_hdr;
	uint16_t		unassigned;
	uint8_t			tcp_options[0];
} __attribute__((packed));

#endif
